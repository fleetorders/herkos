import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { claudeCodeAdapter, hookPath } = await import(
  "../src/adapters/claude-code.js"
);

/**
 * wire() must refuse a settings file it cannot merge into BEFORE writing
 * anything: the hook file, the snapshot, the session-start script — none of
 * them may land from a refused init, or the install is half-applied.
 */
describe("wire() refuses wrong-shape harness settings cleanly", () => {
  let configDir: string;
  const prev = {
    CLAUDE_CONFIG_DIR: process.env.CLAUDE_CONFIG_DIR,
    HERKOS_CONFIG: process.env.HERKOS_CONFIG,
  };

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-cc-"));
    process.env.CLAUDE_CONFIG_DIR = configDir;
    process.env.HERKOS_CONFIG = cfg;
  });
  afterEach(() => {
    if (prev.CLAUDE_CONFIG_DIR === undefined)
      delete process.env.CLAUDE_CONFIG_DIR;
    else process.env.CLAUDE_CONFIG_DIR = prev.CLAUDE_CONFIG_DIR;
    if (prev.HERKOS_CONFIG === undefined) delete process.env.HERKOS_CONFIG;
    else process.env.HERKOS_CONFIG = prev.HERKOS_CONFIG;
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  const settingsFile = (): string => path.join(configDir, "settings.json");

  const cases: [name: string, contents: string, message: RegExp][] = [
    ["hooks is a boolean", '{"hooks": true}', /has 'hooks' as a boolean/],
    [
      "permissions is a number",
      '{"permissions": 42}',
      /has 'permissions' as a number/,
    ],
    ["sandbox is a string", '{"sandbox": "x"}', /has 'sandbox' as a string/],
    ["hooks is an array", '{"hooks": []}', /has 'hooks' as an array/],
    ["hooks is null", '{"hooks": null}', /has 'hooks' as null/],
    ["the whole file is an array", "[]", /holds an array, not a JSON object/],
    ["the whole file is null", "null", /holds null, not a JSON object/],
    ["the file is not valid JSON", "{oops", /is not valid JSON/],
    // Nested shapes wire() dereferences: these used to throw inside wire()
    // after the hook file was already written — the half-applied install.
    [
      "hooks.PreToolUse is a string",
      '{"hooks": {"PreToolUse": "x"}}',
      /has 'hooks\.PreToolUse' as a string/,
    ],
    [
      "hooks.SessionStart holds a null entry",
      '{"hooks": {"SessionStart": [null]}}',
      /non-object entry in 'hooks\.SessionStart'/,
    ],
    [
      "a PreToolUse entry's hooks is a string",
      '{"hooks": {"PreToolUse": [{"hooks": "x"}]}}',
      /whose 'hooks' is not a list of objects/,
    ],
    [
      "permissions.deny is a string",
      '{"permissions": {"deny": "Read(~/x)"}}',
      /has 'permissions\.deny' as a string/,
    ],
    [
      "sandbox.credentials is an array",
      '{"sandbox": {"credentials": []}}',
      /has 'sandbox\.credentials' as an array/,
    ],
    [
      "sandbox.credentials.files is an object",
      '{"sandbox": {"credentials": {"files": {}}}}',
      /has 'sandbox\.credentials\.files' as an object/,
    ],
  ];

  for (const [name, contents, message] of cases) {
    it(`refuses a settings file where ${name} — one line, nothing written`, () => {
      fs.writeFileSync(settingsFile(), contents);
      expect(() =>
        claudeCodeAdapter.wire(compile(loadEffectivePolicy())),
      ).toThrow(message);
      // The refusal happened before any write: no hook, no half-applied install.
      expect(fs.existsSync(hookPath())).toBe(false);
      expect(fs.readdirSync(cfg)).toEqual([]);
    });
  }

  it("still wires a well-formed settings file (the gate is not a veto)", () => {
    fs.writeFileSync(settingsFile(), JSON.stringify({ model: "x" }));
    const r = claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(r.changed).toContain(hookPath());
    expect(fs.existsSync(hookPath())).toBe(true);
  });

  it("still wires a settings file with user hook entries, deny rules and credential files (the deep gate is not a veto)", () => {
    fs.writeFileSync(
      settingsFile(),
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [{ type: "command", command: "echo hi" }],
            },
          ],
        },
        permissions: { deny: ["Read(~/private)"] },
        sandbox: { credentials: { files: [{ path: "~/x", mode: "ask" }] } },
      }),
    );
    const r = claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(r.changed).toContain(hookPath());
    expect(fs.existsSync(hookPath())).toBe(true);
  });
});
