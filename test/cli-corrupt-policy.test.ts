import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

// Imported through the module (its program.parse is skipped under vitest), so
// the command bodies can be exercised without argv.
const { __test } = await import("../src/cli.js");

/**
 * A corrupt user policy is a typo, not a stack trace: every command that reads
 * the policy refuses with a one-line diagnosis and exit 1.
 */
describe("a corrupt policy file refuses cleanly in every command", () => {
  const policyFile = path.join(cfg, "policy.json");
  let captured = "";
  let capturedStdout = "";

  beforeEach(() => {
    fs.writeFileSync(policyFile, '{ "rules": [ TRUNCATED');
    captured = "";
    capturedStdout = "";
    // The diagnosis goes to STDERR: stdout may be piped (`herkos check | grep`),
    // and the reason for an exit 1 must reach the terminal being looked at.
    vi.spyOn(process.stderr, "write").mockImplementation(((
      chunk: string | Uint8Array,
    ) => {
      captured += typeof chunk === "string" ? chunk : "";
      return true;
    }) as typeof process.stderr.write);
    vi.spyOn(process.stdout, "write").mockImplementation(((
      chunk: string | Uint8Array,
    ) => {
      capturedStdout += typeof chunk === "string" ? chunk : "";
      return true;
    }) as typeof process.stdout.write);
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code ?? 0}`);
    }) as unknown as typeof process.exit);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(policyFile, { force: true });
  });

  const commands: [string, () => void][] = [
    ["status", () => __test.statusCmd()],
    ["init", () => __test.initCmd({})],
    ["validate", () => __test.validateCmd()],
    ["check", () => __test.checkCmd()],
    ["rules", () => __test.rulesCmd()],
  ];

  for (const [name, run] of commands) {
    it(`${name} prints one diagnosis line to stderr and exits 1, with no stack trace`, () => {
      expect(run).toThrow("process.exit:1");
      expect(captured).toContain("herkos:");
      expect(captured).toContain("is not valid JSON");
      // The diagnosis must not ride on stdout, where a pipe swallows it.
      expect(capturedStdout).not.toContain("is not valid JSON");
      // A stack trace would carry "    at " lines; a diagnosis does not.
      expect(captured).not.toMatch(/\n\s+at\s/);
    });
  }

  it("discover refuses the same way (its command body lives beside the candidates)", async () => {
    const { discoverCommand } = await import("../src/discover.js");
    const home = fs.mkdtempSync(
      path.join(fs.realpathSync("/tmp"), "herkos-home-"),
    );
    try {
      await expect(discoverCommand({}, home)).rejects.toThrow("process.exit:1");
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
