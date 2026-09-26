import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { call, fireHook, isolateConfig, writeHook } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy, prefixRegex } = await import(
  "../src/policy.js"
);
const { generateHook } = await import("../src/adapters/claude-code.js");

const policyFile = path.join(cfg, "policy.json");
const write = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));
const hookFor = () =>
  writeHook(generateHook({ ...compile(loadEffectivePolicy()), logFile: "" }));
const run = (command: string, harness = false) =>
  fireHook(
    hookFor(),
    call("Bash", { command }),
    process.env,
    harness ? ["--harness", "claude-code"] : [],
  );

afterEach(() => fs.rmSync(policyFile, { force: true }));

// The consumer shape this pins (an independent tier-1 review of a consumer
// repo's install): a catastrophic command-never rule declared as one prefix
// token. The old trailing class ([[:space:]]|$) let every punctuation shape
// below through — only whitespace- or EOL-terminated spellings were caught.
const NO_RESET = {
  rules: [
    {
      id: "no-reset-script",
      class: "command-never",
      description: "the v2 reset script",
      commandPrefixes: [["migrate-v2-reset.sh"]],
    },
  ],
};

describe("a prefix rule ends at shell punctuation, not just whitespace (D-007)", () => {
  it.each([
    ["sh migrate-v2-reset.sh; echo done", "a semicolon follows the spelling"],
    ["bash -c 'migrate-v2-reset.sh'", "the spelling is quoted after -c"],
    ["./migrate-v2-reset.sh|tee log", "a pipe follows the spelling"],
    [
      "(cd /srv && ./migrate-v2-reset.sh)",
      "a subshell closes after the spelling",
    ],
    [
      "sh migrate-v2-reset.sh \\\n--force",
      "a backslash continuation follows the spelling (folded to a space, the backslash still trails it)",
    ],
    [
      "sh migrate-v2-reset.sh.bin",
      "a dot continues the file name but terminates the forbidden spelling",
    ],
    [
      "sh migrate-v2-reset.sh --force",
      "a space follows the spelling (held before the widening too)",
    ],
  ])("blocks %j — %s", (command) => {
    write(NO_RESET);
    const r = run(command, true);
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("rule no-reset-script");
  });

  it.each([
    [
      "sh migrate-v2.sh",
      "a different script that only shares a prefix of the spelling",
    ],
    [
      "sh pre-migrate-v2-reset.sh",
      "a hyphen continues the token before the spelling (the leading class)",
    ],
    [
      "sh migrate-v2-reset.shx",
      "an alphanumeric continues the token past the spelling",
    ],
    [
      "sh migrate-v2-reset-sh",
      "a hyphen continues the token past the spelling",
    ],
  ])("passes %j — %s", (command) => {
    write(NO_RESET);
    const r = run(command, true);
    expect(r.exit).toBe(0);
    expect(r.stderr).not.toContain("no-reset-script");
  });

  it("keeps the classic flag case: --force blocks, --force-with-lease does not", () => {
    write({
      rules: [
        {
          id: "no-force-push",
          class: "vcs",
          description: "force push",
          commandPrefixes: [["git", "push", "--force"]],
        },
      ],
    });
    expect(run("git push --force origin main").exit).toBe(2);
    expect(run("git push --force-with-lease").exit).toBe(0);
  });
});

describe("the baked classes are asymmetric on purpose", () => {
  it("leading: dot and hyphen continue a token; trailing: only token characters do", () => {
    expect(prefixRegex(["sh", "x.sh"])).toBe(
      "(^|[^[:alnum:]_.-])sh[[:space:]]+x\\.sh([^[:alnum:]_-]|$)",
    );
  });
});
