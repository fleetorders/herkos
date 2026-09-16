import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { call, fireHook, isolateConfig, writeHook } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { generateHook } = await import("../src/adapters/claude-code.js");

const policyFile = path.join(cfg, "policy.json");
const write = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));
const hookFor = () =>
  writeHook(generateHook({ ...compile(loadEffectivePolicy()), logFile: "" }));

afterEach(() => fs.rmSync(policyFile, { force: true }));

// One rule whose pattern spans a space, one whose pattern anchors at the start
// — together they pin the two halves of the folded-value semantics (D-006).
const RULES = {
  rules: [
    {
      id: "no-forbidden-pair",
      class: "command-never",
      description: "the forbidden pair of words",
      commandPatterns: ["forbidden[[:space:]]+spelling"],
    },
    {
      id: "top-of-command-only",
      class: "command-never",
      description: "only at the start of the whole command",
      commandPatterns: ["^top-only"],
    },
  ],
};

describe("one string value is one record — embedded newlines fold to spaces", () => {
  it("matches a forbidden spelling split by an embedded newline", () => {
    write(RULES);
    // Line-by-line checking read "forbidden" and "spelling" as two separate
    // values and missed the pair; the folded value is checked whole.
    expect(
      fireHook(
        hookFor(),
        call("Bash", { command: "echo x\nforbidden\nspelling" }),
      ).exit,
    ).toBe(2);
  });

  it("still matches a forbidden spelling sitting on one line of many", () => {
    write(RULES);
    expect(
      fireHook(
        hookFor(),
        call("Bash", { command: "echo a\necho forbidden spelling" }),
      ).exit,
    ).toBe(2);
  });

  it("does not fire a ^-anchored rule at an embedded line start", () => {
    write(RULES);
    // "top-only" starts the second line, not the command: the anchor holds at
    // the value's start only, never mid-value.
    const r = fireHook(
      hookFor(),
      call("Bash", { command: "echo hi\ntop-only run" }),
    );
    expect(r.exit).toBe(0);
    expect(r.stderr).toBe("");
  });

  it("still fires the ^-anchored rule at the value's own start", () => {
    write(RULES);
    expect(
      fireHook(hookFor(), call("Bash", { command: "top-only run" })).exit,
    ).toBe(2);
  });
});
