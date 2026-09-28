import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { fireHook, isolateConfig, writeHook } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { generateHook } = await import("../src/adapters/claude-code.js");
const { runSelfCheck } = await import("../src/selfcheck.js");

const policyFile = path.join(cfg, "policy.json");
const write = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));

const hookFrom = (policy: ReturnType<typeof compile>): string =>
  writeHook(generateHook({ ...policy, logFile: "" }));
const selftest = (script: string) =>
  fireHook(script, "", process.env, ["--selftest"]);

afterEach(() => fs.rmSync(policyFile, { force: true }));

describe("--selftest asserts the baked rules against their policy examples", () => {
  // The branch used to print one line and verify nothing. Now every rule's
  // baked patterns are checked, by the hook itself with grep -E, against the
  // policy's match / notMatch examples — so a baked rule that drifted from
  // its examples fails the wiring's own proof instead of silently not
  // matching at run time.
  it("passes on the baseline and names the number of verified examples", () => {
    const r = selftest(hookFrom(compile(loadEffectivePolicy())));
    expect(r.exit).toBe(0);
    expect(r.stdout).toContain("herkos hook selftest:");
    const n = Number((r.stdout.match(/(\d+) example\(s\) verified/) ?? [])[1]);
    expect(n).toBeGreaterThan(0); // the baseline carries examples on every rule
  });

  it("FAILS, rule and example named, when a baked pattern no longer matches its match example", () => {
    const compiled = compile(loadEffectivePolicy());
    const tampered = {
      ...compiled,
      rules: compiled.rules.map((r) =>
        r.id === "ssh-private-keys"
          ? { ...r, pathRegex: "zz[.]never[.]matches" }
          : r,
      ),
    };
    const r = selftest(hookFrom(tampered));
    expect(r.exit).toBe(1);
    expect(r.stderr).toContain("ssh-private-keys match example");
    expect(r.stderr).toContain("drifted from its policy examples");
  });

  it("FAILS when a baked pattern starts catching a notMatch example", () => {
    const compiled = compile(loadEffectivePolicy());
    // `ssh` the fragment catches the benign known_hosts and config reads the
    // rule deliberately leaves alone.
    const tampered = {
      ...compiled,
      rules: compiled.rules.map((r) =>
        r.id === "ssh-private-keys" ? { ...r, pathRegex: "ssh" } : r,
      ),
    };
    const r = selftest(hookFrom(tampered));
    expect(r.exit).toBe(1);
    expect(r.stderr).toContain("ssh-private-keys notMatch example");
  });

  it("FAILS when grep cannot evaluate a baked pattern — that rule is OFF at run time", () => {
    // An unevaluable pattern used to read as "no match", so every notMatch
    // example passed and the proof reported success for a rule enforce
    // turns off.
    const compiled = compile(loadEffectivePolicy());
    const tampered = {
      ...compiled,
      rules: compiled.rules.map((r) =>
        r.id === "ssh-private-keys" ? { ...r, pathRegex: "(" } : r,
      ),
    };
    const r = selftest(hookFrom(tampered));
    expect(r.exit).toBe(1);
    expect(r.stderr).toContain("the baked patterns cannot be evaluated");
  });

  it("FAILS when grep cannot evaluate a rule's exclusion", () => {
    const compiled = compile(loadEffectivePolicy());
    const tampered = {
      ...compiled,
      rules: compiled.rules.map((r) =>
        r.id === "dotenv-files" ? { ...r, notPathRegex: "(" } : r,
      ),
    };
    const r = selftest(hookFrom(tampered));
    expect(r.exit).toBe(1);
    expect(r.stderr).toContain("the rule exclusion cannot be evaluated");
  });

  it("applies the rule's exclusion first, exactly as enforce does", () => {
    // The dotenv rule's match example `cat ./.env` must fire; the same
    // fragment with the excluded template spelling must not — one rule
    // proving both sides of its own carve-out.
    const compiled = compile(loadEffectivePolicy());
    const dotenv = compiled.rules.find((r) => r.id === "dotenv-files")!;
    expect(dotenv.match).toContain("cat ./.env");
    expect(dotenv.notMatch).toContain("Read app/.env.example");
    const r = selftest(hookFrom(compiled));
    expect(r.exit).toBe(0);
  });

  it("verifies a mixed exclusion example — a real target beside an excluded spelling still fires", () => {
    // st_one used to apply the exclusion whole-subject: an example that
    // merely CONTAINED an excluded spelling read as covered, so the selftest
    // FAILED with "the rule exclusion covers it" on the very case enforce
    // blocks at run time (selfcheck pins `cat ./app/.env ./app/.env.example`
    // → exit 2). The baseline now carries that mixed example as a match, so
    // the policy itself pins the token-removal semantics.
    const compiled = compile(loadEffectivePolicy());
    const dotenv = compiled.rules.find((r) => r.id === "dotenv-files")!;
    expect(dotenv.match).toContain("cat app/.env app/.env.example");
    const r = selftest(hookFrom(compiled));
    expect(r.exit).toBe(0);
    expect(r.stderr).not.toContain("the rule exclusion covers it");
  });

  it("bakes ONE token-removal loop — enforce, notice and st_one share remaining_tokens", () => {
    // Three copies of the exclusion's token loop is how st_one drifted to
    // whole-subject semantics in the first place. The helper is the single
    // owner now: the per-token loop exists exactly once, inside it, and each
    // of the three callers routes through it.
    const script = generateHook({
      ...compile(loadEffectivePolicy()),
      logFile: "",
    });
    expect(script).toContain("remaining_tokens() {");
    expect(script.match(/for tok in \$1; do/g)).toHaveLength(1);
    expect(script.match(/=\$\(remaining_tokens "/g)).toHaveLength(3);
  });

  it("a rule without examples asserts nothing and still reports zero", () => {
    const compiled = compile(loadEffectivePolicy());
    const stripped = {
      ...compiled,
      rules: compiled.rules.map((r) => ({ ...r, match: [], notMatch: [] })),
    };
    const r = selftest(hookFrom(stripped));
    expect(r.exit).toBe(0);
    expect(r.stdout).toContain("0 example(s) verified");
  });

  it("'herkos check' runs the branch and reports it among its cases", () => {
    write({});
    const s = runSelfCheck();
    const row = s.results.find((r) => r.name.includes("--selftest"));
    expect(row).toBeDefined();
    expect(row!.ok).toBe(true);
    expect(s.ok).toBe(true);
  });
});
