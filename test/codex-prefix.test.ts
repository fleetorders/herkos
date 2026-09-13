import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { call, fireHook, isolateConfig, writeHook } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy, validatePolicy } = await import(
  "../src/policy.js"
);
const { generateHook } = await import("../src/adapters/claude-code.js");
const { codexAdapter, codexRulesFile, codexRulesPath } = await import(
  "../src/adapters/codex.js"
);

const policyFile = path.join(cfg, "policy.json");
const writePolicy = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));
const KEYCHAIN = ["security", "dump-keychain"];
const EXECPOLICY = "execpolicy forbidden rules (no trust step)";

describe("prefix rules in the policy model", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  it("derives hook patterns for a rule that is only prefixes", () => {
    writePolicy({
      rules: [
        {
          id: "no-force-push",
          class: "fetched-exec",
          description: "force push",
          commandPrefixes: [["git", "push", "--force"]],
        },
      ],
    });
    const hook = writeHook(generateHook(compile(loadEffectivePolicy())));
    const exit = (command: string): number =>
      fireHook(hook, call("Bash", { command })).exit;
    expect(exit("git push --force origin main")).toBe(2);
    expect(exit("cd x && /usr/bin/git push --force")).toBe(2);
    expect(exit("git push origin main")).toBe(0);
    expect(exit("git push --force-with-lease")).toBe(0);
    expect(exit("legit push --force")).toBe(0);
  });

  it("keeps explicit commandPatterns when a rule declares both", () => {
    const keychain = compile(loadEffectivePolicy()).rules.find(
      (r) => r.id === "macos-keychain",
    )!;
    expect(keychain.commandPrefixes).toContainEqual(KEYCHAIN);
    expect(keychain.commandRegexes[0]).toContain("dump-keychain|");
  });

  it("rejects malformed prefixes", () => {
    writePolicy({
      rules: [
        {
          id: "a",
          class: "fetched-exec",
          description: "a",
          commandPrefixes: [[]],
        },
        {
          id: "b",
          class: "fetched-exec",
          description: "b",
          commandPrefixes: [["x", 3]],
        },
        {
          id: "c",
          class: "fetched-exec",
          description: "c",
          commandPrefixes: "git push",
        },
      ],
    });
    const v = validatePolicy(loadEffectivePolicy());
    for (const id of ["a", "b", "c"]) {
      expect(
        v.errors.some(
          (e) => e.startsWith(`rule ${id}:`) && e.includes("commandPrefixes"),
        ),
      ).toBe(true);
    }
  });
});

describe("the Codex execpolicy rules file", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  it("emits one forbidden prefix_rule per prefix, each carrying itself as a match example", () => {
    const text = codexRulesFile(compile(loadEffectivePolicy()))!;
    expect(text).toContain('pattern = ["security", "dump-keychain"],');
    expect(text).toContain('decision = "forbidden",');
    expect(text).toContain('match = [["security", "dump-keychain"]],');
    expect(text).toContain("herkos rule macos-keychain");
    expect(text).toMatch(/^# herkos-stamp: /m);
    // A pipeline is not a prefix and never becomes one.
    expect(text).not.toContain("curl");
  });

  it("escapes a quote and a backslash in the justification", () => {
    writePolicy({
      rules: [
        {
          id: "q",
          class: "fetched-exec",
          description: 'say "hi" \\ bye',
          commandPrefixes: [["tool", "sub"]],
        },
      ],
    });
    const text = codexRulesFile(compile(loadEffectivePolicy()))!;
    expect(text).toContain('say \\"hi\\" \\\\ bye');
  });

  it("is null when no rule is a prefix", () => {
    writePolicy({ disable: ["macos-keychain"] });
    expect(codexRulesFile(compile(loadEffectivePolicy()))).toBeNull();
  });

  const verdict = (stdout: string): { decision?: string } =>
    JSON.parse(
      stdout
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l.startsWith("{")) ?? "{}",
    );
  const realCodex =
    spawnSync("codex", ["--version"], { encoding: "utf8" }).status === 0;

  it.skipIf(!realCodex)(
    "is accepted by the installed codex, forbidding the prefix and nothing beside it",
    () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-rules-"));
      const f = path.join(dir, "herkos.rules");
      fs.writeFileSync(f, codexRulesFile(compile(loadEffectivePolicy()))!);
      const hit = spawnSync(
        "codex",
        ["execpolicy", "check", "--rules", f, ...KEYCHAIN],
        { encoding: "utf8" },
      );
      expect(verdict(hit.stdout).decision).toBe("forbidden");
      const miss = spawnSync(
        "codex",
        ["execpolicy", "check", "--rules", f, "security", "list-keychains"],
        { encoding: "utf8" },
      );
      expect(verdict(miss.stdout).decision).toBeUndefined();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  );
});

describe("wiring the prefix rules into Codex", () => {
  let home = "";
  let stubDir = "";
  let prevHome: string | undefined;
  let prevBin: string | undefined;

  const stub = (body: string): string => {
    const f = path.join(
      stubDir,
      `codex-${Math.random().toString(36).slice(2)}`,
    );
    fs.writeFileSync(f, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
    return f;
  };
  const ACCEPTS = `printf '{"matchedRules":[{}],"decision":"forbidden"}\\n'`;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-codex-"));
    stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-stub-"));
    prevHome = process.env.CODEX_HOME;
    prevBin = process.env.HERKOS_CODEX_BIN;
    process.env.CODEX_HOME = home;
  });
  afterEach(() => {
    if (prevHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevHome;
    if (prevBin === undefined) delete process.env.HERKOS_CODEX_BIN;
    else process.env.HERKOS_CODEX_BIN = prevBin;
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(stubDir, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  it("installs the rules once Codex accepts them; uninstall removes the file and the directory it made", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    const r = codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(true);
    expect(r.detail).toContain("live via execpolicy");
    const v = codexAdapter.verify();
    expect(v.ok).toBe(true);
    expect(v.detail).toContain("prefix rules live");
    const cov = codexAdapter.coverage!(compile(loadEffectivePolicy()));
    expect(cov.find((c) => c.rule === "macos-keychain")!.layers).toContain(
      EXECPOLICY,
    );
    expect(cov.find((c) => c.rule === "curl-pipe-shell")!.layers).not.toContain(
      EXECPOLICY,
    );
    codexAdapter.unwire();
    expect(fs.existsSync(codexRulesPath())).toBe(false);
    expect(fs.existsSync(path.join(home, "rules"))).toBe(false);
  });

  it("installs nothing, and says so, when Codex refuses the rules", () => {
    process.env.HERKOS_CODEX_BIN = stub(
      `echo "Error: failed to parse policy" >&2; echo "error: invalid decision" >&2; exit 1`,
    );
    const r = codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(false);
    expect(r.detail).toContain("REFUSED");
    const v = codexAdapter.verify();
    // The permission profile and the hook still stand.
    expect(v.ok).toBe(true);
    expect(v.detail).toContain("NOT live");
    const cov = codexAdapter.coverage!(compile(loadEffectivePolicy()));
    expect(cov.find((c) => c.rule === "macos-keychain")!.layers).not.toContain(
      EXECPOLICY,
    );
    codexAdapter.unwire();
  });

  it("withdraws a previously installed file when Codex refuses the new one", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(true);
    process.env.HERKOS_CODEX_BIN = stub(`echo "Error: nope" >&2; exit 1`);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(false);
    codexAdapter.unwire();
  });

  it("installs unvalidated, and says so, when the codex binary cannot run", () => {
    process.env.HERKOS_CODEX_BIN = path.join(stubDir, "missing-codex");
    const r = codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(true);
    expect(r.detail).toContain("not validated");
    codexAdapter.unwire();
  });

  it("leaves a rules directory it did not create, with the user's own rules", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    fs.mkdirSync(path.join(home, "rules"));
    fs.writeFileSync(path.join(home, "rules", "mine.rules"), "# user rules\n");
    codexAdapter.wire(compile(loadEffectivePolicy()));
    codexAdapter.unwire();
    expect(
      fs.readFileSync(path.join(home, "rules", "mine.rules"), "utf8"),
    ).toBe("# user rules\n");
    expect(fs.existsSync(codexRulesPath())).toBe(false);
  });

  it("reports stale wiring when the rules file was removed by hand", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    fs.rmSync(codexRulesPath());
    expect(codexAdapter.verify().state).toBe("stale");
    codexAdapter.unwire();
  });

  it("removes the rules file once the prefix rule is disabled", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    writePolicy({ disable: ["macos-keychain"] });
    codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.existsSync(codexRulesPath())).toBe(false);
    codexAdapter.unwire();
  });

  it("refuses a hooks.json it cannot merge into, writing nothing", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    fs.writeFileSync(path.join(home, "hooks.json"), "{oops");
    expect(() => codexAdapter.wire(compile(loadEffectivePolicy()))).toThrow(
      /hooks\.json is not valid JSON/,
    );
    // The refusal came before any write: no config.toml rewrite, no hook.
    expect(fs.existsSync(path.join(home, "config.toml"))).toBe(false);
    // A wrong SHAPE is refused the same way, not cast into place.
    fs.writeFileSync(
      path.join(home, "hooks.json"),
      JSON.stringify({ hooks: "x" }),
    );
    expect(() => codexAdapter.wire(compile(loadEffectivePolicy()))).toThrow(
      /'hooks' as a string/,
    );
  });

  it("warns loudly when uninstall cannot read hooks.json (the registration may survive)", () => {
    process.env.HERKOS_CODEX_BIN = stub(ACCEPTS);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    fs.writeFileSync(path.join(home, "hooks.json"), "{oops");
    const r = codexAdapter.unwire();
    expect(r.detail).toContain("WARNING");
    expect(r.detail).toContain("could not be parsed");
  });
});
