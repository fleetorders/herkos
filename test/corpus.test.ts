import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { BASELINE, compile, loadEffectivePolicy, validatePolicy } = await import(
  "../src/policy.js"
);
const { CORPUS, LAYER_KINDS, runBypassCorpus } = await import(
  "../src/corpus.js"
);
const { runSelfCheck } = await import("../src/selfcheck.js");
const { blockLogPath } = await import("../src/adapters/claude-code.js");
import type { HarnessView } from "../src/corpus.js";
import type { LayerKind } from "../src/adapters/types.js";

const policyFile = path.join(cfg, "policy.json");

describe("the bypass corpus against the generated hook", () => {
  const effective = loadEffectivePolicy();
  const results = runBypassCorpus(compile(effective), effective, []);

  for (const r of results) {
    it(`${r.case.id}: the hook ${r.case.hook === "block" ? "blocks" : "passes"} it`, () => {
      expect(r.skipped).toBeUndefined();
      expect(r.gotHook).toBe(r.case.hook);
      expect(r.ok).toBe(true);
    });
  }

  it("names only baseline rules and known layer kinds, with unique ids", () => {
    const ids = new Set<string>();
    for (const c of CORPUS) {
      expect(ids.has(c.id)).toBe(false);
      ids.add(c.id);
      expect(BASELINE.some((b) => b.id === c.rule)).toBe(true);
      for (const k of c.heldBy) expect(LAYER_KINDS).toContain(k);
    }
  });

  it("never credits a layer with holding a benign call", () => {
    for (const c of CORPUS.filter((x) => x.benign)) {
      expect(c.hook).toBe("pass");
      expect(c.heldBy).toEqual([]);
    }
  });
});

describe("per-harness verdicts", () => {
  const effective = loadEffectivePolicy();
  const policy = compile(effective);
  const view = (
    hookScope: HarnessView["hookScope"],
    kinds: LayerKind[],
  ): HarnessView => ({
    name: "H",
    hookScope,
    coverage: policy.rules.map((r) => ({ rule: r.id, layers: [], kinds })),
  });
  const verdictOf = (id: string, h: HarnessView) =>
    runBypassCorpus(policy, effective, [h]).find((r) => r.case.id === id)!
      .harnesses[0]!;

  it("names a hook gap UNGUARDED when no declared layer is wired", () => {
    expect(
      verdictOf("ssh-glob-name", view("every-tool", ["hook"])).verdict,
    ).toBe("unguarded");
  });

  it("credits a declared layer once it is wired", () => {
    expect(
      verdictOf("ssh-glob-name", view("every-tool", ["hook", "os-sandbox"])),
    ).toMatchObject({ verdict: "held", by: ["os-sandbox"] });
  });

  it("credits the hook only where the hook is wired", () => {
    expect(verdictOf("ssh-direct-read", view("every-tool", [])).verdict).toBe(
      "unguarded",
    );
    expect(
      verdictOf("ssh-direct-read", view("every-tool", ["hook"])),
    ).toMatchObject({ verdict: "held", by: ["hook"] });
  });

  it("treats a file-tool payload as not applicable where the hook sees shell commands only", () => {
    expect(
      verdictOf("ssh-read-tool", view("shell-commands", ["hook"])).verdict,
    ).toBe("n/a");
  });
});

describe("the corpus follows the user's policy", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  it("skips the cases of a disabled rule", () => {
    fs.writeFileSync(policyFile, JSON.stringify({ disable: ["dotenv-files"] }));
    const effective = loadEffectivePolicy();
    const r = runBypassCorpus(compile(effective), effective, []).find(
      (x) => x.case.id === "dotenv-bare-name",
    )!;
    expect(r.skipped).toContain("disabled");
    expect(r.ok).toBe(true);
  });

  it("fails a benign case that a user rule would refuse", () => {
    fs.writeFileSync(
      policyFile,
      JSON.stringify({
        rules: [
          {
            id: "no-json-formatter",
            class: "fetched-exec",
            description: "over-broad on purpose",
            commandPatterns: ["\\|[[:space:]]*jq"],
          },
        ],
      }),
    );
    const effective = loadEffectivePolicy();
    const r = runBypassCorpus(compile(effective), effective, []).find(
      (x) => x.case.id === "benign-download-to-jq",
    )!;
    expect(r.gotHook).toBe("block");
    expect(r.ok).toBe(false);
  });
});

describe("self-checks never write to the blocked-call log", () => {
  it("runs every blocking case without appending a line", () => {
    runSelfCheck();
    const effective = loadEffectivePolicy();
    runBypassCorpus(compile(effective), effective, []);
    expect(fs.existsSync(blockLogPath())).toBe(false);
  });
});

describe("rule examples", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  const withExamples = (extra: Record<string, unknown>): string =>
    JSON.stringify({
      rules: [
        {
          id: "no-force-push",
          class: "fetched-exec",
          description: "force push",
          commandPrefixes: [["git", "push", "--force"]],
          ...extra,
        },
      ],
    });

  it("accepts a rule whose examples hold", () => {
    fs.writeFileSync(
      policyFile,
      withExamples({
        match: ["git push --force origin main"],
        notMatch: ["git push origin main", "git push --force-with-lease"],
      }),
    );
    expect(validatePolicy(loadEffectivePolicy()).errors).toEqual([]);
  });

  it("reports a match example the rule misses", () => {
    fs.writeFileSync(policyFile, withExamples({ match: ["git push -f"] }));
    expect(validatePolicy(loadEffectivePolicy()).errors.join("\n")).toContain(
      "match example 1",
    );
  });

  it("reports a notMatch example the rule would refuse", () => {
    fs.writeFileSync(
      policyFile,
      withExamples({ notMatch: ["git push --force"] }),
    );
    expect(validatePolicy(loadEffectivePolicy()).errors.join("\n")).toContain(
      "notMatch example 1",
    );
  });

  it("rejects examples that are not a list of strings", () => {
    fs.writeFileSync(policyFile, withExamples({ match: "git push --force" }));
    expect(validatePolicy(loadEffectivePolicy()).errors.join("\n")).toContain(
      "match must be a list of strings",
    );
  });
});
