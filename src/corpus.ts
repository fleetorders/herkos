/**
 * The adversarial bypass corpus: payloads that try to reach the never-list by
 * another spelling, and benign payloads that must never be refused.
 *
 * A bare PASS from `check` proves the script runs, not that the never-list
 * holds. The corpus proves the list: every case names the rule it attacks, the
 * verdict the hook must return, and the native layer kinds that hold it when
 * the hook cannot — so `check` can say "the hook misses this; the OS sandbox
 * holds it" or "the hook misses this and nothing wired here holds it".
 *
 * Only the hook's verdict is measured, by running the generated hook on every
 * case. The native layers are credited as each harness documents them and only
 * where `coverage()` reports them wired on this machine; measuring them needs
 * the real harness (the live probe).
 *
 * The payloads live in a fixture file, not in code: written inline they read
 * as the very attacks a guard on the author's own machine is right to refuse.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import data from "./corpus/bypass.json";
import type { CompiledPolicy, EffectivePolicy } from "./policy.js";
import type { LayerKind, RuleCoverage } from "./adapters/types.js";
import { generateHook } from "./adapters/claude-code.js";

export const LAYER_KINDS: readonly LayerKind[] = [
  "hook",
  "permission-deny",
  "os-sandbox",
  "prefix-rule",
];

export interface BypassCase {
  id: string;
  /** The baseline rule the case attacks (or, when benign, must not trip). */
  rule: string;
  note: string;
  /** A legitimate call: refusing it is a false alarm, and a FAIL. */
  benign?: boolean;
  payload: { tool_name: string; tool_input: Record<string, unknown> };
  /** The verdict the generated hook must return. */
  hook: "block" | "pass";
  /** Native layer kinds that hold the case, as the harnesses document them. */
  heldBy: LayerKind[];
}

export const CORPUS: BypassCase[] = (data as { cases: BypassCase[] }).cases;

/** One installed harness, as the corpus sees it. */
export interface HarnessView {
  name: string;
  hookScope: "every-tool" | "shell-commands";
  coverage: RuleCoverage[];
}

export interface HarnessVerdict {
  name: string;
  /** "n/a": a benign case, or a tool shape this harness's hook never sees. */
  verdict: "held" | "unguarded" | "n/a";
  by: LayerKind[];
}

export interface CorpusResult {
  case: BypassCase;
  /** Why the case did not run — its rule is disabled or absent. */
  skipped?: string;
  gotHook: "block" | "pass" | "error";
  ok: boolean;
  harnesses: HarnessVerdict[];
}

/**
 * Run every case through the hook generated from `policy` and judge it per
 * harness. `ok` fails on a regression (an expected block that passed), on a
 * refused benign call, and on a hook error; a known gap that the policy now
 * blocks — the user added a stronger rule — is not a failure.
 */
export function runBypassCorpus(
  policy: CompiledPolicy,
  effective: EffectivePolicy,
  harnesses: HarnessView[],
): CorpusResult[] {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-corpus-"));
  const script = path.join(dir, "hook.sh");
  // Synthetic blocks must never land in the user's blocked-call log.
  fs.writeFileSync(script, generateHook({ ...policy, logFile: "" }), {
    mode: 0o755,
  });
  try {
    return CORPUS.map((c): CorpusResult => {
      if (!policy.rules.some((r) => r.id === c.rule)) {
        return {
          case: c,
          skipped: effective.disabled.includes(c.rule)
            ? `rule '${c.rule}' disabled`
            : `rule '${c.rule}' not in the policy`,
          gotHook: "pass",
          ok: true,
          harnesses: [],
        };
      }
      const r = spawnSync("sh", [script], {
        input: JSON.stringify(c.payload),
        encoding: "utf8",
        timeout: 10_000,
      });
      const gotHook: CorpusResult["gotHook"] =
        r.status === 2 ? "block" : r.status === 0 ? "pass" : "error";
      const ok =
        gotHook !== "error" &&
        (c.benign
          ? gotHook === "pass"
          : c.hook === "block"
            ? gotHook === "block"
            : true);
      const shellShaped = c.payload.tool_name === "Bash";
      const verdicts = harnesses.map((h): HarnessVerdict => {
        if (c.benign || (h.hookScope === "shell-commands" && !shellShaped)) {
          return { name: h.name, verdict: "n/a", by: [] };
        }
        const live = h.coverage.find((x) => x.rule === c.rule)?.kinds ?? [];
        const by: LayerKind[] = [];
        if (gotHook === "block" && live.includes("hook")) by.push("hook");
        for (const k of c.heldBy) {
          if (live.includes(k) && !by.includes(k)) by.push(k);
        }
        return {
          name: h.name,
          verdict: by.length > 0 ? "held" : "unguarded",
          by,
        };
      });
      return { case: c, gotHook, ok, harnesses: verdicts };
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
