import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { EXTRACT_AWK } from "../src/extract.js";

/**
 * Point herkos at an empty config directory for the whole test process, so a
 * suite never reads THIS machine's user policy (a rule disabled there would
 * change what the baseline cases expect). Call before loading any policy.
 */
export function isolateConfig(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-test-cfg-"));
  process.env.HERKOS_CONFIG = dir;
  return dir;
}

/** Write a generated hook to a temp file and return its path. */
export function writeHook(script: string): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-test-"));
  const f = path.join(tmp, "hook.sh");
  fs.writeFileSync(f, script, { mode: 0o755 });
  return f;
}

/**
 * Wall-clock cap for every synthetic-payload spawn of the generated hook. The
 * cap exists so a HUNG hook fails its test instead of hanging the suite — it
 * is not a budget a healthy hook spends. Spawn latency alone (sh plus the
 * hook, on a machine under load: a parallel CI fleet, a busy laptop) can
 * exceed a tight cap, and the timeout then reads as the hook failing —
 * wholesale, with a failure set that moves between runs. 60s keeps load
 * spikes from masquerading as verdicts while still bounding a hang.
 */
export const SPAWN_TIMEOUT_MS = 60_000;

/** Fire one synthetic tool-call payload through a hook script. */
export function fireHook(
  scriptPath: string,
  payload: string,
  env: NodeJS.ProcessEnv = process.env,
  args: string[] = [],
): { exit: number; stderr: string; stdout: string } {
  const r = spawnSync("sh", [scriptPath, ...args], {
    input: payload,
    encoding: "utf8",
    timeout: SPAWN_TIMEOUT_MS,
    env,
  });
  return {
    exit: r.status ?? -1,
    stderr: r.stderr ?? "",
    stdout: r.stdout ?? "",
  };
}

/** A tool-call payload in the harness's PreToolUse shape. */
export const call = (tool_name: string, tool_input: unknown): string =>
  JSON.stringify({ tool_name, tool_input });

/**
 * The generated hook's own extractor command, runnable on its own: returns a
 * function that feeds one payload through exactly the `FIELDS=$(...)` line the
 * hook runs, locale prefix and all, and returns its record lines. Tests that
 * probe the reader go through this, so a change to how the hook invokes awk is
 * what they test. Throws when the reader exits non-zero.
 */
export function hookExtractor(
  script: string,
  env: NodeJS.ProcessEnv = process.env,
): (payload: string) => string[] {
  // Each piece is named in its failure, so a reformat of the hook breaks the
  // tests with the exact line that changed, not one generic shape error.
  const grab = (name: string, re: RegExp): string => {
    const found = re.exec(script)?.[1];
    if (found === undefined)
      throw new Error(
        `the hook no longer has the ${name} line this helper reads`,
      );
    return found;
  };
  const line = grab("FIELDS=$(…) extractor invocation", /^FIELDS=\$\((.*)\)$/m);
  const awk = grab("EXTRACT_AWK assignment", /^EXTRACT_AWK='([^']*)'$/m);
  const pkeys = grab("PATH_KEYS assignment", /^PATH_KEYS='([^']*)'$/m);
  const ckeys = grab("COMMAND_KEYS assignment", /^COMMAND_KEYS='([^']*)'$/m);
  if (awk !== EXTRACT_AWK)
    throw new Error(
      "the hook's embedded EXTRACT_AWK no longer equals src/extract.ts — the adapter template and the extractor drifted apart",
    );
  const command = line.replace(/ 2>\/dev\/null$/, "");
  return (payload) => {
    const r = spawnSync("sh", ["-c", command], {
      input: payload,
      encoding: "utf8",
      timeout: SPAWN_TIMEOUT_MS,
      env: {
        ...env,
        PATH_KEYS: pkeys,
        COMMAND_KEYS: ckeys,
        EXTRACT_AWK: awk,
      },
    });
    if (r.status !== 0)
      throw new Error(`the extractor exited ${r.status}: ${r.stderr}`);
    return (r.stdout ?? "").split("\n").filter((l) => l !== "");
  };
}
