import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
    timeout: 10_000,
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
  const grab = (re: RegExp) => re.exec(script)?.[1];
  const line = grab(/^FIELDS=\$\((.*)\)$/m);
  const awk = grab(/^EXTRACT_AWK='([^']*)'$/m);
  const pkeys = grab(/^PATH_KEYS='([^']*)'$/m);
  const ckeys = grab(/^COMMAND_KEYS='([^']*)'$/m);
  if (!line || !awk || !pkeys || !ckeys)
    throw new Error(
      "the hook no longer has the extractor shape this helper reads",
    );
  const command = line.replace(/ 2>\/dev\/null$/, "");
  return (payload) => {
    const r = spawnSync("sh", ["-c", command], {
      input: payload,
      encoding: "utf8",
      timeout: 10_000,
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
