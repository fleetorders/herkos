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
): { exit: number; stderr: string; stdout: string } {
  const r = spawnSync("sh", [scriptPath], {
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
