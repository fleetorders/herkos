/**
 * Project-scoped never-list: a repo commits `herkos.json`, and herkos compiles
 * it into that repo's Claude Code project layer — a self-contained hook checked
 * into the repo and registered in the repo's `.claude/settings.json`.
 *
 * Three properties make this safe and portable:
 *
 * - COMPOSITION, not a merged policy. The project hook is a SEPARATE PreToolUse
 *   hook alongside the machine hook (in the user settings). Claude Code runs
 *   hooks from every settings level and any exit-2 blocks, so the project hook
 *   can only ADD refusals — it structurally cannot weaken the machine's floor.
 *   That is why `herkos.json` has no `disable`.
 *
 * - PORTABLE + STRANGER-SAFE. The committed hook is the same dependency-free
 *   shell herkos generates elsewhere (`sh`/`awk`/`grep`), referenced through
 *   `$CLAUDE_PROJECT_DIR` so it resolves in any clone, and it carries no machine
 *   path — the policy file it names is the repo-relative `herkos.json`. A
 *   stranger who clones the repo is guarded once they trust the project hook,
 *   even without herkos installed.
 *
 * - DRIFT-CHECKED. The committed hook carries the policy stamp, so `herkos
 *   project check` (in CI) fails when the committed hook no longer matches
 *   `herkos.json` — the same drift the machine install already detects.
 *
 * Claude Code only: Codex resolves config from `~/.codex` (global) plus `-c`
 * overrides and `-p` profiles, with no repo-local layer, so there is no honest
 * per-repo Codex target. A repo's Codex sessions are still covered by the
 * machine policy; they just do not get the repo's own committed list.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  compile,
  loadProjectPolicy,
  validateProjectPolicy,
  projectLogDestination,
  type CompiledPolicy,
  type EffectivePolicy,
  type ValidationResult,
} from "./policy.js";
import {
  generateHook,
  readInstalledStamp,
  stampOf,
} from "./adapters/claude-code.js";

/** The repo-relative path Claude Code resolves for the committed hook. */
const HOOK_REL = ".claude/hooks/herkos-project.sh";
// Registered so the harness contract holds at the edges too: a missing or
// unreadable hook file must degrade OPEN (plain `sh` on a missing script exits
// 2, which the harness reads as "block" — every tool call in the repo refused,
// the opposite of the hook body's own degrade-to-allow design), while a
// deliberate exit-2 block from inside the hook still propagates; and
// --harness names the caller, so an open rule's notice picks its channel and a
// block is attributed in the blocked-call log.
const HOOK_COMMAND = `test -r "$CLAUDE_PROJECT_DIR/${HOOK_REL}" || { printf 'herkos DEGRADED: project hook not readable — enforcement OFF for this call.\\n' >&2; exit 0; }; sh "$CLAUDE_PROJECT_DIR/${HOOK_REL}" --harness claude-code`;

export function projectHookPath(repoRoot: string): string {
  return path.join(repoRoot, HOOK_REL);
}

export function projectSettingsPath(repoRoot: string): string {
  return path.join(repoRoot, ".claude", "settings.json");
}

/**
 * Compile a repo's `herkos.json` with a repo-relative policy path, so the hook
 * baked from it names `herkos.json` rather than an absolute machine path — the
 * committed artifact must carry nothing machine-specific.
 */
export function compileProjectPolicy(repoRoot: string): {
  effective: EffectivePolicy;
  compiled: CompiledPolicy;
} {
  const effective = loadProjectPolicy(repoRoot);
  const compiled = {
    ...compile(effective),
    userPolicyPath: "herkos.json",
    // A committed hook logs only when herkos.json asks for it, and then to a
    // run-time-resolved repo-relative file beside the hook (see
    // ProjectPolicy.logFile) — never a baked absolute machine path.
    logFile: projectLogDestination(effective.projectLogFile),
  };
  return { effective, compiled };
}

interface SettingsHookEntry {
  matcher?: string;
  hooks?: { type?: string; command?: string }[];
}

/** Is this settings entry the herkos project hook? */
function isOursProject(entry: SettingsHookEntry): boolean {
  return (entry.hooks ?? []).some((h) => (h.command ?? "").includes(HOOK_REL));
}

/**
 * Does git track this file? Best effort: anything uncertain — no git, not a
 * repo, a spawn failure — counts as UNtracked, so the pre-edit backup is
 * still taken. Only a definitive "git holds the prior state" skips it.
 */
function gitTracks(file: string): boolean {
  try {
    return (
      spawnSync("git", ["ls-files", "--error-unmatch", "--", file], {
        cwd: path.dirname(file),
        encoding: "utf8",
        timeout: 5_000,
      }).status === 0
    );
  } catch {
    return false;
  }
}

export interface ProjectWireResult {
  changed: string[];
  ruleCount: number;
  detail: string;
}

/**
 * Compile the repo's `herkos.json` into its Claude Code project layer: write
 * the self-contained hook and register it on PreToolUse in the repo's
 * `.claude/settings.json`. Idempotent (the herkos entry is replaced, never
 * duplicated). Before the first edit of a settings file it takes a one-time
 * backup — unless git already tracks the file, in which case the prior state
 * lives in history and a backup file would only be untracked residue dirtying
 * every clone that runs init.
 */
export function wireProject(
  repoRoot: string,
  compiled: CompiledPolicy,
): ProjectWireResult {
  const changed: string[] = [];

  // 1. The committed, self-contained hook.
  const hookFile = projectHookPath(repoRoot);
  fs.mkdirSync(path.dirname(hookFile), { recursive: true });
  fs.writeFileSync(hookFile, generateHook(compiled), { mode: 0o755 });
  changed.push(hookFile);

  // 2. Register it on PreToolUse in the repo's project settings.
  const sp = projectSettingsPath(repoRoot);
  let settings: Record<string, unknown> = {};
  let backedUp = false;
  if (fs.existsSync(sp)) {
    settings = JSON.parse(fs.readFileSync(sp, "utf8")) as Record<
      string,
      unknown
    >;
    const bak = `${sp}.herkos-bak`;
    // Only when git does not hold the prior state (see the doc above): a
    // tracked settings file needs no second copy beside it.
    if (!fs.existsSync(bak) && !gitTracks(sp)) {
      fs.copyFileSync(sp, bak);
      changed.push(bak);
      backedUp = true;
    }
  }
  const rawHooks = settings["hooks"];
  const hooks = (
    typeof rawHooks === "object" && rawHooks !== null ? rawHooks : {}
  ) as Record<string, SettingsHookEntry[]>;
  const rawPre = hooks["PreToolUse"];
  const pre = (Array.isArray(rawPre) ? rawPre : []).filter(
    (e) => !isOursProject(e),
  );
  pre.push({
    matcher: "*",
    hooks: [{ type: "command", command: HOOK_COMMAND }],
  });
  hooks["PreToolUse"] = pre;
  settings["hooks"] = hooks;
  fs.mkdirSync(path.dirname(sp), { recursive: true });
  fs.writeFileSync(sp, JSON.stringify(settings, null, 2) + "\n");
  changed.push(sp);

  return {
    changed,
    ruleCount: compiled.ruleCount,
    detail: `project hook generated (${compiled.ruleCount} rule(s), stamp ${stampOf(compiled)}) and registered on PreToolUse in ${path.relative(repoRoot, sp) || sp}.${compiled.logFile ? ` Blocks are logged to ${compiled.logFile}, resolved beside the hook at run time — gitignore it and the sessions/ dir beside it, or the first refusal dirties the clone.` : ""}${backedUp ? ` A one-time pre-herkos backup of the previous settings sits at ${path.relative(repoRoot, `${sp}.herkos-bak`)} — untracked; delete it (or commit it) once the wiring looks right.` : ""} Commit .claude/ so every clone is guarded; it composes on top of each contributor's machine policy and can only add blocks.`,
  };
}

/** Remove exactly what wireProject added: the hook entry, the hook file, and an emptied hooks container. */
export function unwireProject(repoRoot: string): ProjectWireResult {
  const changed: string[] = [];
  const sp = projectSettingsPath(repoRoot);
  if (fs.existsSync(sp)) {
    const settings = JSON.parse(fs.readFileSync(sp, "utf8")) as Record<
      string,
      unknown
    >;
    const rawHooks = settings["hooks"];
    const hooks = (
      typeof rawHooks === "object" && rawHooks !== null ? rawHooks : {}
    ) as Record<string, SettingsHookEntry[]>;
    const pre = hooks["PreToolUse"];
    if (Array.isArray(pre)) {
      const kept = pre.filter((e) => !isOursProject(e));
      if (kept.length !== pre.length) {
        if (kept.length === 0) delete hooks["PreToolUse"];
        else hooks["PreToolUse"] = kept;
        if (Object.keys(hooks).length === 0) delete settings["hooks"];
        else settings["hooks"] = hooks;
        fs.writeFileSync(sp, JSON.stringify(settings, null, 2) + "\n");
        changed.push(sp);
      }
    }
  }
  const hookFile = projectHookPath(repoRoot);
  if (fs.existsSync(hookFile)) {
    fs.rmSync(hookFile);
    changed.push(hookFile);
  }
  return {
    changed,
    ruleCount: 0,
    detail: changed.length ? "project wiring removed" : "nothing to remove",
  };
}

export interface ProjectVerifyResult {
  ok: boolean;
  state: "ok" | "stale" | "unwired" | "no-policy";
  detail: string;
}

/**
 * Verify a repo's committed project wiring against its `herkos.json` — the CI
 * drift check. `unwired` when there is a policy but no registered hook;
 * `stale` when the committed hook's stamp does not match the policy (someone
 * edited `herkos.json` without re-running `project init`); `ok` when they agree.
 */
export function verifyProject(repoRoot: string): ProjectVerifyResult {
  const { effective, compiled } = compileProjectPolicy(repoRoot);
  if (!effective.userPolicyLoaded) {
    return {
      ok: false,
      state: "no-policy",
      detail: `no ${path.join(path.relative(process.cwd(), repoRoot) || ".", "herkos.json")} — nothing to check`,
    };
  }
  const hookFile = projectHookPath(repoRoot);
  const sp = projectSettingsPath(repoRoot);
  const registered =
    fs.existsSync(sp) &&
    fs.readFileSync(sp, "utf8").includes(HOOK_REL) &&
    fs.existsSync(hookFile);
  if (!registered) {
    return {
      ok: false,
      state: "unwired",
      detail: `herkos.json present but no committed project hook — run 'herkos project init'`,
    };
  }
  const installed = readInstalledStamp(hookFile);
  const want = stampOf(compiled);
  if (installed !== want) {
    return {
      ok: false,
      state: "stale",
      detail: `the committed project hook carries '${installed}' but herkos.json compiles to '${want}' — run 'herkos project init' and commit the result`,
    };
  }
  return {
    ok: true,
    state: "ok",
    detail: `project hook matches herkos.json (${compiled.ruleCount} rule(s), stamp ${want}); ${logNote(repoRoot, hookFile, compiled.logFile)}`,
  };
}

/**
 * What the project check says about the blocked-call log: where a policy
 * asked for one, or that none is configured. A configured destination git
 * does not ignore gets named — the first block would dirty the tree, which
 * belongs in a CI check's output, not in a contributor's surprise. git's
 * verdict is best effort: no git, no repo, no verdict — silence, never error.
 */
function logNote(repoRoot: string, hookFile: string, logFile: string): string {
  if (logFile === "")
    return `no block log (herkos.json may set "logFile" to record refusals beside the hook)`;
  let note = `block log at ${logFile}, resolved beside the hook at run time`;
  const r = spawnSync(
    "git",
    [
      "-C",
      repoRoot,
      "check-ignore",
      "-q",
      "--",
      path.join(path.dirname(hookFile), logFile),
    ],
    { encoding: "utf8", timeout: 5_000 },
  );
  if (r.status === 1)
    note += ` — NOT gitignored: the first block dirties the clone; add it (and the sessions/ dir) to .gitignore`;
  return note;
}

/** Validate a repo's project policy (thin re-export path for the CLI). */
export function validateRepoPolicy(repoRoot: string): {
  effective: EffectivePolicy;
  validation: ValidationResult;
} {
  const effective = loadProjectPolicy(repoRoot);
  return { effective, validation: validateProjectPolicy(effective) };
}
