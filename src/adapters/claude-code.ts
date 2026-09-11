/**
 * Claude Code adapter. Enforcement is delivered as a generated, self-contained
 * shell hook wired into the harness's PreToolUse hooks — shell because the hook
 * runs on EVERY tool call and must add near-zero latency, self-contained because
 * the enforcement path may depend on nothing (not this package, not the network).
 * The compiled rules are baked into the generated script; regenerating the hook
 * is how a policy change deploys.
 *
 * Hooks fire in every permission mode, including bypass/skip-permissions modes —
 * which is exactly why this is the enforcement point: headless and unattended
 * runs get the same wall as interactive ones.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { blockLogFile, compile, loadEffectivePolicy } from "../policy.js";
import type { CompiledPolicy, CompiledRule } from "../policy.js";
import { COMMAND_KEYS, KNOWN_TOOLS, PATH_KEYS } from "../matchers.js";
import type {
  HarnessAdapter,
  DetectResult,
  WireResult,
  VerifyResult,
} from "./types.js";

const HOOK_MARK = "herkos-hook";
const SESSION_MARK = "herkos-session-start";

export function herkosDir(): string {
  return (
    process.env.HERKOS_CONFIG ?? path.join(os.homedir(), ".config", "herkos")
  );
}

export function hookPath(): string {
  return path.join(herkosDir(), "hook-claude-code.sh");
}

/** The blocked-call log the hook appends to (see blocklog.ts). */
export function blockLogPath(): string {
  return blockLogFile();
}

/** Rotate the log past this size: one previous generation is kept. */
const LOG_MAX_BYTES = 1_048_576;

/**
 * The session-start hook: one line per session saying whether the never-list is
 * actually enforced right now. Separate from the enforcement hook because it
 * runs once per session rather than on every tool call, and because its absence
 * must never affect enforcement.
 */
export function sessionStartHookPath(): string {
  return path.join(herkosDir(), "hook-session-start.sh");
}

/**
 * A byte copy of the user policy as it stood at `init`. The session-start hook
 * compares the live file against it with nothing but `cat` and a string test —
 * that is the dependency-free way to notice "the policy was edited but never
 * recompiled", which the baked fingerprint alone cannot see (an uncompiled edit
 * leaves hook and expectation in agreement, both stale).
 */
export function policySnapshotPath(): string {
  return path.join(herkosDir(), "policy.snapshot");
}

/**
 * Which entries of the harness's own settings herkos added. Permission rules are
 * bare strings with no room for a marker, so ownership is recorded beside the
 * hook: `unwire` removes exactly these, and an identical entry the user wrote
 * before herkos is never recorded — so it is never removed.
 */
export function ownedSettingsPath(): string {
  return path.join(herkosDir(), "claude-code-owned.json");
}

interface OwnedSettings {
  /** permissions.deny entries herkos added. */
  deny: string[];
  /** herkos created the permissions object — drop it once it is empty. */
  createdPermissions: boolean;
  /** herkos created permissions.deny — drop it once it is empty. */
  createdDeny: boolean;
}

function readOwned(): OwnedSettings {
  try {
    const o = JSON.parse(
      fs.readFileSync(ownedSettingsPath(), "utf8"),
    ) as Partial<OwnedSettings>;
    return {
      deny: Array.isArray(o.deny)
        ? o.deny.filter((d): d is string => typeof d === "string")
        : [],
      createdPermissions: o.createdPermissions === true,
      createdDeny: o.createdDeny === true,
    };
  } catch {
    return { deny: [], createdPermissions: false, createdDeny: false };
  }
}

/**
 * The permission deny rules a policy compiles to: one `Read(…)` per read-deny
 * target. These are the strongest layer Claude Code has — they hold in every
 * permission mode, block through a symlink as well as its target, cover the
 * file commands the harness recognises inside Bash, and no hook or setting can
 * override them. Command-shaped rules never become deny rules: denying a
 * command prefix would refuse every legitimate use of that program.
 *
 * Claude Code resolves a single leading slash relative to the settings file,
 * so an absolute target is written with two.
 */
export function claudeDenyRules(policy: CompiledPolicy): string[] {
  const out: string[] = [];
  for (const r of policy.rules) {
    for (const t of r.denyRead) {
      const target = t.startsWith("/") && !t.startsWith("//") ? `/${t}` : t;
      const rule = `Read(${target})`;
      if (!out.includes(rule)) out.push(rule);
    }
  }
  return out;
}

/** Drop permission containers herkos created once they hold nothing. */
function tidyPermissions(
  settings: Record<string, unknown>,
  owned: OwnedSettings,
): boolean {
  const perms = settings["permissions"];
  if (typeof perms !== "object" || perms === null) return false;
  const p = perms as Record<string, unknown>;
  let changed = false;
  const deny = p["deny"];
  if (owned.createdDeny && Array.isArray(deny) && deny.length === 0) {
    delete p["deny"];
    changed = true;
  }
  if (owned.createdPermissions && Object.keys(p).length === 0) {
    delete settings["permissions"];
    changed = true;
  }
  return changed;
}

function settingsPath(configDir: string): string {
  return path.join(configDir, "settings.json");
}

export function detectConfigDir(): string {
  return process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), ".claude");
}

/**
 * Quote a string as a POSIX single-quoted shell literal. EVERY value baked
 * into the generated script (rule ids, descriptions, path and command regexes,
 * the policy path) goes through this — a pattern containing a single quote
 * must never break the script's syntax, or the hook exits 2 on every call and
 * bricks the session (D-004).
 */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const STAMP_MARK = "herkos-stamp:";

/** The wiring stamp: "<version> <policy fingerprint> <rule count>". */
export function stampOf(policy: CompiledPolicy): string {
  return `${policy.version} ${policy.hash} ${policy.ruleCount}`;
}

/**
 * The stamp of the hook installed on this machine, read from its marker line
 * (no execution — `status` must work even if the file lost its exec bit).
 * `null` when there is no hook, or it carries no stamp (generated by a herkos
 * older than stamping).
 */
export function readInstalledStamp(file: string = hookPath()): string | null {
  if (!fs.existsSync(file)) return null;
  const m = fs
    .readFileSync(file, "utf8")
    .match(new RegExp(`^#\\s*${STAMP_MARK}\\s*(.+)$`, "m"));
  return m?.[1]?.trim() ?? null;
}

/**
 * Generate the hook script text from a compiled policy. Exported for tests and
 * for `herkos check`, which runs the generated script against synthetic
 * payloads. The script:
 * - blocks (exit 2, reason on stderr — the protocol Claude Code requires) when
 *   a Bash command or a file path matches the compiled never-list, naming the
 *   rule that fired;
 * - fails OPEN but LOUD when it cannot parse its input (a security hook that
 *   hard-blocks on every malformed call would brick the session; one that
 *   silently allows would be worse — so it allows and announces). The same
 *   applies per-rule at grep time: a pattern grep cannot evaluate turns that
 *   ONE rule off for the call, loudly, and the rest of the never-list stays
 *   enforced — never exit 2 on a grep error;
 * - supports --selftest so the wiring can prove itself end to end.
 */
export function generateHook(policy: CompiledPolicy): string {
  // One check per rule (not one merged regex) so a refusal can name its rule.
  // Both rule bodies take the subject as "$1" and the kind as "$2", so the same
  // baked lines serve every tool argument the extractor found.
  // enforce <id> <description> <kind> <subject> <regex>
  const pathLine = (rule: CompiledRule): string =>
    rule.pathRegex === ""
      ? ""
      : `  enforce ${shQuote(rule.id)} ${shQuote(rule.description)} "$2" "$1" ${shQuote(rule.pathRegex)}`;
  const cmdLine = (rule: CompiledRule, re: string): string =>
    `  enforce ${shQuote(rule.id)} ${shQuote(rule.description)} "$2" "$1" ${shQuote(re)}`;

  // A command-shaped argument is checked against BOTH vocabularies: it may name
  // a credential file (`cat ~/.kube/config`) or be fetched code piped to a shell.
  const commandRules =
    policy.rules
      .flatMap((rule) => [
        pathLine(rule),
        ...rule.commandRegexes.map((re) => cmdLine(rule, re)),
      ])
      .filter((line) => line !== "")
      .join("\n") || "  :";
  const pathRules =
    policy.rules
      .map(pathLine)
      .filter((line) => line !== "")
      .join("\n") || "  :";

  const shList = (xs: readonly string[]): string => shQuote(xs.join(" "));

  return `#!/bin/sh
# Generated by herkos — do not edit; edit your policy and re-run 'herkos init'.
# Blocks the never-list at the tool-call layer, in every mode.
# marker: ${HOOK_MARK}
# ${STAMP_MARK} ${policy.version} ${policy.hash} ${policy.ruleCount}

PATH_RE=${shQuote(policy.pathRegex)}
POLICY_FILE=${shQuote(policy.userPolicyPath)}
STAMP=${shQuote(stampOf(policy))}
PATH_KEYS=${shList(PATH_KEYS)}
COMMAND_KEYS=${shList(COMMAND_KEYS)}
KNOWN_TOOLS=${shList(KNOWN_TOOLS)}
LOG_FILE=${shQuote(policy.logFile)}
LOG_MAX_BYTES=${LOG_MAX_BYTES}
TOOL=""

# The registered command names its harness, so a block is attributed to it.
HARNESS=unknown
if [ "\${1:-}" = "--harness" ]; then
  if [ "$#" -ge 2 ]; then HARNESS=$2; shift 2; else shift; fi
fi

block() {
  printf '%s\\n' "$1" >&2
  exit 2
}

# json VALUE — escape for a JSON string: backslash, quote, control characters.
json() {
  printf '%s' "$1" | tr -d '\\000-\\037' | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g'
}

# log_block RULE — one JSON line per refusal: time, harness, tool, rule, cwd.
# NEVER the command text, which can itself carry a secret. Best effort at every
# step and every failure swallowed: a log that cannot be written must never
# turn a block into an allow, and enforcement never depends on these utilities.
log_block() {
  [ -n "$LOG_FILE" ] || return 0
  {
    log_dir=$(dirname "$LOG_FILE")
    [ -d "$log_dir" ] || mkdir -p "$log_dir"
    if [ -f "$LOG_FILE" ]; then
      log_size=$(wc -c < "$LOG_FILE" | tr -d ' ')
      if [ "\${log_size:-0}" -gt "$LOG_MAX_BYTES" ]; then
        mv -f "$LOG_FILE" "$LOG_FILE.1"
      fi
    fi
    printf '{"event":"block","time":"%s","harness":"%s","tool":"%s","rule":"%s","cwd":"%s"}\\n' \\
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json "$HARNESS")" "$(json "$TOOL")" "$(json "$1")" "$(json "$(pwd)")" >> "$LOG_FILE"
  } 2>/dev/null || true
}

# enforce ID DESCRIPTION KIND SUBJECT REGEX — grep the subject against one
# compiled pattern. Match → block, naming the rule. No match → fall through.
# grep itself failing (bad regex, exit >= 2) degrades LOUDLY: that one rule is
# off for this call and the session keeps working; every other rule stays
# enforced. Never exit 2 because of a grep error.
enforce() {
  [ -n "$5" ] || return 0
  printf '%s' "$4" | grep -Eq -e "$5"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_block "$1"
    block "BLOCKED (herkos) rule $1 — $2. This $3 is on the never-list. To adjust: narrow the rule in $POLICY_FILE or disable it by id; 'herkos rules' lists the policy."
  fi
  if [ "$rc" -ge 2 ]; then
    printf "herkos DEGRADED: rule %s pattern could not be evaluated (grep exit %s) — that rule is OFF for this call. Run 'herkos validate'.\\n" "$1" "$rc" >&2
  fi
}

# command_rules SUBJECT KIND — everything a shell or interpreter will run.
command_rules() {
${commandRules}
}

# path_rules SUBJECT KIND — everything that names a file.
path_rules() {
${pathRules}
}

if [ "\${1:-}" = "--stamp" ]; then
  # Machine-readable: "<version> <policy fingerprint> <rule count>". The
  # session-start hook and 'herkos status' read this to tell a current hook
  # from one generated before the policy changed.
  printf '%s\\n' "$STAMP"
  exit 0
fi

if [ "\${1:-}" = "--selftest" ]; then
  # Exercised by 'herkos check' with synthetic payloads on stdin plus an
  # expected verdict; here we only confirm the script runs and rules are baked.
  printf 'herkos hook selftest: %s rule(s), path regex %s, stamp %s\\n' "${policy.rules.length}" "\${PATH_RE:+set}" "$STAMP"
  exit 0
fi

IN=$(cat 2>/dev/null) || exit 0
command -v jq >/dev/null 2>&1 || {
  printf 'herkos DEGRADED: jq unavailable — never-list enforcement is OFF for this call. Install jq to restore.\\n' >&2
  exit 0
}

TOOL=$(printf '%s' "$IN" | jq -r '.tool_name // ""' 2>/dev/null)

# values KEYS — every non-empty string held under one of KEYS, at any depth of
# tool_input, one per line (array elements individually). Reading by argument
# NAME rather than by tool name is what lets a tool-server tool that takes a
# path be checked without herkos having heard of it.
values() {
  printf '%s' "$IN" | jq -r --arg keys "$1" '
    ($keys | split(" ")) as $k
    | [ (.tool_input // {}) | .. | objects | to_entries[]
        | select(.key as $n | $k | index($n)) | .value
        | if type == "array" then .[] else . end
        | select(type == "string" and length > 0) ]
    | unique | .[]' 2>/dev/null
}

COMMAND_VALUES=$(values "$COMMAND_KEYS")
PATH_VALUES=$(values "$PATH_KEYS")

# Split on newlines only, in THIS shell (not a pipeline subshell), so a block's
# exit 2 ends the hook rather than a subshell. Pathname expansion is OFF while
# the values are split: an argument like "src/*" must be checked as written,
# never replaced by whatever files happen to sit in the working directory.
OLD_IFS=$IFS
IFS='
'
set -f
for v in $COMMAND_VALUES; do command_rules "$v" "$TOOL command"; done
for v in $PATH_VALUES; do path_rules "$v" "$TOOL path"; done
set +f
IFS=$OLD_IFS

# Honest coverage: a tool herkos does not know, whose arguments carry none of
# the names it reads, is UNCOVERED — it may touch anything, and herkos cannot
# see what. Say so; never assume it is safe. Known tools that take no path stay
# quiet, because an announcement on every call is how a guard gets muted.
if [ -z "$COMMAND_VALUES" ] && [ -z "$PATH_VALUES" ] && [ -n "$TOOL" ]; then
  case " $KNOWN_TOOLS " in
    *" $TOOL "*) ;;
    *)
      NARGS=$(printf '%s' "$IN" | jq -r '(.tool_input // {}) | if type == "object" then (keys | length) else 0 end' 2>/dev/null)
      case "$NARGS" in
        ''|0) ;;
        *) printf "herkos UNCOVERED: tool %s passed arguments herkos cannot read as a path or a command — the never-list was NOT checked for this call.\\n" "$TOOL" >&2 ;;
      esac
      ;;
  esac
fi
exit 0
`;
}

/**
 * Generate the session-start script: the answer to "is the never-list actually
 * enforced in THIS session?", printed once before the first tool call.
 *
 * The silent-absence failure is the one that costs everything — a harness
 * upgrade, a hand-edited settings file or a policy edited without recompiling
 * leaves the user believing they are guarded while nothing is. The README used
 * to ask people to run `check` after upgrades; nobody does, so this says it
 * unasked, every session.
 *
 * Dependency-free like the enforcement hook, and deliberately silent about
 * anything it cannot establish: it reports what it checked, never a guarantee.
 * It exits 0 in every branch — a proof line must never be able to stop a
 * session.
 */
export function generateSessionStartHook(
  policy: CompiledPolicy,
  harnessName: string,
  settingsFile: string,
): string {
  return `#!/bin/sh
# Generated by herkos — do not edit; edit your policy and re-run 'herkos init'.
# Prints one line per session: enforced, or not wired and what is unenforced.
# marker: ${SESSION_MARK}

HOOK=${shQuote(hookPath())}
SETTINGS=${shQuote(settingsFile)}
POLICY_FILE=${shQuote(policy.userPolicyPath)}
SNAPSHOT=${shQuote(policySnapshotPath())}
WANT_STAMP=${shQuote(stampOf(policy))}
RULE_COUNT=${shQuote(String(policy.ruleCount))}
CLASSES=${shQuote(policy.classes.join(", "))}
HARNESS=${shQuote(harnessName)}

say() {
  printf 'herkos: %s\\n' "$1"
}

if [ ! -f "$HOOK" ]; then
  say "NOT wired on $HARNESS — the enforcement hook is missing at $HOOK, so nothing on the never-list is blocked ($CLASSES). Run 'herkos init'."
  exit 0
fi

if [ -f "$SETTINGS" ] && ! grep -q -F -e "$HOOK" "$SETTINGS" 2>/dev/null; then
  say "NOT wired on $HARNESS — the hook exists but is not registered in $SETTINGS, so no tool call reaches it ($CLASSES unenforced). Run 'herkos init'."
  exit 0
fi

GOT_STAMP=$(sh "$HOOK" --stamp 2>/dev/null)
if [ "$GOT_STAMP" != "$WANT_STAMP" ]; then
  say "DRIFT on $HARNESS — the installed hook reports '$GOT_STAMP' but this wiring expects '$WANT_STAMP'. The hook was replaced or edited; run 'herkos init' to recompile."
  exit 0
fi

LIVE=""
SNAP=""
if [ -f "$POLICY_FILE" ]; then LIVE=$(cat "$POLICY_FILE" 2>/dev/null); fi
if [ -f "$SNAPSHOT" ]; then SNAP=$(cat "$SNAPSHOT" 2>/dev/null); fi
if [ "$LIVE" != "$SNAP" ]; then
  say "enforced on $HARNESS with $RULE_COUNT rule(s), BUT $POLICY_FILE changed since 'herkos init' — the hook still carries the old rules. Run 'herkos init' to recompile."
  exit 0
fi

say "enforced on $HARNESS — $RULE_COUNT rule(s) ($CLASSES) checked on every tool call, in every mode."
exit 0
`;
}

interface SettingsHookEntry {
  matcher?: string;
  hooks?: { type?: string; command?: string }[];
}

/** Does this settings entry run one of the scripts herkos owns? */
function isOurs(entry: SettingsHookEntry): boolean {
  return (entry.hooks ?? []).some((h) => {
    const c = h.command ?? "";
    return c.includes(hookPath()) || c.includes(sessionStartHookPath());
  });
}

export const claudeCodeAdapter: HarnessAdapter = {
  id: "claude-code",
  name: "Claude Code",

  detect(): DetectResult {
    const r = spawnSync("claude", ["--version"], {
      encoding: "utf8",
      timeout: 15_000,
    });
    if (r.status !== 0 || r.error) {
      return { installed: false, detail: "claude not found on PATH" };
    }
    const version = (r.stdout ?? "").trim().split("\n")[0] ?? "unknown";
    const configDir = detectConfigDir();
    return {
      installed: true,
      version,
      configDir,
      detail: `${version} · config at ${configDir}`,
    };
  },

  wire(policy: CompiledPolicy): WireResult {
    const changed: string[] = [];
    const configDir = detectConfigDir();
    const sp = settingsPath(configDir);

    // 1. The generated hook, owned by herkos in its own directory.
    fs.mkdirSync(herkosDir(), { recursive: true });
    fs.writeFileSync(hookPath(), generateHook(policy), { mode: 0o755 });
    changed.push(hookPath());

    // 2. Wire it into settings.json (create the file if the harness has none yet).
    let settings: Record<string, unknown> = {};
    if (fs.existsSync(sp)) {
      settings = JSON.parse(fs.readFileSync(sp, "utf8")) as Record<
        string,
        unknown
      >;
      const bak = `${sp}.herkos-bak`;
      if (!fs.existsSync(bak)) {
        fs.copyFileSync(sp, bak); // one pre-herkos backup, never overwritten
        changed.push(bak);
      }
    }
    const hooks = (settings["hooks"] ?? {}) as Record<
      string,
      SettingsHookEntry[]
    >;
    const pre: SettingsHookEntry[] = (hooks["PreToolUse"] ?? []).filter(
      (e) => !isOurs(e),
    );
    const cmd = `sh "${hookPath()}" --harness claude-code`;
    // Every tool, including tool-server tools: the hook decides what to read by
    // argument name, so a new tool is covered without a new matcher.
    pre.push({ matcher: "*", hooks: [{ type: "command", command: cmd }] });
    hooks["PreToolUse"] = pre;

    // 3. The session-start proof, and the policy snapshot it compares against.
    fs.writeFileSync(
      policySnapshotPath(),
      fs.existsSync(policy.userPolicyPath)
        ? fs.readFileSync(policy.userPolicyPath, "utf8")
        : "",
    );
    changed.push(policySnapshotPath());
    fs.writeFileSync(
      sessionStartHookPath(),
      generateSessionStartHook(policy, "Claude Code", sp),
      { mode: 0o755 },
    );
    changed.push(sessionStartHookPath());
    const start: SettingsHookEntry[] = (hooks["SessionStart"] ?? []).filter(
      (e) => !isOurs(e),
    );
    start.push({
      hooks: [{ type: "command", command: `sh "${sessionStartHookPath()}"` }],
    });
    hooks["SessionStart"] = start;

    // 4. Credential reads as the harness's own permission deny rules.
    const owned = readOwned();
    const rawPerms = settings["permissions"];
    const hadPerms = typeof rawPerms === "object" && rawPerms !== null;
    const permissions = (hadPerms ? rawPerms : {}) as Record<string, unknown>;
    const hadDeny = Array.isArray(permissions["deny"]);
    // Withdraw what herkos added last time first, so a narrowed policy leaves no
    // stale entry behind; entries the user wrote are carried over untouched.
    const deny = (hadDeny ? (permissions["deny"] as unknown[]) : []).filter(
      (d) => !(typeof d === "string" && owned.deny.includes(d)),
    );
    const added: string[] = [];
    for (const rule of claudeDenyRules(policy)) {
      if (!deny.includes(rule)) {
        deny.push(rule);
        added.push(rule);
      }
    }
    const nowOwned: OwnedSettings = {
      deny: added,
      createdPermissions: owned.createdPermissions || !hadPerms,
      createdDeny: owned.createdDeny || !hadDeny,
    };
    permissions["deny"] = deny;
    settings["permissions"] = permissions;
    tidyPermissions(settings, nowOwned);
    fs.writeFileSync(
      ownedSettingsPath(),
      JSON.stringify(nowOwned, null, 2) + "\n",
    );
    changed.push(ownedSettingsPath());

    settings["hooks"] = hooks;
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(sp, JSON.stringify(settings, null, 2) + "\n");
    changed.push(sp);

    return {
      changed,
      detail: `hook generated (${policy.ruleCount} rules, stamp ${stampOf(policy)}) and registered on PreToolUse for every tool; ${claudeDenyRules(policy).length} credential read(s) added to permissions.deny; a session-start line reports enforcement each session. Takes effect for sessions started from now on.`,
    };
  },

  unwire(): WireResult {
    const changed: string[] = [];
    const sp = settingsPath(detectConfigDir());
    if (fs.existsSync(sp)) {
      const settings = JSON.parse(fs.readFileSync(sp, "utf8")) as Record<
        string,
        unknown
      >;
      const hooks = (settings["hooks"] ?? {}) as Record<
        string,
        SettingsHookEntry[]
      >;
      let touched = false;
      for (const event of ["PreToolUse", "SessionStart"]) {
        const entries = hooks[event];
        if (!entries) continue;
        const kept = entries.filter((e) => !isOurs(e));
        if (kept.length === entries.length) continue;
        // Leave no empty event key behind: unwire removes exactly what wire added.
        if (kept.length === 0) delete hooks[event];
        else hooks[event] = kept;
        touched = true;
      }
      const owned = readOwned();
      const perms = settings["permissions"] as
        | Record<string, unknown>
        | undefined;
      if (perms && Array.isArray(perms["deny"]) && owned.deny.length > 0) {
        const denyList = perms["deny"] as unknown[];
        const kept = denyList.filter(
          (d) => !(typeof d === "string" && owned.deny.includes(d)),
        );
        if (kept.length !== denyList.length) {
          perms["deny"] = kept;
          touched = true;
        }
      }
      if (tidyPermissions(settings, owned)) touched = true;
      if (touched) {
        if (Object.keys(hooks).length === 0) delete settings["hooks"];
        else settings["hooks"] = hooks;
        fs.writeFileSync(sp, JSON.stringify(settings, null, 2) + "\n");
        changed.push(sp);
      }
    }
    for (const f of [
      hookPath(),
      sessionStartHookPath(),
      policySnapshotPath(),
      ownedSettingsPath(),
    ]) {
      if (fs.existsSync(f)) {
        fs.rmSync(f);
        changed.push(f);
      }
    }
    return {
      changed,
      detail: changed.length ? "herkos wiring removed" : "nothing to remove",
    };
  },

  verify(): VerifyResult {
    if (!fs.existsSync(hookPath())) {
      return {
        ok: false,
        detail: `hook missing at ${hookPath()} — run 'herkos init'`,
      };
    }
    const sp = settingsPath(detectConfigDir());
    if (!fs.existsSync(sp)) {
      return { ok: false, detail: `harness settings not found at ${sp}` };
    }
    const settings = JSON.parse(fs.readFileSync(sp, "utf8")) as Record<
      string,
      unknown
    >;
    const hooks = (settings["hooks"] ?? {}) as Record<
      string,
      SettingsHookEntry[]
    >;
    const ours = (hooks["PreToolUse"] ?? []).filter((e) => isOurs(e));
    if (ours.length === 0) {
      return {
        ok: false,
        state: "unwired",
        detail: `hook not registered in ${sp} — run 'herkos init'`,
      };
    }
    // An install from before every-tool matching registered two fixed matchers
    // (Bash, and four file tools): enforcing, but blind to Glob, NotebookEdit and
    // every tool-server tool. That is an older wiring, not a current one.
    if (!ours.some((e) => e.matcher === "*" || e.matcher === undefined)) {
      return {
        ok: false,
        state: "stale",
        detail: `hook registered for ${ours.map((e) => e.matcher).join(", ")} only — tool-server tools, Glob and NotebookEdit bypass it; run 'herkos init' to match every tool`,
      };
    }
    // Present is not current: a policy edited without re-running `init` leaves a
    // hook that enforces the OLD never-list, which is the honest thing to say.
    const installed = readInstalledStamp();
    const current = compile(loadEffectivePolicy());
    const want = stampOf(current);
    const notes: string[] = [
      "hook present and registered on PreToolUse for every tool",
    ];
    if (installed === null) {
      notes.push(
        "the installed hook carries no stamp (generated by an older herkos) — run 'herkos init' so drift can be detected",
      );
    } else if (installed !== want) {
      return {
        ok: false,
        state: "stale",
        detail: `enforcing an OLDER policy — the hook carries '${installed}' but the current policy compiles to '${want}'; run 'herkos init' to recompile`,
      };
    }
    // The deny rules are a second copy of the credential never-list in a file
    // the user also edits by hand; one deleted there is a hole the hook's stamp
    // cannot see.
    const perms = settings["permissions"] as { deny?: unknown } | undefined;
    const present = Array.isArray(perms?.deny) ? (perms.deny as unknown[]) : [];
    const expected = claudeDenyRules(current);
    const missing = expected.filter((r) => !present.includes(r));
    if (missing.length > 0) {
      return {
        ok: false,
        state: "stale",
        detail: `${missing.length} of ${expected.length} credential deny rule(s) missing from permissions.deny in ${sp}: ${missing.join(", ")} — run 'herkos init'`,
      };
    }
    if (expected.length > 0) {
      notes.push(
        `${expected.length} credential deny rule(s) present in permissions.deny`,
      );
    }
    notes.push(
      (hooks["SessionStart"] ?? []).some((e) => isOurs(e))
        ? "session-start proof registered"
        : "session-start proof NOT registered — run 'herkos init' to get the per-session line",
    );
    return { ok: true, state: "ok", detail: notes.join("; ") };
  },
};
