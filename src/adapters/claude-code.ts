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
import { EXTRACT_AWK } from "../extract.js";
import type {
  HarnessAdapter,
  DetectResult,
  WireResult,
  VerifyResult,
  RuleCoverage,
  LayerKind,
  ProbeContext,
  ProbeCommand,
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
  /** sandbox.credentials.files paths herkos added (always mode "deny"). */
  credentialFiles: string[];
  /** herkos created sandbox / sandbox.credentials / its files list — drop each once empty. */
  createdSandbox: boolean;
  createdCredentials: boolean;
  createdFiles: boolean;
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
      credentialFiles: Array.isArray(o.credentialFiles)
        ? o.credentialFiles.filter((d): d is string => typeof d === "string")
        : [],
      createdSandbox: o.createdSandbox === true,
      createdCredentials: o.createdCredentials === true,
      createdFiles: o.createdFiles === true,
    };
  } catch {
    return {
      deny: [],
      createdPermissions: false,
      createdDeny: false,
      credentialFiles: [],
      createdSandbox: false,
      createdCredentials: false,
      createdFiles: false,
    };
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
    for (const rule of r.denyRead.map(denyRuleFor)) {
      if (!out.includes(rule)) out.push(rule);
    }
  }
  return out;
}

/** One read-deny target as a Claude Code permission rule. */
function denyRuleFor(target: string): string {
  return `Read(${target.startsWith("/") && !target.startsWith("//") ? `/${target}` : target})`;
}

/**
 * The concrete credential paths a policy compiles to for the OS sandbox's own
 * credential list, `sandbox.credentials.files` with mode "deny". Its schema
 * takes a file or directory path — absolute or `~`-expanded — not a glob, so a
 * target ending in `/**` contributes its directory and any other glob is left
 * out. Globs are not lost: Claude Code merges `Read(...)` deny permission rules
 * into the sandbox's own read-deny list (stated in its settings schema as of
 * 2.1.268), so they reach the OS layer through the rules herkos already writes.
 * A relative target is left out too: here it would resolve against the settings
 * directory, not the project.
 */
export function claudeSandboxCredentialFiles(policy: CompiledPolicy): string[] {
  const out: string[] = [];
  for (const r of policy.rules) {
    for (const t of r.denyRead) {
      const dir = t.endsWith("/**") ? t.slice(0, -3) : t;
      if (!(dir.startsWith("~/") || dir.startsWith("/"))) continue;
      if (/[*?[\]{}]/.test(dir)) continue;
      const p = dir.startsWith("//") ? dir.slice(1) : dir;
      if (!out.includes(p)) out.push(p);
    }
  }
  return out;
}

/** The `path` of a sandbox credential entry, if it is one. */
function entryPath(x: unknown): string | undefined {
  const p = (x as { path?: unknown } | null)?.path;
  return typeof x === "object" && x !== null && typeof p === "string"
    ? p
    : undefined;
}

/** A credential entry herkos could have written: a path with mode "deny". */
function isDenyEntry(x: unknown): x is { path: string; mode: "deny" } {
  return (
    entryPath(x) !== undefined && (x as { mode?: unknown }).mode === "deny"
  );
}

/** Drop sandbox containers herkos created once they hold nothing. */
function tidySandbox(
  settings: Record<string, unknown>,
  owned: OwnedSettings,
): boolean {
  const sandbox = settings["sandbox"];
  if (typeof sandbox !== "object" || sandbox === null) return false;
  const sb = sandbox as Record<string, unknown>;
  let changed = false;
  const creds = sb["credentials"];
  if (typeof creds === "object" && creds !== null) {
    const c = creds as Record<string, unknown>;
    const files = c["files"];
    if (owned.createdFiles && Array.isArray(files) && files.length === 0) {
      delete c["files"];
      changed = true;
    }
    if (owned.createdCredentials && Object.keys(c).length === 0) {
      delete sb["credentials"];
      changed = true;
    }
  }
  if (owned.createdSandbox && Object.keys(sb).length === 0) {
    delete settings["sandbox"];
    changed = true;
  }
  return changed;
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

/** "a boolean" / "an array" / "null" — for messages about a wrong-shape value. */
function describeValue(v: unknown): string {
  if (Array.isArray(v)) return "an array";
  if (v === null) return "null";
  return `a ${typeof v}`;
}

/**
 * Read the harness settings and refuse anything herkos cannot merge into
 * safely: a file that is not valid JSON, a top level that is not an object, or
 * a `hooks`/`permissions`/`sandbox` that is not an object. Blindly casting the
 * latter crashed wire() mid-write — after the hook file was written but before
 * it was registered — leaving a stack trace and a half-applied install; this
 * gate runs BEFORE anything is written, so a refused init writes nothing.
 */
function readSettingsForWire(sp: string): {
  settings: Record<string, unknown>;
  existed: boolean;
} {
  if (!fs.existsSync(sp)) return { settings: {}, existed: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(sp, "utf8"));
  } catch (e) {
    throw new Error(
      `${sp} is not valid JSON (${String((e as Error).message)}) — fix or remove it, then re-run 'herkos init'`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(
      `${sp} holds ${describeValue(parsed)}, not a JSON object — fix or remove it, then re-run 'herkos init'`,
    );
  }
  const settings = parsed as Record<string, unknown>;
  for (const key of ["hooks", "permissions", "sandbox"]) {
    const v: unknown = settings[key];
    if (v === undefined) continue;
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      throw new Error(
        `your settings.json has '${key}' as ${describeValue(v)} — herkos cannot merge into that; fix or remove it, then re-run 'herkos init'`,
      );
    }
  }
  return { settings, existed: true };
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
 * - surfaces an OPEN rule's message without blocking: printed to stderr as it
 *   is collected, and on Claude Code also as a JSON systemMessage on stdout —
 *   stderr at exit 0 reaches only the debug log there, so the JSON line is the
 *   one channel that is both visible and non-blocking (D-005);
 * - fails OPEN but LOUD when it cannot parse its input (a security hook that
 *   hard-blocks on every malformed call would brick the session; one that
 *   silently allows would be worse — so it allows and announces). The same
 *   applies per-rule at grep time: a pattern grep cannot evaluate — the rule's
 *   own or its exclusion — turns that ONE rule off for the call, loudly, and
 *   the rest of the never-list stays
 *   enforced — never exit 2 on a grep error. Since D-008 the announcements
 *   ride the heard channel with the notices, and a degradation marks the
 *   session so every later call in it keeps saying it — a degradation seen
 *   once is a degradation the session forgets;
 * - supports --selftest so the wiring can prove itself end to end.
 */
export function generateHook(policy: CompiledPolicy): string {
  // One check per rule (not one merged regex) so a refusal can name its rule.
  // A block rule calls `enforce` (exit 2 on match); an open rule calls `notice`
  // (surface a message, never block). Both bodies take the subject as "$1" and
  // the kind as "$2", so the same baked lines serve every tool argument found.
  //   enforce <id> <description> <kind> <subject> <regex> <exclude> <message>
  //   notice  <id> <message>     <kind> <subject> <regex> <exclude>
  // <exclude> is the rule's notPaths alternation ("" for none): a subject it
  // matches — the committed .env templates — never fires the rule.
  const line = (rule: CompiledRule, re: string): string =>
    rule.disposition === "open"
      ? `  notice ${shQuote(rule.id)} ${shQuote(rule.message || rule.description)} "$2" "$1" ${shQuote(re)} ${shQuote(rule.notPathRegex)}`
      : `  enforce ${shQuote(rule.id)} ${shQuote(rule.description)} "$2" "$1" ${shQuote(re)} ${shQuote(rule.notPathRegex)} ${shQuote(rule.message)}`;
  const pathLine = (rule: CompiledRule): string =>
    rule.pathRegex === "" ? "" : line(rule, rule.pathRegex);

  // Open rules first, so a notice always surfaces before any block rule exits.
  const ordered = [...policy.rules].sort((a, b) =>
    a.disposition === b.disposition ? 0 : a.disposition === "open" ? -1 : 1,
  );
  // A command-shaped argument is checked against BOTH vocabularies: it may name
  // a credential file or be fetched code piped to a shell.
  const commandRules =
    ordered
      .flatMap((rule) => [
        pathLine(rule),
        ...rule.commandRegexes.map((re) => line(rule, re)),
      ])
      .filter((l) => l !== "")
      .join("\n") || "  :";
  const pathRules =
    ordered
      .map(pathLine)
      .filter((l) => l !== "")
      .join("\n") || "  :";

  const shList = (xs: readonly string[]): string => shQuote(xs.join(" "));

  // Session state (degradation stickiness, D-008) lives beside the log: the
  // hook writes machine-local state exactly when it writes a machine-local
  // log. A hook that must write nothing (a committed project hook, synthetic
  // runs, or the user turning the blocked-call log off) gets no state dir and
  // degrades to per-call announcements — loud, just not sticky.
  const stateDir =
    policy.logFile === ""
      ? ""
      : path.join(path.dirname(policy.logFile), "sessions");

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
EXTRACT_AWK=${shQuote(EXTRACT_AWK)}
LOG_FILE=${shQuote(policy.logFile)}
STATE_DIR=${shQuote(stateDir)}
LOG_MAX_BYTES=${LOG_MAX_BYTES}
TOOL=""
NOTICES=""
SESSION=""
LOSSY=0

# The registered command names its harness, so a block is attributed to it.
HARNESS=unknown
if [ "\${1:-}" = "--harness" ]; then
  if [ "$#" -ge 2 ]; then HARNESS=$2; shift 2; else shift; fi
fi

block() {
  flush_notices
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

# enforce ID DESCRIPTION KIND SUBJECT REGEX EXCLUDE MESSAGE — grep the subject
# against one compiled pattern, unless it matches EXCLUDE (the rule's own
# benign-spelling exclusions, "" for none), in which case the rule never fires.
# Match → block, naming the rule. No match → fall through. grep itself failing
# (bad regex, exit >= 2) degrades LOUDLY — on EITHER pattern: the rule's own
# or its exclusion, an unevaluable exclusion would otherwise flip verdicts
# silently (exit 2 reads as "no match", the rule fires as if the carve-out did
# not exist). That one rule is off for this call and the session keeps working;
# every other rule stays enforced. Never exit 2 because of a grep error, and
# never let one dump raw grep text into the session.
enforce() {
  [ -n "$5" ] || return 0
  if [ -n "$6" ]; then
    printf '%s' "$4" | grep -Eq -e "$6" 2>/dev/null
    xrc=$?
    if [ "$xrc" -eq 0 ]; then return 0; fi
    if [ "$xrc" -ge 2 ]; then
      degrade "rule $1 exclude pattern could not be evaluated (grep exit $xrc) — that rule is OFF for this call. Run 'herkos validate'."
      return 0
    fi
  fi
  printf '%s' "$4" | grep -Eq -e "$5"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_block "$1"
    _m="BLOCKED (herkos) rule $1 — $2. This $3 is on the never-list. To adjust: narrow the rule in $POLICY_FILE or disable it by id; 'herkos rules' lists the policy."
    [ -n "$7" ] && _m="$_m $7"
    block "$_m"
  fi
  if [ "$rc" -ge 2 ]; then
    degrade "rule $1 pattern could not be evaluated (grep exit $rc) — that rule is OFF for this call. Run 'herkos validate'."
  fi
}

# notice ID MESSAGE KIND SUBJECT REGEX EXCLUDE — an OPEN rule: surface the
# message on a match and let the call THROUGH. Never blocks, never changes the
# exit code, and a grep error just means no notice for this call. The line goes
# to stderr as it is collected, and is recorded for flush_notices — see there
# for why stderr alone is not the surface.
notice() {
  [ -n "$5" ] || return 0
  if [ -n "$6" ] && printf '%s' "$4" | grep -Eq -e "$6" 2>/dev/null; then return 0; fi
  if printf '%s' "$4" | grep -Eq -e "$5" 2>/dev/null; then
    printf 'herkos NOTICE (rule %s): %s\\n' "$1" "$2" >&2
    NOTICES="\${NOTICES:+$NOTICES | }herkos NOTICE (rule $1): $2"
  fi
  return 0
}

# degrade REASON — a call herkos could not fully check. The line goes to
# stderr as collected AND onto the heard channel with the notices: D-005's
# finding (stderr at exit 0 reaches nobody) applies to degradation lines
# exactly as it did to open-rule notices, and a degradation nobody sees is
# enforcement silently off. It also marks the session, D-008: a degradation
# announced once and never again is a degradation the session forgets, so the
# marker makes later calls in the same session keep announcing it. Best effort
# at every step — a marker that cannot be written degrades to per-call
# announcements, never to silence and never to blocking.
degrade() {
  printf 'herkos DEGRADED: %s\n' "$1" >&2
  NOTICES="\${NOTICES:+$NOTICES | }herkos DEGRADED: $1"
  if [ -n "$STATE_DIR" ] && [ -n "$SESSION" ]; then
    {
      mkdir -p "$STATE_DIR" 2>/dev/null
      printf '%s\n' "$1" > "$STATE_DIR/degraded-$SESSION" 2>/dev/null
      # Sessions are short-lived; one week of markers is plenty of memory.
      find "$STATE_DIR" -type f -mtime +7 -delete 2>/dev/null
    } || true
  fi
}

# flush_notices — put what herkos has to SAY on the harness's
# non-blocking, user-visible channel: open-rule notices and, alongside them
# since D-008, the DEGRADED and UNCOVERED lines. On Claude Code, stderr from a
# hook that exits 0 goes to the debug log only — the model never sees it and
# the user never opens it — so a JSON systemMessage on stdout is what makes
# these heard; the alternatives all break the rules' own contracts
# (permissionDecision deny and exit 2 block the call; allow bypasses the
# permission prompt). The model stays blind either way: stated, not hidden.
# Any other harness name (or none): stderr as collected, because only Claude
# Code's channel is verified — claiming another's would be a guarantee herkos
# cannot keep. Never changes the exit code.
flush_notices() {
  [ -n "$NOTICES" ] || return 0
  if [ "$HARNESS" = "claude-code" ]; then
    printf '{"systemMessage":"%s"}\\n' "$(json "$NOTICES")"
  fi
  return 0
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

command -v awk >/dev/null 2>&1 || {
  degrade "awk unavailable — never-list enforcement is OFF for this call."
  flush_notices
  exit 0
}

# One awk pass over the payload (see extract.ts): the tool name, every string
# under a command- or path-shaped key at any depth, the argument count, and E
# when the payload cannot be read. awk and grep are POSIX; nothing else is needed.
FIELDS=$(awk -v pkeys="$PATH_KEYS" -v ckeys="$COMMAND_KEYS" "$EXTRACT_AWK" 2>/dev/null)
AWK_RC=$?

TAB=$(printf '\\t')
NL='
'
TOOL=""
COMMAND_VALUES=""
PATH_VALUES=""
NARGS=0
PARSE_ERROR=""
while IFS= read -r line; do
  tag=\${line%%"$TAB"*}
  val=\${line#*"$TAB"}
  case "$tag" in
    T) [ -n "$TOOL" ] || TOOL=$val ;;
    S) [ -n "$SESSION" ] || SESSION=$val ;;
    C) COMMAND_VALUES="$COMMAND_VALUES$val$NL" ;;
    P) PATH_VALUES="$PATH_VALUES$val$NL" ;;
    N) NARGS=$val ;;
    E) PARSE_ERROR=$val ;;
    W) LOSSY=1 ;;
  esac
done <<HERKOS_FIELDS
$FIELDS
HERKOS_FIELDS
if [ "$AWK_RC" -ne 0 ] && [ -z "$PARSE_ERROR" ]; then
  PARSE_ERROR="the extractor exited $AWK_RC"
fi

# Sticky degradation, D-008: a session that already ran a call herkos could
# not check keeps saying so on every later call — announced BEFORE the rules
# run, so even a call that ends blocked carries the line. The marker is keyed
# to the session id, so a fresh session starts clean; this path only reads it,
# it never rewrites it (the reason it names is the first one recorded).
if [ -n "$STATE_DIR" ] && [ -n "$SESSION" ] && [ -f "$STATE_DIR/degraded-$SESSION" ]; then
  why=$(cat "$STATE_DIR/degraded-$SESSION" 2>/dev/null)
  dmsg="an earlier call in this session could not be checked (\${why:-unknown reason}) and was allowed with enforcement OFF for it — this call was checked normally"
  printf 'herkos DEGRADED: %s.\\n' "$dmsg" >&2
  NOTICES="\${NOTICES:+$NOTICES | }herkos DEGRADED: $dmsg"
fi

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

# Whatever was read has been checked, so a matched rule still blocked above.
# Past that, a payload that could not be read is announced, never assumed safe.
if [ -n "$PARSE_ERROR" ]; then
  degrade "could not read this tool call ($PARSE_ERROR) — enforcement is OFF for the rest of this call."
  flush_notices
  exit 0
fi

# The reader decoded a checked value lossily (D-008): non-ASCII as "?",
# control characters as spaces. What was decoded is still checked — an ASCII
# pattern sees every ASCII stretch intact — but a rule naming the replaced
# text would not match, and that is said rather than hidden. Not sticky and
# never enforcement-off: it is fidelity about one value, not a session state.
if [ "$LOSSY" = 1 ]; then
  dmsg="a checked value contained characters the reader cannot represent (non-ASCII shown as ?, some controls as spaces) — rules ran against the decoded text, so a rule naming such text would not match"
  printf 'herkos DEGRADED: %s.\\n' "$dmsg" >&2
  NOTICES="\${NOTICES:+$NOTICES | }herkos DEGRADED: $dmsg"
fi

# Honest coverage: a tool herkos does not know, whose arguments carry none of
# the names it reads, is UNCOVERED — it may touch anything, and herkos cannot
# see what. Say so; never assume it is safe. Known tools that take no path stay
# quiet, because an announcement on every call is how a guard gets muted. On
# the heard channel the line is said ONCE per session and tool (D-008), for
# the same noise reason; the stderr diagnostic stays on every call, and a
# hook with no state dir keeps UNCOVERED on stderr only.
if [ -z "$COMMAND_VALUES" ] && [ -z "$PATH_VALUES" ] && [ -n "$TOOL" ]; then
  case " $KNOWN_TOOLS " in
    *" $TOOL "*) ;;
    *)
      case "$NARGS" in
        ''|0) ;;
        *)
          umsg="tool $TOOL passed arguments herkos cannot read as a path or a command — the never-list was NOT checked for this call"
          printf 'herkos UNCOVERED: %s.\\n' "$umsg" >&2
          if [ -n "$STATE_DIR" ] && [ -n "$SESSION" ]; then
            ukey=$(printf '%s' "$TOOL" | tr -c 'A-Za-z0-9._-' '_')
            if [ ! -f "$STATE_DIR/uncovered-$SESSION-$ukey" ]; then
              NOTICES="\${NOTICES:+$NOTICES | }herkos UNCOVERED: $umsg"
              { mkdir -p "$STATE_DIR" 2>/dev/null; : > "$STATE_DIR/uncovered-$SESSION-$ukey" 2>/dev/null; } || true
            fi
          fi
          ;;
      esac
      ;;
  esac
fi
flush_notices
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
  hookScope: "every-tool",

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

    // 1. Read the settings and refuse a shape herkos cannot merge into —
    //    BEFORE anything is written, so a refused init is a clean no-op.
    const { settings, existed } = readSettingsForWire(sp);

    // 2. The generated hook, owned by herkos in its own directory.
    fs.mkdirSync(herkosDir(), { recursive: true });
    fs.writeFileSync(hookPath(), generateHook(policy), { mode: 0o755 });
    changed.push(hookPath());

    // 3. Wire it into settings.json (create the file if the harness has none yet).
    if (existed) {
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

    // 4. The session-start proof, and the policy snapshot it compares against.
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

    // 5. Credential reads as the harness's own permission deny rules.
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
      credentialFiles: [],
      createdSandbox: owned.createdSandbox,
      createdCredentials: owned.createdCredentials,
      createdFiles: owned.createdFiles,
    };
    permissions["deny"] = deny;
    settings["permissions"] = permissions;
    tidyPermissions(settings, nowOwned);

    // 6. Credential files into the OS sandbox's own credential list. Turning the
    //    sandbox on is the user's call: herkos writes the entries and never
    //    touches `sandbox.enabled`. The entries are inert while it is off and
    //    hold from the first command once it is on.
    const rawSandbox = settings["sandbox"];
    const hadSandbox = typeof rawSandbox === "object" && rawSandbox !== null;
    const sandbox = (hadSandbox ? rawSandbox : {}) as Record<string, unknown>;
    const rawCreds = sandbox["credentials"];
    const hadCreds = typeof rawCreds === "object" && rawCreds !== null;
    const creds = (hadCreds ? rawCreds : {}) as Record<string, unknown>;
    const hadFiles = Array.isArray(creds["files"]);
    const files = (hadFiles ? (creds["files"] as unknown[]) : []).filter(
      (f) => !(isDenyEntry(f) && owned.credentialFiles.includes(f.path)),
    );
    const credentialPaths = claudeSandboxCredentialFiles(policy);
    for (const p of credentialPaths) {
      // The user's own entry for a path wins, whatever its mode.
      if (files.some((f) => entryPath(f) === p)) continue;
      files.push({ path: p, mode: "deny" });
      nowOwned.credentialFiles.push(p);
    }
    nowOwned.createdSandbox = owned.createdSandbox || !hadSandbox;
    nowOwned.createdCredentials = owned.createdCredentials || !hadCreds;
    nowOwned.createdFiles = owned.createdFiles || !hadFiles;
    creds["files"] = files;
    sandbox["credentials"] = creds;
    settings["sandbox"] = sandbox;
    tidySandbox(settings, nowOwned);
    const sandboxOn = sandbox["enabled"] === true;

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
      detail: `hook generated (${policy.ruleCount} rules, stamp ${stampOf(policy)}) and registered on PreToolUse for every tool; ${claudeDenyRules(policy).length} credential read(s) added to permissions.deny; ${credentialPaths.length} credential path(s) in sandbox.credentials.files (${sandboxOn ? "OS sandbox on" : "the OS sandbox is OFF in these settings — herkos never turns it on; the entries take effect if you do"}); a session-start line reports enforcement each session. Takes effect for sessions started from now on.`,
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
      const sb = settings["sandbox"];
      const credsU =
        typeof sb === "object" && sb !== null
          ? (sb as Record<string, unknown>)["credentials"]
          : undefined;
      if (
        typeof credsU === "object" &&
        credsU !== null &&
        owned.credentialFiles.length > 0
      ) {
        const c = credsU as Record<string, unknown>;
        const list = c["files"];
        if (Array.isArray(list)) {
          const kept = list.filter(
            (f) => !(isDenyEntry(f) && owned.credentialFiles.includes(f.path)),
          );
          if (kept.length !== list.length) {
            c["files"] = kept;
            touched = true;
          }
        }
      }
      if (tidySandbox(settings, owned)) touched = true;
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

  liveProbeCommand(ctx: ProbeContext): ProbeCommand {
    // One non-interactive turn against the real installed hook. JSON output so
    // the report can read the model's own usage/cost; a USD budget is the hard
    // spend ceiling, and --dangerously-skip-permissions makes the run headless
    // WITHOUT relaxing herkos — the hook fires in that mode exactly as in any
    // other (that is the point of the hook). The child keeps the real config
    // and auth; only the working directory is the throwaway.
    return {
      bin: process.env.HERKOS_CLAUDE_BIN ?? "claude",
      args: [
        "-p",
        ctx.prompt,
        "--output-format",
        "json",
        "--max-budget-usd",
        ctx.budgetUsd.toFixed(2),
        "--dangerously-skip-permissions",
      ],
      env: { ...process.env },
      ceilingNote: `--max-budget-usd ${ctx.budgetUsd.toFixed(2)} plus a wall-clock timeout`,
    };
  },

  coverage(policy: CompiledPolicy): RuleCoverage[] {
    let deny: unknown[] = [];
    let credentialEntries: unknown[] = [];
    let sandboxOn = false;
    let hookRegistered = false;
    try {
      const s = JSON.parse(
        fs.readFileSync(settingsPath(detectConfigDir()), "utf8"),
      ) as {
        permissions?: { deny?: unknown };
        hooks?: { PreToolUse?: unknown };
        sandbox?: { enabled?: unknown; credentials?: { files?: unknown } };
      };
      const rawDeny = s.permissions?.deny;
      if (Array.isArray(rawDeny)) deny = rawDeny;
      const rawFiles = s.sandbox?.credentials?.files;
      if (Array.isArray(rawFiles)) credentialEntries = rawFiles;
      sandboxOn = s.sandbox?.enabled === true;
      hookRegistered = JSON.stringify(s.hooks?.PreToolUse ?? []).includes(
        hookPath(),
      );
    } catch {
      // No readable settings: nothing is wired.
    }
    const hookLive = hookRegistered && fs.existsSync(hookPath());
    return policy.rules.map((r) => {
      const layers: string[] = [];
      const kinds: LayerKind[] = [];
      if (r.disposition === "open") {
        // An open rule surfaces a message and lets the call through — advisory,
        // not a wall. Report it as such and never among the blocking layers.
        return {
          rule: r.id,
          layers: hookLive ? ["hook notice (advisory, does not block)"] : [],
          kinds: [],
        };
      }
      const targets = r.denyRead.map(denyRuleFor);
      const denyHeld =
        targets.length > 0 && targets.every((t) => deny.includes(t));
      const paths = claudeSandboxCredentialFiles({ ...policy, rules: [r] });
      const filesHeld =
        paths.length > 0 &&
        paths.every((p) => credentialEntries.some((f) => entryPath(f) === p));
      // Strongest first: the OS enforces the sandbox for every shell command
      // and its children; it only exists while the user has it switched on.
      if (sandboxOn && (denyHeld || filesHeld)) {
        layers.push("OS sandbox for shell commands");
        kinds.push("os-sandbox");
      }
      if (denyHeld) {
        layers.push("permission deny rules");
        kinds.push("permission-deny");
      }
      if (hookLive && (r.pathRegex !== "" || r.commandRegexes.length > 0)) {
        layers.push("hook on every tool");
        kinds.push("hook");
      }
      return { rule: r.id, layers, kinds };
    });
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
    const sb = settings["sandbox"] as
      | { enabled?: unknown; credentials?: { files?: unknown } }
      | undefined;
    const rawFiles = sb?.credentials?.files;
    const presentFiles = Array.isArray(rawFiles) ? rawFiles : [];
    const wantFiles = claudeSandboxCredentialFiles(current);
    const missingFiles = wantFiles.filter(
      (p) => !presentFiles.some((f) => entryPath(f) === p),
    );
    if (missingFiles.length > 0) {
      return {
        ok: false,
        state: "stale",
        detail: `${missingFiles.length} of ${wantFiles.length} credential path(s) missing from sandbox.credentials.files in ${sp}: ${missingFiles.join(", ")} — run 'herkos init'`,
      };
    }
    if (wantFiles.length > 0) {
      notes.push(
        sb?.enabled === true
          ? `OS sandbox on: ${wantFiles.length} credential path(s) denied, and the deny rules merged into its read-deny list`
          : `OS sandbox not enabled in ${sp} — herkos never turns it on, so credential reads rest on the deny rules and the hook (a project or managed setting may still enable it)`,
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
