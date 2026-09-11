/**
 * The policy model: what an agent must never do on this machine.
 *
 * Two rule classes in v0.1, both about removing the payoff of a hijacked agent:
 * - "credential-read": reading files that hold live secret values.
 * - "fetched-exec": piping just-downloaded content straight into a shell.
 *
 * The BASELINE below is the curated, high-confidence never-list every install
 * gets by default — generic conventions only (nothing machine-specific may ever
 * appear here). A user policy file extends it with their own paths and can
 * disable individual baseline rules by id; disabling is per-rule and explicit,
 * never "turn the guard off".
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { HERKOS_VERSION } from "./version.js";

/**
 * A rule's class is an OPEN label. `credential-read` and `fetched-exec` are the
 * two curated baseline classes; a user rule may name its own — `command-never`,
 * `outbound-data`, whatever describes it — so the refusal names the real class
 * instead of one of two that would lie. The label is display and grouping only;
 * it changes no matching. See D-003: the baseline stays curated and small; the
 * openness is for the user's own never-list.
 */
export type RuleClass = string;

/** The two curated baseline classes, named for reference. */
export const BASELINE_CLASSES = ["credential-read", "fetched-exec"] as const;

/**
 * What a matched rule does. `block` (the default, and every baseline rule)
 * refuses the call. `open` lets the call THROUGH but surfaces the rule's message
 * to the session — for approval-gated rules ("never push without asking") that a
 * hard block would be too blunt for, and that filing as a block would mislabel.
 * An open rule is advisory, not a wall; it is never a permission or an allow-list
 * (it grants nothing), so it stays inside the boundary.
 */
export type Disposition = "block" | "open";

export interface Rule {
  id: string;
  class: RuleClass;
  description: string;
  /** block (default) refuses the call; open lets it through and surfaces `message`. */
  disposition?: Disposition;
  /** A line shown to the session when the rule matches — appended on a block, the point of an open rule. */
  message?: string;
  /** Path fragments matched as substrings against file paths AND command text (credential-read). */
  paths?: string[];
  /** Extended regexes matched against command text (fetched-exec / command-shaped rules). */
  commandPatterns?: string[];
  /**
   * Command prefixes as argument tokens, program first (`["git", "push"]`).
   * A harness with a native prefix-rule layer enforces these directly — on
   * Codex that layer needs no trust step, unlike its hooks. Only a rule that
   * genuinely IS a prefix belongs here: a pipeline such as fetched code piped
   * to a shell cannot be one without forbidding the shell outright. When a
   * rule has prefixes but no `commandPatterns`, the hook's patterns are derived
   * from them, so every harness still enforces the rule.
   */
  commandPrefixes?: string[][];
  /**
   * Examples the rule must match — commands or paths, checked by `validate`
   * with the same evaluator the hook uses. A rule that stops matching its own
   * example is caught before it is wired, not after it silently fails.
   */
  match?: string[];
  /** Examples the rule must NOT match: the legitimate calls it must leave alone. */
  notMatch?: string[];
  /**
   * Concrete deny targets for OS-level filesystem-deny adapters (Codex permission
   * profiles). Home/absolute paths ("~/.ssh", "/etc/x") go in the filesystem
   * table; glob entries (containing "*", e.g. "**\/.env*") go under
   * :workspace_roots. Absent → this rule isn't expressible as a filesystem deny
   * (e.g. fetched-exec rules), and that adapter falls back to its hook.
   */
  codexDeny?: string[];
  /**
   * Concrete read-deny targets for harness-native filesystem layers that take
   * gitignore-style globs (Claude Code's permission deny rules and its OS
   * sandbox): home-anchored (`~/…/id_*`), absolute (`/etc/…`), or relative to
   * the session's working directory (`**\/.env`). Precise where precision is
   * cheap — a key-file glob rather than the whole directory — because a native
   * deny cannot be narrowed per call the way a user can narrow a hook rule.
   * Absent → derived from `codexDeny` (a directory target becomes `dir/**`).
   */
  denyRead?: string[];
}

export interface UserPolicy {
  /** Extra rules, same shape as baseline rules. */
  rules?: Rule[];
  /** Baseline rule ids to disable (per-rule, auditable). */
  disable?: string[];
  /** The blocked-call log (see blocklog.ts). On unless set to false. */
  log?: boolean;
}

export interface EffectivePolicy {
  rules: Rule[];
  disabled: string[];
  userPolicyPath: string;
  userPolicyLoaded: boolean;
  /** Is the blocked-call log on? Absent means on. */
  log?: boolean;
  /** The `log` value exactly as the user wrote it — validated, never trusted. */
  rawLog?: unknown;
}

/**
 * The baseline never-list. Curation bar: near-universally never-legitimate for
 * an agent session; a false positive in a default rule teaches users to disable
 * the guard, which is worse than no guard. Grow this list slowly.
 */
export const BASELINE: Rule[] = [
  {
    id: "ssh-private-keys",
    class: "credential-read",
    description: "SSH private keys",
    paths: [".ssh/id_"],
    codexDeny: ["~/.ssh"],
    // Key files only: known_hosts and the client config stay readable, which a
    // session debugging a git remote legitimately needs.
    denyRead: ["~/.ssh/id_*"],
  },
  {
    id: "cloud-credentials",
    class: "credential-read",
    description: "Cloud provider credential files (AWS, GCP, Azure)",
    paths: [
      ".aws/credentials",
      ".config/gcloud/",
      ".azure/accessTokens",
      ".azure/msal_token_cache",
    ],
    codexDeny: ["~/.aws/credentials", "~/.config/gcloud", "~/.azure"],
    denyRead: [
      "~/.aws/credentials",
      "~/.config/gcloud/**",
      "~/.azure/accessTokens*",
      "~/.azure/msal_token_cache*",
    ],
  },
  {
    id: "kube-config",
    class: "credential-read",
    description: "Kubernetes cluster credentials",
    paths: [".kube/config"],
    codexDeny: ["~/.kube/config"],
    denyRead: ["~/.kube/config"],
  },
  {
    id: "dotenv-files",
    class: "credential-read",
    description:
      "Environment files that conventionally hold secrets (.env and variants)",
    // Matched as path fragments: covers .env, .env.local, .env.production, etc.
    paths: ["/.env"],
    codexDeny: ["**/.env", "**/.env.*"],
    denyRead: ["**/.env", "**/.env.*"],
  },
  {
    id: "token-rc-files",
    class: "credential-read",
    description: "Per-user token files (.netrc, .npmrc, .pypirc)",
    paths: [".netrc", ".npmrc", ".pypirc"],
    codexDeny: ["~/.netrc", "~/.npmrc", "~/.pypirc"],
    denyRead: ["~/.netrc", "~/.npmrc", "~/.pypirc"],
  },
  {
    id: "gnupg-private",
    class: "credential-read",
    description: "GnuPG private keyring",
    paths: [".gnupg/private-keys"],
    codexDeny: ["~/.gnupg"],
    // The modern private-key directory and the legacy secret keyring; public
    // keyrings stay readable so signature verification keeps working.
    denyRead: ["~/.gnupg/private-keys-v1.d/**", "~/.gnupg/secring.gpg"],
  },
  {
    id: "docker-auth",
    class: "credential-read",
    description: "Docker registry auth file",
    paths: [".docker/config.json"],
    codexDeny: ["~/.docker/config.json"],
    denyRead: ["~/.docker/config.json"],
  },
  {
    id: "macos-keychain",
    class: "fetched-exec",
    description: "macOS keychain credential dumps (holds OS-level secrets)",
    commandPrefixes: [
      ["security", "dump-keychain"],
      ["security", "find-generic-password"],
      ["security", "find-internet-password"],
      ["security", "export"],
    ],
    commandPatterns: [
      "security[[:space:]]+(dump-keychain|find-generic-password|find-internet-password|export)",
    ],
  },
  {
    id: "curl-pipe-shell",
    class: "fetched-exec",
    description: "Piping downloaded content directly into a shell",
    commandPatterns: [
      "(curl|wget)[^|]*\\|[[:space:]]*(sudo([[:space:]]+-[[:alnum:]]+)*[[:space:]]+)?(env[[:space:]]+)?(ba|z|da)?sh([[:space:]]|$|[[:space:]]*-)",
      "eval[[:space:]]+.?\\$\\((curl|wget)",
      // Same intent, no pipe: process substitution, and the download handed
      // to a shell as a string. Found by the bypass corpus.
      "(^|[^[:alnum:]_.-])((ba|z|da)?sh|source|\\.)[[:space:]]+<\\([[:space:]]*(curl|wget)",
      "(^|[^[:alnum:]_.-])(ba|z|da)?sh[[:space:]]+-c[[:space:]]+[\"']?\\$\\([[:space:]]*(curl|wget)",
    ],
  },
];

/** The directory herkos owns: its policy, generated hooks and its log. */
export function herkosConfigDir(): string {
  return (
    process.env.HERKOS_CONFIG ?? path.join(os.homedir(), ".config", "herkos")
  );
}

export function userPolicyPath(): string {
  return path.join(herkosConfigDir(), "policy.json");
}

/** Beside the policy: the one file the hook writes during enforcement. */
export function blockLogFile(): string {
  return path.join(herkosConfigDir(), "blocked.log");
}

export function loadEffectivePolicy(): EffectivePolicy {
  const p = userPolicyPath();
  let user: UserPolicy = {};
  let loaded = false;
  if (fs.existsSync(p)) {
    try {
      user = JSON.parse(fs.readFileSync(p, "utf8")) as UserPolicy;
      loaded = true;
    } catch (e) {
      throw new Error(`user policy at ${p} is not valid JSON: ${String(e)}`);
    }
  }
  const disabled = user.disable ?? [];
  const rules = [
    ...BASELINE.filter((r) => !disabled.includes(r.id)),
    ...(user.rules ?? []),
  ];
  return {
    rules,
    disabled,
    userPolicyPath: p,
    userPolicyLoaded: loaded,
    log: user.log !== false,
    rawLog: user.log,
  };
}

// ---------------------------------------------------------------------------
// Validation — catches policy mistakes BEFORE they are compiled into a hook.
// The hook bakes patterns into a shell script and evaluates them with
// `grep -E`; a pattern that grep rejects would make that rule fail open in
// silence at run time (D-004: degrade loudly, never silently allow). So the
// validator asks grep itself, the same evaluator, while wiring is still
// refusable.
// ---------------------------------------------------------------------------

export interface ValidationResult {
  errors: string[];
  warnings: string[];
}

const KNOWN_RULE_KEYS: readonly string[] = [
  "id",
  "class",
  "description",
  "paths",
  "commandPatterns",
  "commandPrefixes",
  "disposition",
  "message",
  "match",
  "notMatch",
  "codexDeny",
  "denyRead",
];

/**
 * Test one extended regex the way the hook will evaluate it: `grep -E` with
 * the pattern as an argv element (never through a shell string). Exit 0 or 1
 * means the pattern compiled; exit 2 or a spawn error means it did not.
 */
function grepAccepts(pattern: string): { ok: boolean; detail: string } {
  const r = spawnSync("grep", ["-E", "-q", "-e", pattern], {
    input: "",
    encoding: "utf8",
    timeout: 5_000,
  });
  if (r.error) return { ok: false, detail: String(r.error) };
  if (r.status === 0 || r.status === 1) return { ok: true, detail: "" };
  return {
    ok: false,
    detail: (r.stderr ?? "").trim() || `grep exited ${r.status}`,
  };
}

function checkEntries(
  rid: string,
  key: "paths" | "commandPatterns" | "codexDeny" | "denyRead",
  entries: unknown,
  errors: string[],
): void {
  if (entries === undefined) return;
  if (!Array.isArray(entries)) {
    errors.push(`rule ${rid}: ${key} must be a list of strings`);
    return;
  }
  entries.forEach((entry, i) => {
    const n = i + 1;
    if (typeof entry !== "string" || entry.length === 0) {
      errors.push(
        `rule ${rid}: ${key} entry ${n} is not a non-empty string (skipped)`,
      );
      return;
    }
    if (/[\r\n]/.test(entry)) {
      errors.push(`rule ${rid}: ${key} entry ${n} contains a newline`);
      return;
    }
    // A native deny target is written inside the harness's own rule syntax,
    // `Read(<target>)`; a parenthesis would end or corrupt that rule.
    if ((key === "denyRead" || key === "codexDeny") && /[()]/.test(entry)) {
      errors.push(
        `rule ${rid}: ${key} entry ${n} contains "(" or ")" — it would break the harness's deny rule syntax`,
      );
      return;
    }
    // Path fragments are regex-escaped before they reach grep, so only raw
    // command patterns need the evaluator's own verdict.
    if (key === "commandPatterns") {
      const g = grepAccepts(entry);
      if (!g.ok) {
        errors.push(
          `rule ${rid}: pattern ${n} is not a valid extended regex: ${g.detail}`,
        );
      }
    }
  });
}

/** Each prefix must be a non-empty list of non-empty single-line tokens. */
function checkPrefixes(rid: string, prefixes: unknown, errors: string[]): void {
  if (prefixes === undefined) return;
  if (!Array.isArray(prefixes)) {
    errors.push(`rule ${rid}: commandPrefixes must be a list of token lists`);
    return;
  }
  prefixes.forEach((prefix, i) => {
    const n = i + 1;
    if (
      !Array.isArray(prefix) ||
      prefix.length === 0 ||
      !prefix.every(
        (t) => typeof t === "string" && t.length > 0 && !/[\r\n]/.test(t),
      )
    ) {
      errors.push(
        `rule ${rid}: commandPrefixes entry ${n} must be a non-empty list of single-line, non-empty strings (program first)`,
      );
    }
  });
}

/** Does this rule match the text, by the hook's own evaluator (`grep -E`)? */
function ruleMatches(rule: Rule, text: string): boolean {
  const paths = rule.paths ?? [];
  const regexes = [
    ...(paths.length > 0 ? [paths.map(escapeERE).join("|")] : []),
    ...((rule.commandPatterns ?? []).length > 0
      ? (rule.commandPatterns ?? [])
      : (rule.commandPrefixes ?? []).map(prefixRegex)),
  ];
  return regexes.some(
    (re) =>
      spawnSync("grep", ["-E", "-q", "-e", re], {
        input: text,
        encoding: "utf8",
        timeout: 5_000,
      }).status === 0,
  );
}

/** Run a rule's `match` / `notMatch` examples against the rule itself. */
function checkExamples(rid: string, rule: Rule, errors: string[]): void {
  const sets: [key: "match" | "notMatch", want: boolean][] = [
    ["match", true],
    ["notMatch", false],
  ];
  for (const [key, want] of sets) {
    const list: unknown = rule[key];
    if (list === undefined) continue;
    if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) {
      errors.push(`rule ${rid}: ${key} must be a list of strings`);
      continue;
    }
    list.forEach((example: string, i) => {
      if (ruleMatches(rule, example) === want) return;
      errors.push(
        want
          ? `rule ${rid}: match example ${i + 1} (${JSON.stringify(example)}) is not matched by the rule`
          : `rule ${rid}: notMatch example ${i + 1} (${JSON.stringify(example)}) is matched by the rule — that call would be refused`,
      );
    });
  }
}

/** Validate an effective policy: errors block wiring; warnings just inform. */
export function validatePolicy(policy: EffectivePolicy): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  policy.rules.forEach((raw, idx) => {
    if (typeof raw !== "object" || raw === null) {
      errors.push(`rule ${idx + 1}: not an object`);
      return;
    }
    const rule = raw as Rule;
    const rid =
      typeof rule.id === "string" && rule.id.length > 0
        ? rule.id
        : `#${idx + 1}`;
    if (rid.startsWith("#")) {
      errors.push(`rule ${rid}: missing or empty id`);
    } else {
      if (seen.has(rid)) errors.push(`rule ${rid}: duplicate id`);
      seen.add(rid);
    }
    if (
      typeof rule.class !== "string" ||
      !/^[a-z0-9][a-z0-9-]*$/i.test(rule.class)
    ) {
      errors.push(
        `rule ${rid}: class must be a simple label (letters, digits, hyphens); got ${JSON.stringify(rule.class)}`,
      );
    }
    if (
      rule.disposition !== undefined &&
      rule.disposition !== "block" &&
      rule.disposition !== "open"
    ) {
      errors.push(
        `rule ${rid}: disposition must be "block" or "open" (got ${JSON.stringify(rule.disposition)})`,
      );
    }
    if (rule.message !== undefined) {
      if (typeof rule.message !== "string" || rule.message.length === 0) {
        errors.push(`rule ${rid}: message must be a non-empty string`);
      } else if (/[\r\n]/.test(rule.message)) {
        errors.push(`rule ${rid}: message must be a single line`);
      }
    }
    if (rule.disposition === "open" && !rule.message && !rule.description) {
      errors.push(
        `rule ${rid}: an open rule needs a message (or a description) — it exists to say something`,
      );
    }
    const hasPaths = (rule.paths ?? []).length > 0;
    const hasCmds =
      (rule.commandPatterns ?? []).length > 0 ||
      (rule.commandPrefixes ?? []).length > 0;
    if (!hasPaths && !hasCmds) {
      errors.push(
        `rule ${rid}: has neither paths nor commandPatterns nor commandPrefixes`,
      );
    }
    checkPrefixes(rid, rule.commandPrefixes, errors);
    const beforeMatchers = errors.length;
    checkEntries(rid, "paths", rule.paths, errors);
    checkEntries(rid, "commandPatterns", rule.commandPatterns, errors);
    checkEntries(rid, "codexDeny", rule.codexDeny, errors);
    checkEntries(rid, "denyRead", rule.denyRead, errors);
    // Examples only mean something once the rule's own matchers are valid.
    if (errors.length === beforeMatchers) checkExamples(rid, rule, errors);
    // Unknown keys only matter for user rules — the baseline is ours.
    if (!BASELINE.some((b) => b === raw)) {
      for (const k of Object.keys(raw)) {
        if (!KNOWN_RULE_KEYS.includes(k)) {
          warnings.push(`rule ${rid}: unknown key "${k}" is ignored`);
        }
      }
    }
  });
  for (const d of policy.disabled) {
    if (!BASELINE.some((b) => b.id === d)) {
      warnings.push(`disable: "${d}" is not a baseline rule id (no effect)`);
    }
  }
  if (policy.rawLog !== undefined && typeof policy.rawLog !== "boolean") {
    errors.push(
      `log must be true or false (got ${JSON.stringify(policy.rawLog)}) — it switches the blocked-call log`,
    );
  }
  return { errors, warnings };
}

/**
 * Load and validate in one step: throws (message lists every error, one per
 * line) when the policy must not be compiled into a hook.
 */
export function loadValidatedPolicy(): EffectivePolicy {
  const policy = loadEffectivePolicy();
  const { errors } = validatePolicy(policy);
  if (errors.length > 0) {
    throw new Error(
      [`policy has ${errors.length} error(s):`, ...errors].join("\n"),
    );
  }
  return policy;
}

/** One rule's compiled matchers — the hook names the rule that fired. */
export interface CompiledRule {
  id: string;
  class: RuleClass;
  description: string;
  /** block refuses; open lets the call through with a surfaced message. */
  disposition: Disposition;
  /** The line surfaced to the session on a match ("" if none). */
  message: string;
  /** POSIX extended regex alternation of this rule's escaped path fragments ("" if none). */
  pathRegex: string;
  /** This rule's extended regexes for command text. */
  commandRegexes: string[];
  /** Argument-token prefixes for native prefix-rule layers (Codex execpolicy). */
  commandPrefixes: string[][];
  /** Gitignore-style read-deny targets for harness-native layers (see denyReadTargets). */
  denyRead: string[];
}

/** The compiled matchers a hook needs: one path-fragment regex + command regexes. */
export interface CompiledPolicy {
  /** POSIX extended regex alternation of escaped path fragments ("" if none). */
  pathRegex: string;
  /** POSIX extended regexes for command-shaped rules. */
  commandRegexes: string[];
  ruleCount: number;
  /** Per-rule matchers — refusals name the rule; the hook is generated from these. */
  rules: CompiledRule[];
  /** Where the user's policy lives — baked into refusal messages. */
  userPolicyPath: string;
  /** Fingerprint of the compiled rules — drift detection, see policyFingerprint. */
  hash: string;
  /** The herkos version that compiled this policy. */
  version: string;
  /** The rule classes present, in first-seen order — named when nothing is wired. */
  classes: RuleClass[];
  /** Where the hook appends one line per block; "" when the log is off. */
  logFile: string;
}

/**
 * A short, stable fingerprint of the compiled never-list, baked into every
 * generated hook. It lets `status` and the session-start line separate "the
 * hook is current" from "the policy changed since this hook was installed" —
 * the silent-drift failure that costs everything (a harness upgrade, a hand
 * edit, a policy edited without re-running `init`).
 *
 * It covers exactly what the hook enforces — rule id, class, description and
 * matchers — so reformatting the policy FILE without changing a rule correctly
 * reports no drift, and a changed matcher always does. Not a tamper defence:
 * a same-user hash has no trust anchor, and anyone who can edit the hook can
 * edit the stamp.
 */
export function policyFingerprint(rules: CompiledRule[]): string {
  const canonical = JSON.stringify(
    rules.map((r) => [
      r.id,
      r.class,
      r.description,
      r.disposition,
      r.message,
      r.pathRegex,
      r.commandRegexes,
      r.commandPrefixes,
      r.denyRead,
    ]),
  );
  return crypto
    .createHash("sha256")
    .update(canonical)
    .digest("hex")
    .slice(0, 12);
}

// Escape a literal path fragment for use inside a POSIX extended regex.
function escapeERE(s: string): string {
  return s.replace(/[.[\]()*+?{}|^$\\]/g, "\\$&");
}

export interface CodexDeny {
  /** Home/absolute path deny entries → [permissions.<p>.filesystem]. */
  paths: string[];
  /** Glob deny entries → [permissions.<p>.filesystem.":workspace_roots"]. */
  globs: string[];
  /** Rules that could NOT be expressed as a filesystem deny (fetched-exec) — the Codex adapter covers these via its hook. */
  fetchedExecRules: Rule[];
}

/** Split the effective policy into Codex's filesystem-deny targets + the rules it can't express that way. */
export function collectCodexDeny(policy: EffectivePolicy): CodexDeny {
  const paths: string[] = [];
  const globs: string[] = [];
  const fetchedExecRules: Rule[] = [];
  for (const r of policy.rules) {
    if (r.codexDeny && r.codexDeny.length) {
      for (const d of r.codexDeny) (d.includes("*") ? globs : paths).push(d);
    } else if (r.class === "fetched-exec") {
      fetchedExecRules.push(r);
    }
  }
  return { paths, globs, fetchedExecRules };
}

/**
 * The read-deny targets one rule contributes to a harness's native filesystem
 * layers. An explicit `denyRead` wins. Otherwise the rule's `codexDeny` targets
 * are reused: a glob stays as written, and a home or absolute target — which may
 * name a file or a directory, and cannot be told apart without touching the
 * disk — contributes both itself and everything beneath it.
 */
export function denyReadTargets(rule: Rule): string[] {
  const strings = (xs: unknown): string[] =>
    Array.isArray(xs)
      ? xs.filter((x): x is string => typeof x === "string" && x.length > 0)
      : [];
  const explicit = strings(rule.denyRead);
  if (explicit.length > 0) return explicit;
  const out: string[] = [];
  for (const d of strings(rule.codexDeny)) {
    if (d.includes("*")) out.push(d);
    else out.push(d, `${d.replace(/\/+$/, "")}/**`);
  }
  return out;
}

/**
 * The hook's pattern for a rule that is only a prefix: the tokens in order,
 * separated by whitespace, starting where a program name can start (line start,
 * or after a separator or a path slash — so `/usr/bin/x` counts) and ending at
 * a token boundary. Lets one declared prefix be enforced by the hook on every
 * harness and by a native prefix layer where one exists.
 */
export function prefixRegex(tokens: string[]): string {
  return `(^|[^[:alnum:]_.-])${tokens.map(escapeERE).join("[[:space:]]+")}([[:space:]]|$)`;
}

export function compile(policy: EffectivePolicy): CompiledPolicy {
  const rules: CompiledRule[] = policy.rules.map((r) => ({
    id: r.id,
    class: r.class,
    description: r.description,
    disposition: r.disposition === "open" ? "open" : "block",
    message: r.message ?? "",
    pathRegex: (r.paths ?? []).map(escapeERE).join("|"),
    commandRegexes:
      (r.commandPatterns ?? []).length > 0
        ? [...(r.commandPatterns ?? [])]
        : (r.commandPrefixes ?? []).map(prefixRegex),
    commandPrefixes: (r.commandPrefixes ?? []).map((p) => [...p]),
    denyRead: denyReadTargets(r),
  }));
  const classes: RuleClass[] = [];
  for (const r of rules) if (!classes.includes(r.class)) classes.push(r.class);
  return {
    pathRegex: rules
      .map((r) => r.pathRegex)
      .filter((re) => re !== "")
      .join("|"),
    commandRegexes: rules.flatMap((r) => r.commandRegexes),
    ruleCount: policy.rules.length,
    rules,
    userPolicyPath: policy.userPolicyPath,
    hash: policyFingerprint(rules),
    version: HERKOS_VERSION,
    classes,
    logFile: policy.log === false ? "" : blockLogFile(),
  };
}
