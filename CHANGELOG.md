# herkos

## 0.4.2

### Patch Changes

- f0f823a: A command containing a multi-byte character (an em dash, an accented letter, an emoji) no longer turns enforcement off; the hook now reads the payload as bytes, so every value passes through unchanged. Regenerate with `herkos init` / `herkos project init`.

## 0.4.1

### Patch Changes

- 95112fc: Re-running `herkos init` over an install from an earlier release no longer registers the hook twice or breaks Codex's config. Registration is recognised in every path spelling, and a rewritten Codex `config.toml` no longer gains a duplicate herkos table. `wire` and `unwire` remove only herkos's own commands; a user command in the same entry stays.

## 0.4.0

### Minor Changes

- 00281da: Hardening pass on the generated hook and project layer; regenerate with `herkos init` / `herkos project init`, every hook changes. Calls with arguments but nothing readable now announce `herkos UNCOVERED`, wrapped commands are checked, and `--selftest` verifies every baked rule against its examples. `herkos.json` may set `"logFile"` to log refusals as JSON lines beside the hook; off by default.
- 0992c2a: Prefix rules now catch shell punctuation after a forbidden spelling, so `sh migrate-v2-reset.sh; echo done` no longer passes; a name that merely shares the prefix still passes. Enforcement degradations are announced to you and repeat for the session, and approximately decoded text is announced while still being checked.
- 236235f: Open-rule notices now reach you as a system message on Claude Code instead of only stderr, and the agent never sees them. Multi-line values are checked whole, so a forbidden spelling can no longer be split across lines. A missing project hook file no longer blocks every call; re-run `herkos project init` to pick this up.

### Patch Changes

- 9374143: Security: a rule's `notPaths` exclusion now removes only the benign spellings it matches and re-tests the rule on what remains, so `cat app/.env app/.env.example` is refused while commands naming only templates still pass. `herkos check` exercises the mixed command on every run.
- 37fe589: A block rule whose exclusion regex cannot be evaluated no longer changes the verdict silently: that rule is off for the call, named in an announcement that sticks for the session. `validate` also warns on duplicate prefixes, and the schema docs state that patterns are single-line.
- 7dc45c9: `herkos check` no longer reports success for a rule that runs with enforcement off; a pattern or exclusion grep cannot evaluate now fails the selftest, naming the rule and which of the two is at fault. Uncovered-tool session markers now expire like degradation markers.
- 9374143: `herkos init` now checks the full shape of Claude Code settings and Codex's `hooks.json` before writing, so a malformed file is refused up front with one line instead of crashing mid-write and leaving a half-applied install. `uninstall` no longer reports success over an unreadable Codex `hooks.json`; one-line failures now go to stderr.

## 0.3.0

### Minor Changes

- 3f8d360: New `herkos project`: a repo commits a `herkos.json` declaring rules its contributors must never take, and `herkos project init` compiles it into a self-contained hook at `.claude/hooks/herkos-project.sh`. Commit `.claude/` and every clone is guarded, even without herkos installed. A repo policy can only add refusals; `herkos project check` fails CI on drift; Claude Code only.

## 0.2.0

### Minor Changes

- 1b05f3d: Every refusal now appends one JSON line to `blocked.log` beside the policy file: time, harness, tool, rule and working directory, never the command text. `herkos status` shows per-rule counts and the most recent blocks. On by default (`"log": false` disables it); an unwritable log never turns a block into an allow.
- bf9b434: `herkos check` now runs a bypass corpus: each baseline rule attacked by other spellings (a glob, a `cd` then a relative read, a symlink, fetched code through `sudo`), plus benign calls that must pass. It reports a verdict per layer, credits native layers only where they are wired, and names each case nothing holds as UNGUARDED.
- ca10a8d: Credential reads are now also compiled into Claude Code's `permissions.deny` as `Read(...)` entries, generated from the same policy as the hook so the two cannot drift. Rules gain an optional `denyRead` list of gitignore-style targets. herkos records the entries it adds, never touches an identical one you already had, and removes exactly its own on `uninstall`.
- 4c68a89: Claude Code: credential paths are now also compiled into the OS sandbox's credential list (`sandbox.credentials.files`, mode `deny`), enforced for every shell command once the sandbox is on. herkos never switches the sandbox on; the entries are inert while it is off. herkos records its entries and removes exactly its own on `uninstall`.
- 8dda68b: Codex: genuine prefix rules now also compile into Codex's own execpolicy as `forbidden` prefix rules, loaded at startup with no trust step. Rules gain an optional `commandPrefixes` list; hook patterns derive from it, so every harness still enforces the rule. Codex validates the generated file before installing; `status` names which layer holds each rule.
- 63b5c99: The `dotenv-files` rule no longer refuses committed templates like `.env.example`; rules gain a `notPaths` exclusion list, and a secret beside a template in one command still blocks. The harness-native deny layers now enumerate the conventional variants, so an unconventional secret like `.env.standby` is held only by the hook there.
- 77c4c86: The Claude Code hook now checks every tool through one `*` matcher, reading path- and command-shaped argument names at any depth, so `Glob`, `NotebookEdit`, `PowerShell` and MCP tools no longer bypass the never-list. A tool whose arguments carry no readable names is announced as `herkos UNCOVERED`; `status` reports older installs as STALE.
- 133bc3a: New `herkos discover`: names credential-shaped files on this machine that are not on your never-list (GitHub CLI, PostgreSQL, cloud CLIs, package registries and more) and offers to add a rule for each. Paths only; contents are never read. Findings go only into your user policy, never a tracked file.
- 7916a06: The enforcement hook no longer needs `jq`: it reads the payload with POSIX `awk`, so machines without jq enforce instead of silently doing nothing. A payload that cannot be read is announced as `herkos DEGRADED` after whatever was readable has been checked.
- d40c257: New opt-in `herkos probe`: runs one real headless agent session per harness against your wiring and reads the transcript to confirm a block actually fires. Both cases are safe by construction; a leaked sentinel fails the probe. It spends real tokens, so it requires explicit confirmation and a `--budget-usd` ceiling (default 0.50).
- 43c8b4f: Rules can now carry their own class label and a message, and a rule can be advisory: `disposition: "open"` lets a matched call through and surfaces the rule's message as `herkos NOTICE`, never blocking and never granting anything. `block` stays the default. `validate` requires an open rule to carry a message.
- ba45bbd: herkos now says at the start of every session whether it is actually enforcing: enforced with a rule count, NOT wired naming what goes unenforced, DRIFT (the hook was replaced), or enforced-but-stale. Every generated hook carries a stamp readable with `sh hook --stamp`, and `status` reports a wired-but-stale harness as STALE.

### Patch Changes

- 7881244: Security: bump vitest 2.1.8 to 2.1.9, clearing an RCE advisory in the Vitest API server (GHSA-9crc-q9x8-hgqq; vite transitively to 5.4.21). Remaining advisories require a semver-major bump.
- 57d78c7: Codex: `default_permissions = "herkos"` is now written in the root section of `config.toml`; it used to be appended after your tables, where TOML scoped it to the last table, so the deny profile was never selected and Codex refused to start. Stale managed blocks are collapsed, and markers now match again.
- 3fe4e0d: `herkos uninstall` no longer leaves an empty hooks skeleton in Codex's `hooks.json`: emptied keys and wrappers are dropped, a herkos-only file is removed, and foreign entries survive untouched. Each adapter keeps its one pre-herkos backup and leaves it in place on uninstall.
- 8f5cbd9: A corrupt `~/.config/herkos/policy.json` no longer crashes herkos; every command loads the policy through one gate that prints a one-line diagnosis and exits 1.
- f296cbd: `herkos discover --list` now does what it documents: prints the findings and the exact `--add` command without entering the per-candidate prompt.
- 22775fb: A shell command whose text names a credential path (`rg '.aws/credentials' .`) is refused by the hook; this trade-off is now documented in the README, and `herkos check` reports it as a known refusal rather than a false alarm.
- e4945a7: package.json now ships repository, homepage and bugs links; the npm page gains a Repository link.
- 8aaf8f4: A tool call whose `tool_input` is present but not an object is now announced as `herkos DEGRADED` instead of passing unchecked with no output.
- 57d78c7: Security: a rule pattern containing a single quote was pasted unescaped into the generated hook, turning the script into a shell syntax error that blocked every tool call; an invalid regex silently disabled the rule. Validation rejects both up front, every baked value is shell-quoted, and a run-time grep error degrades that rule with a DEGRADED line.
- 92225f1: `herkos probe` refuses a non-numeric, empty, or zero/negative `--budget-usd` or `--timeout` up front with a one-line diagnosis; a NaN value used to silently remove the spend ceiling you set.
- cdbde7f: `herkos probe` reports a harness binary that cannot be run as its own `unavailable` outcome, not "inconclusive"; only a real timeout counts as a ceiling hit.
- 57d78c7: `herkos check` honours a baseline rule disabled by id: the case that exercises it now expects the call to pass, so a sanctioned per-rule disable no longer turns `check` red.
- 25a8c97: The `macos-keychain` rule is now classed `credential-read`, so refusals group it correctly (matching unchanged); `validate` refuses a `:` in a deny target and a multi-line `id` or `description`.
- 2cc4683: `herkos init` now refuses a Claude Code `settings.json` it cannot merge into, before writing anything. Invalid JSON, a non-object top level, or a non-object `hooks`, `permissions` or `sandbox` prints one line naming the problem, exits 1, and leaves no half-applied install.

## 0.1.0

### Minor Changes

- Initial release: declare a never-list once and compile it into each harness's native enforcement; a PreToolUse hook for Claude Code and a permission-profile adapter for Codex, with a self-check that proves the wiring holds.
