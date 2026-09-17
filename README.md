# herkos

<div align="center">
  <img src="https://raw.githubusercontent.com/fleetorders/herkos/main/media/herkos-logo.png" width="520" alt="herkos — an interlocked wall of shields over a line an agent's forbidden actions cannot cross">
  <p>
    <a href="https://www.npmjs.com/package/herkos"><img src="https://img.shields.io/npm/v/herkos.svg?label=npm&color=cb3837" alt="npm version"></a>
    <a href="https://github.com/fleetorders/herkos/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/fleetorders/herkos/ci.yml?branch=main&label=CI" alt="CI"></a>
    <a href="https://github.com/fleetorders/herkos/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license"></a>
  </p>
</div>

_ἕρκος — the defensive rampart._

**Your never-list, enforced everywhere.** You declare a short list of things an
agent must never do on your machine — read your credentials, pipe fetched code
into a shell — and herkos compiles that one policy into every agent harness you
have installed, and enforces it in every mode, including headless and
bypass/skip-permissions runs.

```sh
npx herkos init      # detect installed harnesses, wire the policy into each
npx herkos check     # prove the never-list is enforced
npx herkos validate  # check the policy file for errors before wiring
npx herkos status    # what's protected, and with which rules
npx herkos discover  # credential files on this machine not yet on the list
```

## What it blocks (the default-on baseline)

Out of the box, before any configuration, herkos blocks the near-universal
never-list:

- **Credential reads** — SSH private keys, cloud credentials (AWS/GCP/Azure),
  Kubernetes config, `.env`-class files, `.netrc`/`.npmrc`/`.pypirc`, the GnuPG
  private keyring, Docker auth, and macOS keychain dumps. The committed
  placeholder templates — `.env.example` and friends — are not blocked: they
  hold no secrets by convention, and refusing everyday reads of them is the
  kind of false alarm that gets a guard switched off.
- **Fetched-code execution** — piping downloaded content straight into a shell
  (`curl … | sh`, `eval "$(curl …)"`).

These are curated to be near-zero false alarm — the kind of thing no agent
session should ever legitimately do. You extend them with your own rules in
`~/.config/herkos/policy.json`, and you can disable any baseline rule by id
(per-rule and explicit, never "turn the guard off").

## Honest scope — coverage differs by harness

herkos is **harness-agnostic at the policy layer** (one never-list) but delivers
enforcement through each harness's own extension point, so how much it can
enforce depends on what the harness exposes:

- **Claude Code — full enforcement.** herkos installs a small, self-contained (POSIX `sh`, `awk` and `grep`, nothing else)
  shell hook on `PreToolUse` that blocks both rule classes on every tool call, in
  every mode (including headless / skip-permissions). The hook matches **every
  tool**, including tool-server (MCP) tools you add later, and reads arguments by
  name — `file_path`, `path`, `paths`, `notebook_path`, `command`, `args` and
  their common spellings, at any depth. A tool it does not know whose arguments
  carry none of those names is announced as `herkos UNCOVERED` for that call,
  never assumed safe — and so is a call from a path- or command-bearing tool
  (Bash, Read, Write, the edit tools) that yields nothing readable: that is the
  harness renaming its argument keys, not safety. Tools whose arguments are
  never paths or commands (a to-do list, a search) stay quiet. Search
  patterns, URLs and free text (an edit's new
  content, a prompt) are deliberately not read as paths: documentation that
  names a credential file is not an attempt to read it.
- **Codex CLI — credential reads OS-enforced; fetched-code via a hook you trust
  once.** herkos compiles the credential never-list into a Codex permission
  profile whose filesystem `deny` entries are enforced by the OS sandbox
  (Seatbelt/Landlock) — verified: a read of a denied path returns `Operation not
permitted`. This half is seamless and arguably stronger than a hook. For
  fetched-code, herkos installs the same shell hook into Codex's `PreToolUse`, but
  non-managed Codex hooks require a one-time trust step — **run `/hooks` in Codex
  once** to activate fetched-code blocking (credential denies are live
  immediately). Requires Codex ≥ 0.146. Command rules that are genuinely
  prefixes — the keychain dumps — are also compiled into Codex's own execpolicy
  as `forbidden` rules, which load at startup with **no trust step**. Codex
  checks the generated file before herkos installs it; a file it refuses
  installs nothing. The hook still covers what a prefix rule cannot see, such
  as a program called by its full path.

`herkos status` names, per harness, which layer holds each rule, and lists any
rule no layer holds as **NOT enforced here**.

On Claude Code the credential rules are also written into the harness's **own
permission deny rules** (`permissions.deny` in its settings), generated from the
same policy so the two layers cannot disagree. A deny rule holds in every mode,
blocks through a symlink as well as its target, and covers the file commands the
harness recognises inside Bash; the hook covers what deny rules miss (a shell
wrapper, a program called by its full path). Targets are precise where that is
cheap — the SSH `id_*` key files, not the whole directory, so `known_hosts` and
the client config stay readable. herkos records which entries it added, never
claims an identical entry you already had, and `uninstall` removes exactly its
own. Command-shaped rules never become deny rules: denying a command prefix
would refuse every legitimate use of that program.

If you run Claude Code with its **OS sandbox** on, the credential paths are also
in the sandbox's own credential list (`sandbox.credentials.files`, mode `deny`),
enforced by the operating system for every shell command and its child
processes. herkos never switches the sandbox on: when it is off, the entries are
inert and `status` says the credential rules rest on the deny rules and the
hook. That list takes paths, not globs; a glob such as the SSH key-file pattern
still reaches the sandbox, because Claude Code merges `Read(…)` deny rules into
the sandbox's read-deny list (per its settings schema, as of 2.1.268).

Adding a harness is adding an adapter, not redesigning — the policy never changes.

## It tells you every session whether it is actually on

The failure that costs everything is silent absence: a harness upgrade, a
hand-edited settings file or a policy you edited and never recompiled leaves you
believing you are guarded while nothing is. So herkos does not wait to be asked.
It registers a second, tiny hook on session start that prints one line before
the first tool call:

```
herkos: enforced on Claude Code — 9 rule(s) (credential-read, fetched-exec) checked on every tool call, in every mode.
herkos: NOT wired on Claude Code — the enforcement hook is missing at …; nothing on the never-list is blocked (credential-read, fetched-exec). Run 'herkos init'.
herkos: enforced on Claude Code with 9 rule(s), BUT …/policy.json changed since 'herkos init' — the hook still carries the old rules. Run 'herkos init' to recompile.
```

Every generated hook carries a **stamp** — the herkos version, a fingerprint of
the compiled rules, and the rule count — so `herkos status` can tell a current
hook from one enforcing an older policy, and report the difference instead of a
bare "protected". The stamp is drift detection, not tamper resistance: anyone
who can edit the hook can edit the stamp.

## A record of what it refused

Every block appends one line to `~/.config/herkos/blocked.log` — time, harness,
tool, rule id and working directory, and **never the command text**, which can
itself carry a secret. `herkos status` turns it into per-rule counts and the five
most recent blocks, so you can see that the guard fires at all, and spot a rule
firing on legitimate work before it trains you to switch the guard off. The log
is on by default; set `"log": false` in the policy to turn it off. Writing it is
best effort: a log that cannot be written never turns a block into an allow. It
rotates past 1 MiB, and `uninstall` leaves it in place with your policy.

## Removing it

`herkos uninstall` removes exactly what `init` added — the hook and its registration, the deny rules and sandbox entries, the Codex permission profile and execpolicy file — and leaves your policy and the blocked-call log in place. Each adapter also leaves the one pre-herkos backup it took before first editing a config file (`settings.json.herkos-bak`, `config.toml.herkos-bak`, `hooks.json.herkos-bak`): it is your copy of the file as it was before herkos touched it, never overwritten since, and removing it at uninstall would destroy the recovery path exactly when you might want it. Delete the backups yourself once you are satisfied.

## Proof against other spellings

A PASS that only shows the script runs proves little. `herkos check` also runs a
**bypass corpus**: each baseline rule attacked by other spellings — a glob in
place of a file name, a `cd` then a relative read, a symlink, a path built at run
time, a vendor CLI reading the file itself, fetched code through `sudo` or
process substitution — plus benign calls that must never be refused. For every
case it measures the hook's verdict, credits the native layers (deny rules, OS
sandbox, prefix rules) only where they are wired on your machine, and names each
case nothing wired holds as **UNGUARDED**. Two gaps are recorded rather than
papered over, because one text pattern cannot tell them from everyday use:
downloading a script to a file and then running it, and piping a download to an
interpreter.

One class of refusal is **documented rather than fixed**: a shell command whose
_text_ names a credential path. `rg '.aws/credentials' .`, documentation that
mentions `~/.ssh/id_`, an echo of such a label — all refused, because the hook
matches Bash command text against the never-list's path fragments (that is also
how `cat ~/.ssh/id_rsa` is caught) and text cannot reveal intent: the same
string is a search term in one command and a file read in the next. The file
tools' search arguments are exempt by name — a `Grep` pattern is free text —
but inside a shell there is no such signal, and refusing is the safe side. The
corpus carries this as a known-refusal case, so the behavior stays pinned and
named, never silent.

Your own rules can carry examples, which `validate` runs with the hook's own
evaluator before anything is wired — and the generated hook re-checks the same
examples itself: `--selftest` (run by `herkos check`) fails if a baked rule no
longer behaves as its examples say:

```json
{
  "id": "no-force-push",
  "class": "fetched-exec",
  "description": "Force-pushing over shared history",
  "commandPrefixes": [["git", "push", "--force"]],
  "match": ["git push --force origin main"],
  "notMatch": ["git push origin main", "git push --force-with-lease"]
}
```

One semantics note on `commandPrefixes`, because the name under-sells what the
hook does: each spelling compiles to a bounded **token** match, not an anchored
prefix. It fires wherever the tokens stand as whole shell tokens in the line —
`bin/deploy.sh` also catches `sh bin/deploy.sh` and `./bin/deploy.sh`, and
`ls <token>` is not exempt. A harness-native prefix layer (Codex execpolicy)
reads them as true program prefixes; the hook is deliberately wider so a
called-by-path or wrapped invocation cannot dodge the rule.

## Finding what to add

A baseline of generic conventions cannot know that _your_ machine has a
`~/.pgpass` or a `~/.config/gh/hosts.yml`. `herkos discover` looks for
credential-shaped files that exist here and are not yet on your never-list, and
offers to add each — one keypress per candidate on a terminal, or
`herkos discover --add <ids>` in a script. It reports **paths only and never
reads a file's contents**: reading a credential file to decide whether to
protect it would be the exposure it exists to prevent. What it finds goes into
your own policy, never the shipped baseline.

## Proof through the real harness (opt-in)

The self-check and the corpus prove the hook herkos generates; they cannot prove
the harness still calls it after an upgrade. `herkos probe` does — it runs one
real, headless session per harness against your installed wiring and reads the
transcript to confirm a block fires. It is **opt-in and bounded**: it never runs
without a typed confirmation (or `--yes`), every run has a spend ceiling
(`--budget-usd`, default \$0.50, plus a `--timeout`), and it reads only decoy
files it plants in a throwaway directory — never a real secret. A `LEAKED`
verdict, the decoy's contents coming back in the output, fails the command.

```sh
herkos probe                 # confirm, then probe every installed harness
herkos probe --harness codex --yes --budget-usd 0.25
```

## What it is NOT

- **Not a sandbox.** OS-level containment is the platforms' job and they do it
  natively; herkos removes the _payoff_ of a hijacked agent (reading and
  shipping your secrets), it does not jail the process.
- **Not protection against everything.** It enforces a declared never-list. A
  risk you don't put on the list is one it won't stop.
- **Not a set-and-forget-and-never-check tool.** Harnesses change. herkos says
  so itself at the start of every session (see above); `herkos check` proves it
  on demand.

## Rules that guide instead of block

Some of the rules you actually want are not absolute "never"s but "not without
asking" — never push shared history, never write to prod, never send data
outward — where a hard block is too blunt. Give such a rule
`"disposition": "open"` and a `message`: when it matches, herkos lets the call
through and surfaces the message as a notice, instead of blocking. On Claude
Code the notice is shown to you as a system message in the transcript; the
agent itself does not see it — no non-blocking channel reaches the model — so
an open rule guides you, it cannot nudge the agent. An open rule grants nothing
and gates nothing — it is advisory — so it is not a
permission or an allow-list. Rules also carry their own **class** label (any
simple word) and an optional `message`, so a refusal names the real rule instead
of forcing it into one of the two built-in classes.

```json
{
  "id": "ask-before-push",
  "class": "shared-checkout-git",
  "disposition": "open",
  "description": "pushing shared history",
  "message": "Ask before pushing — this branch is shared.",
  "commandPrefixes": [["git", "push"]]
}
```

`herkos status` marks an open rule as an advisory notice, never among the layers
that actually block.

## A never-list a repo commits (`herkos project`)

The machine policy protects every session on your machine. A **project policy**
lets a repository carry its own never-list for every contributor — "never read
`secrets/prod`", "never run the reset script". Commit a `herkos.json` at the repo
root and run `herkos project init`:

```sh
herkos project init      # compile ./herkos.json into the repo's .claude project hook
herkos project check     # CI: fail if the committed hook drifted from herkos.json
```

It compiles the repo's rules into a **self-contained hook checked into the repo**
(`.claude/hooks/herkos-project.sh`, registered on `PreToolUse` in
`.claude/settings.json` via `$CLAUDE_PROJECT_DIR`). Commit `.claude/` and every
clone is guarded — **even a contributor who has never installed herkos**, because
the hook needs only `sh`, `awk` and `grep`.

Two properties keep it safe:

- **It composes; it can only add.** The project hook runs _alongside_ each
  contributor's machine hook — Claude Code runs hooks from every settings level
  and any refusal blocks — so a repo's policy can only _add_ to the machine's
  never-list, never weaken it. That's why `herkos.json` has no `disable`
  (herkos rejects one). A checked-out repo can't turn your protection off.
- **It carries nothing machine-specific.** The committed hook names the
  repo-relative `herkos.json`, no home path — clean to commit to a public repo.
  It carries the policy stamp, so `herkos project check` in CI fails when someone
  edits `herkos.json` without re-running init.

```json
// herkos.json at the repo root
{
  "rules": [
    {
      "id": "no-prod-secrets",
      "class": "credential-read",
      "description": "the repo's production secrets",
      "paths": ["secrets/prod/"]
    },
    {
      "id": "no-reset-script",
      "class": "command-never",
      "description": "the destructive reset script",
      "commandPrefixes": [["./scripts/reset-db.sh"]]
    }
  ]
}
```

**Claude Code only.** Codex resolves config from `~/.codex` with no repo-local
layer, so a repo's Codex sessions rest on the machine policy, not the repo's own
list — herkos says so rather than pretend a per-repo Codex guard exists.

**Blocked-call log (optional).** A committed hook logs nothing by default — a
stranger's clone must not be dirtied. `herkos.json` may set
`"logFile": "herkos-blocks.jsonl"`: every refusal then appends one JSON line
(time, harness, tool, rule — never the command text) to that file, resolved at
run time against the hook's own directory, so any clone or linked worktree
logs beside its own hook rather than a path baked on one machine. Gitignore
the file (and the `sessions/` state dir beside it); `herkos project check`
names it in CI when you haven't.

## Policy file

`~/.config/herkos/policy.json`:

```json
{
  "rules": [
    {
      "id": "my-vault",
      "class": "credential-read",
      "description": "Company vault dir",
      "paths": ["secrets/prod/"]
    }
  ],
  "disable": ["docker-auth"]
}
```

## Development

```sh
npm install
npm test          # includes a self-check that runs the real generated hook
npm run build
npm run typecheck
```

Roadmap: [ROADMAP.md](ROADMAP.md) · Decisions: [DECISIONS.md](DECISIONS.md)

## License

[MIT](LICENSE)
