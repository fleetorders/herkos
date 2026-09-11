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
```

## What it blocks (the default-on baseline)

Out of the box, before any configuration, herkos blocks the near-universal
never-list:

- **Credential reads** — SSH private keys, cloud credentials (AWS/GCP/Azure),
  Kubernetes config, `.env`-class files, `.netrc`/`.npmrc`/`.pypirc`, the GnuPG
  private keyring, Docker auth, and macOS keychain dumps.
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

- **Claude Code — full enforcement.** herkos installs a small, self-contained
  shell hook on `PreToolUse` that blocks both rule classes on every tool call, in
  every mode (including headless / skip-permissions). The hook matches **every
  tool**, including tool-server (MCP) tools you add later, and reads arguments by
  name — `file_path`, `path`, `paths`, `notebook_path`, `command`, `args` and
  their common spellings, at any depth. A tool it does not know whose arguments
  carry none of those names is announced as `herkos UNCOVERED` for that call,
  never assumed safe. Search patterns, URLs and free text (an edit's new
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
  immediately). Requires Codex ≥ 0.146.

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

## What it is NOT

- **Not a sandbox.** OS-level containment is the platforms' job and they do it
  natively; herkos removes the _payoff_ of a hijacked agent (reading and
  shipping your secrets), it does not jail the process.
- **Not protection against everything.** It enforces a declared never-list. A
  risk you don't put on the list is one it won't stop.
- **Not a set-and-forget-and-never-check tool.** Harnesses change. herkos says
  so itself at the start of every session (see above); `herkos check` proves it
  on demand.

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
