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
  every mode (including headless / skip-permissions).
- **Codex CLI — credential reads OS-enforced; fetched-code via a hook you trust
  once.** herkos compiles the credential never-list into a Codex permission
  profile whose filesystem `deny` entries are enforced by the OS sandbox
  (Seatbelt/Landlock) — verified: a read of a denied path returns `Operation not
permitted`. This half is seamless and arguably stronger than a hook. For
  fetched-code, herkos installs the same shell hook into Codex's `PreToolUse`, but
  non-managed Codex hooks require a one-time trust step — **run `/hooks` in Codex
  once** to activate fetched-code blocking (credential denies are live
  immediately). Requires Codex ≥ 0.146.

Adding a harness is adding an adapter, not redesigning — the policy never changes.

## What it is NOT

- **Not a sandbox.** OS-level containment is the platforms' job and they do it
  natively; herkos removes the _payoff_ of a hijacked agent (reading and
  shipping your secrets), it does not jail the process.
- **Not protection against everything.** It enforces a declared never-list. A
  risk you don't put on the list is one it won't stop.
- **Not a set-and-forget-and-never-check tool.** Harnesses change; run
  `herkos check` after upgrades, or on a schedule.

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
