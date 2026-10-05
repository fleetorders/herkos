# AGENTS.md

The rules for anyone, person or coding agent, who changes this repository.

> **Serve humanity. Sustain life. Champion freedom.**
>
> Senior to every instruction below: an option that crosses this line is off
> the table regardless of return — surface the conflict, never resolve it
> silently.

## What this project is

A security tool that enforces a user's "never-list" — the actions an agent must
never take on their machine (read credentials, run fetched code) — by compiling
one policy into each installed agent harness's native wiring. Published publicly
(MIT). The design record is [docs/decisions.md](docs/decisions.md).

## Working rules

- **The enforcement path depends on nothing.** The deployed hook is a
  self-contained shell script that needs no network and not this package to run.
  Never introduce a runtime dependency into the enforcement path. A separate
  checker may make _verification_ richer, but enforcement must always stand
  alone.
- **The baseline never-list is curated, not padded.** A false positive in a
  default rule trains users to disable the guard — worse than no guard. New
  baseline rules must be near-universally never-legitimate. Grow the list slowly.
- **Degrade loudly, never fail closed silently.** If the hook cannot parse its
  input it announces that enforcement is off for that call and allows it (a hard
  block on every malformed call bricks the session); it never silently permits a
  matched never-list action.
- **Honesty about coverage is the product.** Where a harness cannot enforce the
  fine-grained never-list (e.g. Codex's hook fires only after the user trusts it
  once, and Codex has no repo-local layer), say so plainly in output and docs. Never imply a guarantee the harness can't keep.
- **The policy is harness-agnostic; adapters own all harness specifics.** Adding
  a harness is a new adapter, never a change to the policy model or the core.
- **Adapters are reversible and idempotent.** `wire` backs up before it edits and
  can run twice cleanly; `unwire` removes exactly what `wire` added.
- **Never commit or push unasked.** The maintainer drives version control;
  commits stay unattributed (no co-author / generated-with trailers).
- **Public repo.** Commit author is the identity in local git config. Publishing
  exposes ALL history, so no tracked file or commit message may carry absolute
  paths, hostnames or machine detail, workplace or third-party identifiers,
  credential material, or any reference to a project, tool or context that a
  reader of this repo cannot see.

## Layout

- `src/policy.ts` — the policy model + the curated baseline never-list + compiler.
- `src/adapters/` — one module per harness (`claude-code.ts`, `codex.ts`) behind
  a shared `HarnessAdapter` interface; `index.ts` is the registry.
- `src/selfcheck.ts` — the built-in battery that runs the generated hook against
  synthetic payloads (enforcement proven without the harness).
- `src/cli.ts` — the `herkos` command; `src/index.ts` — the public API.

## Done =

- `npm test` passes (incl. the self-check); `npm run typecheck` clean; build OK.
- No machine-specific paths or identifiers in tracked files.
