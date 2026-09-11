# Roadmap

A living list — items get done, dropped, or reordered. Deleted when stale rather
than left to rot. What exists today is described in the README, not here.

## Now

- Per-session proof that enforcement is on — **done**: a session-start line
  reports enforced / not wired / drifted, and every generated hook carries a
  version + policy fingerprint stamp.
- Every tool checked, including tool-server tools — **done**: one `*` matcher,
  arguments read by name at any depth, unknown shapes announced as uncovered.
- Credential reads in the harness's own deny layer — **done** for Claude Code
  permission deny rules, with exact ownership tracking so `uninstall` removes
  only what herkos added.
- A record of what was refused — **done**: a blocked-call log without command
  text, per-rule counts in `status`.
- Codex rules live without the trust step — **done** for prefix-shaped command
  rules (execpolicy `forbidden`, checked by Codex before install); `status`
  names which layer holds each rule on each harness.
- Credential reads in the OS sandbox — **done** for Claude Code
  (`sandbox.credentials.files`, never switching the sandbox on; `status` says
  when it is off).
- Proof against other spellings — **done**: a bypass corpus in `check` with the
  hook measured and native layers credited where wired; rule `match` /
  `notMatch` examples run by `validate`. Open: two recorded gaps (download then
  run; download piped to an interpreter).
- An enforcement path that depends on nothing — **done**: the hook reads its
  payload with a POSIX awk extractor; no jq, and an unreadable payload is
  announced instead of passing in silence.
- Adapters for more harnesses (the policy is harness-agnostic; each is a new
  adapter behind the shared interface).
- A guided `herkos init` that reports, per harness, exactly what it can and
  cannot enforce before writing anything.

## Next

- More baseline rule classes, added slowly and only when near-universally
  never-legitimate (candidate: tamper-detection of agent instruction files).
- Managed/organisation policy: compile the never-list into each harness's
  enterprise-policy layer so it cannot be overridden locally.

## Later

- A team view: one policy, many machines, with an auditable record of per-user
  overrides.
