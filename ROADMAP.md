# Roadmap

A living list — items get done, dropped, or reordered. Deleted when stale rather
than left to rot. What exists today is described in the README, not here.

## Now

- Per-session proof that enforcement is on — **done**: a session-start line
  reports enforced / not wired / drifted, and every generated hook carries a
  version + policy fingerprint stamp.
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
