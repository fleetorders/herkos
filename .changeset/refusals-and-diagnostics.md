---
"herkos": patch
---

Wiring refusals, diagnostics and docs:

- The Claude Code settings gate now checks the nested shapes `wire()` actually dereferences — `hooks.PreToolUse` / `hooks.SessionStart` as arrays of objects (each entry's `hooks`, when present, an array of objects), `permissions.deny` an array, `sandbox.credentials` an object with `files` an array. A string `hooks.PreToolUse` or non-array `deny` used to throw inside `wire()` after the hook file was written — the exact half-applied install the one-level gate said was now impossible. Codex gains the same gate for `~/.codex/hooks.json`, checked before anything is written (a string `hooks` there used to make the registration a silent no-op while `init` reported success).
- An adapter refusal and a herkos defect are no longer the same message. Refusals are a typed `WireRefusalError` printed as one line; anything else out of `wire()` is a bug in herkos and prints its stack, labelled as such. And when wiring fails on the second harness, `init` now says which harnesses were already wired and how to finish, instead of exiting mid-loop as if nothing happened.
- `herkos uninstall` no longer reports clean success over an unreadable Codex `hooks.json`: the file is left alone and the result carries a WARNING that the PreToolUse registration may still be in it (degrade loudly, never silently).
- One-line exit-1 diagnoses (`herkos: …`) go to stderr, so `herkos check | grep` no longer swallows the reason for the failure — stdout may be piped; the terminal being looked at gets the diagnosis.
- The hook's exclusion grep suppresses grep's own stderr in `enforce` exactly as `notice` already did; a broken exclude regex no longer leaks a raw `grep:` line into the session ahead of the rule's own DEGRADED banner (the exit-status handling is unchanged).
- The README's `herkos.json` example is now valid strict JSON (the `//` header comment inside the `json` block failed `herkos project init` on copy-paste), with the `commandPrefixes` shape — a list of token lists, program first — described in prose beside it.
