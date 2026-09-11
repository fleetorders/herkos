---
"herkos": minor
---

Claude Code: credential paths are now also compiled into the OS sandbox's own credential list, `sandbox.credentials.files` with mode `deny`, which the operating system enforces for every shell command and its child processes once the sandbox is on. herkos never switches the sandbox on: the entries are written either way, are inert while it is off, and hold from the first command once the user enables it. `init`, `status` and the per-rule coverage all say which it is — when the sandbox is off, credential reads rest on the permission deny rules and the hook, and `status` says exactly that.

The sandbox list takes a file or directory path (absolute or `~`-expanded), not a glob, so a target ending in `/**` contributes its directory and other globs are left out. They are not lost: Claude Code's settings schema (as of 2.1.268) states that `sandbox.filesystem.denyRead` is merged with `Read(…)` deny permission rules, so the rules herkos already writes reach the OS layer too. A relative target is left out, since it would resolve against the settings directory rather than the project.

As with the deny rules, herkos records which entries it added: an entry the user already has for the same path — in any mode, including `mask` — is never replaced or removed, a rule disabled later has its entries withdrawn, and `uninstall` removes exactly herkos's entries and only the containers it created, never `sandbox.enabled`. `status` reports a hand-deleted entry as STALE and names the OS sandbox as the strongest layer of each rule it holds.
