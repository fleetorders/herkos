---
"herkos": minor
---

herkos now keeps a blocked-call log. Every refusal appends one JSON line to `blocked.log` beside the policy file — time, harness, tool, rule id and working directory, and never the command text, which can itself carry a secret. Until now nothing recorded what was blocked: a user could not tell whether the guard ever fired, and nobody could see a rule firing on legitimate work, which is the evidence the curation bar depends on. `herkos status` shows per-rule counts and the five most recent blocks.

The log is on by default; `"log": false` in the policy turns it off, and `validate` rejects any non-boolean value. Writing is best effort at every step and every failure is swallowed, so a log that cannot be written never turns a block into an allow. It rotates past 1 MiB, keeping one previous generation, and `uninstall` leaves it in place with the policy. The registered hook command now names its harness (`--harness claude-code` / `--harness codex`) so each block is attributed; a hook registered by an earlier version records `unknown`.
