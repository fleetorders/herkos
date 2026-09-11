---
"herkos": minor
---

Credential reads are now also compiled into Claude Code's own permission deny rules. `init` adds one `Read(…)` entry per credential target to `permissions.deny` in the harness settings, generated from the same policy as the hook so the two cannot drift apart. A deny rule holds in every permission mode, blocks through a symlink as well as its target, covers the file commands Claude Code recognises inside Bash and their redirections, and no hook or setting can override it. The hook keeps what deny rules miss (a shell wrapper, a program called by full path); deny rules keep what text matching misses (symlinks, a `cd` followed by a relative read, directory reads through Grep and Glob).

Rules gain an optional, harness-agnostic `denyRead` list of gitignore-style targets — home-anchored, absolute, or relative to the session's working directory. The baseline sets precise ones: only the SSH `id_*` key files rather than the whole directory, the GnuPG private-key directory rather than every keyring. A user rule without `denyRead` derives its targets from `codexDeny`. Command-shaped rules never become deny rules: denying a command prefix such as `curl` would refuse every download.

The change is reversible and never claims what the user wrote: herkos records which entries it added in its own directory, leaves an identical entry the user already had untouched, withdraws the entries of a rule disabled later, and on `uninstall` removes exactly its own entries (and the `permissions` block only if herkos created it). `status` reports a hand-deleted deny rule as STALE and names it; `rules` lists each rule's native targets; `validate` rejects a target containing a parenthesis or a newline.
