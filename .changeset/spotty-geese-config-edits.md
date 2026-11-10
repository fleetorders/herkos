---
"herkos": patch
---

Config-editing fixes: orphaned tables, a bare selector, string examples, quoted spellings.

- Codex: an orphaned `[permissions.herkos]` table runs to the next table header, never to a blank line — a blank line inside one used to leave its keys behind in whatever table sat above, duplicating `extends` into a config Codex refuses to load. Wiring and uninstalling are both affected.
- Codex: `uninstall` now removes a bare `default_permissions = "herkos"` as well as the marked one. A tool that strips comments takes the ownership marker off that line; the selector then survived uninstall while the profile went with it, naming a profile that no longer exists.
- Codex: a `[permissions.herkos]` written inside a triple-quoted string — an example in `developer_instructions` — is text, not a table header. Cleanup used to delete through it and return a config with an unterminated string.
- Codex: `init` refuses a config that would define the herkos table twice in different spellings (`[permissions.herkos]` and `[permissions."herkos"]` are the same table) instead of appending a second copy Codex cannot load. The spelling is still never rewritten; the refusal names it.
- Claude Code and Codex: a hook command whose path ends in `~` — an editor's `hook-claude-code.sh~` backup — is someone else's script; `uninstall` no longer claims and removes its registration.
