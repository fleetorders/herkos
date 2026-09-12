---
"herkos": patch
---

Codex adapter, two defects found on a live install: (1) `default_permissions = "herkos"` was appended after the user's tables, which TOML scopes to the last table rather than the root, so the deny profile was defined but never selected and Codex refused its config ("defines [permissions] profiles but does not set default_permissions"); the key now goes in the root section above the first table, marked, and `uninstall` removes it. (2) The managed-block markers contain parentheses that were never escaped in the adapter's own regex, so the block was never found again and every `init` appended another copy until Codex refused the file ("duplicate key"); markers are now escaped, stale copies are collapsed to one, and `verify` reports a profile that is present but not selected as NOT wired.
