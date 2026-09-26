---
"herkos": patch
---

Re-running `herkos init` over an install made by an earlier release no longer registers the hook twice or breaks Codex's config.

- The hook's registration is now recognised in every spelling a command can use for a path under your home directory (`$HOME/...`, `${HOME}/...`, `~/...` and the absolute path). Early releases registered it as `$HOME/...`. Upgrading kept that entry and added a second one, so the hook ran twice on every call, in both Claude Code and Codex.
- Codex: when something else rewrites `config.toml` and drops herkos's opening marker comment, the `[permissions.herkos]` tables are still found and replaced; before, a second copy was appended and Codex refused to start. `unwire` removes such tables too, and the block is now always written after a blank line, the boundary where a careful tool stops when it deletes the section above. A tool that deletes through blank lines can still remove the opening marker; the table is then still found by its heading. As a last guard, `init` refuses to write a `config.toml` that would repeat a herkos table, and leaves the file as it was.
- `wire` and `unwire` remove only herkos's own commands from a hook entry; a user command in the same entry stays.
