---
"herkos": patch
---

`herkos discover --list` now does what it documents: it prints the uncovered credential-shaped files and stops, naming the exact `--add` command to act on them — it never enters the per-candidate prompt. The flag was declared ("only list; never prompt") but never read, so on a terminal `--list` still prompted `y/N/a/q` for every candidate. The command body moved beside the candidates it names (still injected with the CLI's options), so the flag handling is tested without the CLI's argv.
