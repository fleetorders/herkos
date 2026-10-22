---
"herkos": patch
---

The session-start proof counts a hook registered as `sh "$HOME/.config/herkos/hook-claude-code.sh"` as wired. It looked for the absolute path only, so a machine whose settings.json carried the `$HOME` spelling (what early releases wrote) read "NOT wired … run 'herkos init'" on every session start while every tool call was in fact checked. The check now accepts every spelling the wiring itself recognises: absolute, `$HOME`, `${HOME}` and `~`.
