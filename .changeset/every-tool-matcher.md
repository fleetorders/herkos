---
"herkos": minor
---

The Claude Code hook now checks every tool, not two fixed matchers. It was registered for `Bash` and `Read|Grep|Edit|Write` and read two argument names, so `Glob`, `NotebookEdit`, `PowerShell` and every tool-server (MCP) tool — a filesystem server's `read_text_file`, say — reached the session without passing the never-list. `init` now registers a single `*` matcher, and the hook reads arguments by name at any depth of the argument object: path-shaped names (`file_path`, `path`, `paths`, `notebook_path`, `source`, `destination` and common spellings) are matched against the path fragments; command-shaped names (`command`, `cmd`, `script`, `code`, `args`, `argv`) against both the path fragments and the command patterns. Refusals name the tool.

A tool herkos does not know whose arguments carry none of those names is announced on stderr as `herkos UNCOVERED` for that call — the never-list was not checked, and herkos says so instead of assuming the call is safe. Known tools that take no path stay quiet.

Deliberately not read as paths, to keep false alarms near zero: `pattern` (a search expression in `Grep`), `url`/`uri`, and free text such as an edit's new content or a prompt. Pathname expansion is disabled while argument values are split, so a value like `src/*` is checked as written. `status` reports an install from an earlier version (two fixed matchers) as STALE, and `check` gains a tool-server case.
