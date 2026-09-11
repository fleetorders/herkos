---
"herkos": patch
---

`herkos init` now refuses a Claude Code settings file it cannot merge into, cleanly and before writing anything. A `settings.json` that is not valid JSON, whose top level is not an object, or whose `hooks`, `permissions` or `sandbox` is not an object used to crash wire() mid-write with a raw `TypeError` — after the hook file was written but before it was registered, leaving a stack trace and a half-applied install. The shape is now checked first, and a refused init prints one line ("your settings.json has 'hooks' as a boolean — fix or remove it, then re-run 'herkos init'"), exits 1, and writes nothing: no hook, no snapshot, no half-registered settings.
