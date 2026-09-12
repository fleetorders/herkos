---
"herkos": patch
---

The hook now announces a tool call whose `tool_input` is present but not an object, instead of reading it as nothing. An array, a bare string or a literal as `tool_input` used to produce exit 0 with empty stderr — no arguments read, no `E` record, no `UNCOVERED` banner — contradicting the stated guarantee that a payload which could not be read is announced, never assumed safe. The extractor emits `tool_input is not an object` on its `E` channel, so the call surfaces as a `herkos DEGRADED` line: the argument vocabularies are keyed by name, and a container without names cannot be read. Only reachable when a harness violates its own payload contract (Claude Code and MCP always send an object); arrays under a named key _inside_ `tool_input` (such as `args`) are still read element by element as before.
