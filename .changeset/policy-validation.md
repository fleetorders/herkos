---
"herkos": patch
---

Security: a user rule whose commandPatterns entry contained a single quote was pasted unescaped into the generated hook, turning the script into a shell syntax error that blocked every tool call; an invalid extended regex in a pattern made grep exit 2, silently disabling that rule. Policy validation now rejects both before wiring (`herkos validate`; `init` refuses on errors), every baked value is shell-quoted so the script always parses, refusals name the rule that fired, and a run-time grep error degrades loudly (that rule off for the call, DEGRADED on stderr) instead of failing open in silence.
