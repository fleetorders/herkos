---
"herkos": patch
---

Selftest-exclusion, shared-helper and project-fallback channel fixes.

- Claude Code: the generated hook's `--selftest` applies a rule's exclusion by the same token-removal semantics `enforce` uses, not whole-subject — a match example naming a real target beside an excluded spelling (`cat app/.env app/.env.example`, which the hook blocks at run time) used to FAIL the selftest as "the rule exclusion covers it", the exact drift the selftest exists to catch. The baseline dotenv rule now carries that mixed example, so the wiring's own proof pins the semantics.
- Claude Code: `enforce`, `notice` and the selftest share one `remaining_tokens` helper instead of three copies of the exclusion's token loop — the copies had already drifted apart once.
- Claude Code (project wiring): the registered project-hook command's fallback for a missing or unreadable hook file now says its DEGRADED line as a JSON `systemMessage` on stdout as well — exit-0 stderr reaches only the debug log on Claude Code, so the one case with enforcement entirely off was announced to nobody. The wiring lives in Claude Code's own settings, so no other harness runs it.
