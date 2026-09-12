---
"herkos": patch
---

`herkos probe` now reports a harness binary that cannot be run as its own outcome, instead of folding it into the timeout verdict. A missing binary (a misconfigured `HERKOS_CLAUDE_BIN`, a harness not on PATH), an `EPERM`, any spawn error used to land under "inconclusive — hit the time/spend ceiling", which misdiagnoses a broken setup as a bounded run. Spawn failures are now `unavailable` with the error named ("the harness binary could not be run (claude: ENOENT) — a broken setup, not a verdict on the wiring"); only a real timeout signal remains a ceiling hit.
