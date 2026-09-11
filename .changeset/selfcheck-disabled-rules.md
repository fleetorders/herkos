---
"herkos": patch
---

`herkos check` honours a baseline rule disabled by id: the case that exercises it now expects the call to pass through (and says so) instead of reporting a broken guard, so a sanctioned per-rule disable no longer turns `check` red. The test suite no longer reads the machine's own user policy.
