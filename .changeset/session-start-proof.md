---
"herkos": minor
---

herkos now says every session whether it is actually enforcing. `init` registers a second, dependency-free hook on `SessionStart` that prints one line before the first tool call: enforced with a rule count and the classes covered, NOT wired (hook missing, or present but never registered, naming what goes unenforced), DRIFT (the installed hook was replaced or edited), or enforced-but-stale (the policy file changed and was never recompiled). Silent absence after a harness upgrade or a hand edit was the failure that cost everything, and the README's "run `herkos check` after upgrades" relied on remembering.

Every generated hook now carries a stamp — herkos version, a fingerprint of the compiled rules, and the rule count — readable with `sh hook --stamp` and from its marker line. `herkos status` prints the policy's current fingerprint and reports a wired-but-stale harness as STALE rather than "protected"; `VerifyResult` gains an optional `state` of `ok` / `stale` / `unwired`. The stamp is drift detection, not tamper resistance: a same-user hash has no trust anchor. `uninstall` removes the session-start hook, the policy snapshot it compares against, and any empty hook-event key it would otherwise leave behind.
