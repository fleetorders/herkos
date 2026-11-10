---
"herkos": patch
---

`herkos discover`'s covered-check now runs in the one sound direction. A candidate used to count as covered when a rule's fragment merely CONTAINED the candidate's fragment — but such a rule is narrower than the candidate (it protects one specific spelling, leaving the candidate's other paths open), so a user rule like `.config/rclone/rclone.conf.backup` could silently hide the `rclone-conf` candidate. Coverage is now exactly: the rule's fragment appears inside one of the candidate's fragments, so every path the candidate would match is already blocked. The catalogue's two baseline-covered candidates (`gcloud-adc`, `pypirc-home`) are documented for what they are — offered only while their covering baseline rule is disabled, never alongside it — and the test now asserts what the command's own filter produces (plant every probe path, compare the offered set) instead of comparing rule ids, which the old test did while the predicate disagreed with it.
