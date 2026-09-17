---
"herkos": minor
---

Prefix rules now catch shell punctuation, degradations are heard and sticky, and the payload reader is honest about what it cannot decode.

- A prefix rule's pattern ended at whitespace or end-of-line, so a forbidden spelling followed by any other shell punctuation passed: `sh migrate-v2-reset.sh; echo done`, a pipe after the spelling, a subshell-close, `bash -c 'migrate-v2-reset.sh'` — a shell would have run the forbidden program in every one of those positions. The trailing boundary is now "any non-token character" (`[^[:alnum:]_-]`), while the leading boundary keeps dot and hyphen as token continuations, so a name that merely shares a prefix (`migrate-v2.sh` under a `migrate-v2` rule) still passes and `migrate-v2-reset.sh.bin` does not. Recorded as D-007.

- Every degradation announcement (awk missing, unparseable payload, a rule whose pattern grep cannot evaluate) now rides the same channel that made open-rule notices heard: a JSON `systemMessage` on stdout on Claude Code, stderr as before elsewhere. And degradation is sticky for the session — keyed to the payload's `session_id`, later calls in the same session keep announcing that an earlier call ran with enforcement off, instead of the state being one unseen line on one call. An UNCOVERED tool reaches the user channel once per session and tool (its stderr diagnostic stays on every call), keeping D-005's noise bound. The fail-open posture itself is unchanged and now written down: D-008 records the review's fail-closed argument for catastrophic rules and leaves the flip to the maintainer.

- The awk string decoder mangled non-ASCII escapes to `?` and control characters to spaces with no signal — a future rule naming such text would silently not match. A lossily decoded value now carries a W record and the hook announces it (decoded text is still checked; enforcement is not turned off over one non-ASCII character), validation warns when a pattern itself carries non-ASCII (it can never match what the reader decodes), and a property test pins the decoder against a real JSON encoder's output across 200 generated values. Recorded as D-007 and D-008.
