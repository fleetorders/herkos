---
"herkos": patch
---

Ownership matching and hook-channel fixes.

- Claude Code and Codex: `init` and `uninstall` now recognize a hook registration written with quote-split spellings (`"$HOME"/.config/...`) — unmatched, `init` appended a second entry and the hook ran twice: the exact double registration 0.4.1 fixed, in its quoted form.
- Claude Code and Codex: a command that merely NAMES the hook path (`cat`, `grep`) no longer counts as running it — `init` could report the hook wired while a wrapper read the script instead of executing it, and `uninstall` could remove an entry that was never herkos's. Codex's wired-check parses hooks.json instead of matching text in it; JSON that will not parse says "not wired".
- Claude Code: an OPEN rule whose exclusion grep cannot evaluate degrades loudly instead of silently noticing the benign spellings the carve-out exists to spare — the same guard block rules already had, so the comment ("exactly as in enforce") and the code now agree. Its exclusion is also evaluated only after the main pattern matches: one grep per rule per call on payloads that match nothing, instead of two — a broken exclusion degrades exactly when it could flip a verdict.
- Claude Code: a block no longer emits a systemMessage JSON on stdout — exit 2's verified channel is stderr (on a live harness, a stdout systemMessage there surfaces as unparsed raw text beside the refusal); notices ride stderr next to the refusal.
- Claude Code: a relative LOG_FILE no longer resolves against a nonsense path when the hook is invoked by bare name through PATH ($0 with no slash).
- Claude Code: the session id from the payload is folded to flat filename characters before it names a marker file, making the state directory's flatness unconditional rather than an accident of the `degraded-` prefix.
