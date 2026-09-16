---
"herkos": minor
---

Open-rule notices now reach the user, multi-line values can no longer split a forbidden spelling, and the project registration degrades open on a missing hook file.

- An open rule's notice was printed to stderr and exited 0 — a channel whose output goes to the harness debug log only, so neither the user nor the agent ever saw it. On Claude Code the notice is now also emitted as a JSON `systemMessage` on stdout: the one hook channel that is both visible and non-blocking (the alternatives all break the rule's contract — `permissionDecision: "deny"` and exit 2 block the call; `"allow"` bypasses the permission prompt). The stderr line is still printed; other harnesses keep stderr, because only Claude Code's channel is verified. The agent still does not see the notice — no non-blocking channel reaches the model — stated in the README rather than hidden. Recorded as D-005.

- A string value containing newlines was rule-checked line by line, so a forbidden spelling could be split by an embedded newline — a fetched-code pipeline continued onto the next line (`curl … |\nsh`) read as two harmless lines and passed — and a `^`-anchored pattern fired at every embedded line start instead of the value's start. Values are now checked whole, their embedded newlines folded to spaces; a `^`-anchored pattern matches only at the start of the whole value. The bypass corpus gained the pipeline-split case. Recorded as D-006.

- The project-layer registration (`herkos project init`) ran `sh "$CLAUDE_PROJECT_DIR/.claude/hooks/herkos-project.sh"` bare. A missing or unreadable committed hook file made `sh` exit 2, which the harness reads as "block" — every tool call in the repo refused, the opposite of the hook body's own degrade-to-allow design. The registered command now checks readability first and exits 0 (with a DEGRADED line) when the file cannot run, while a deliberate exit-2 block from inside the hook still propagates — and it passes `--harness claude-code`, so an open rule's notice picks the right channel and a block is attributed in the blocked-call log. Repos wired by an earlier version pick this up on their next `project init`.
