# Decisions

Append-only. Each entry records a decision, why it went that way, and what it
forecloses. Supersede an entry with a new one; never rewrite its substance.

### D-001 — One policy, compiled into each harness's native wiring

**Scope:** repo · **Decided:** 2026-08-15

The user declares one never-list; per-harness adapters compile it into each
installed harness's native enforcement mechanism. The policy is harness-agnostic;
adapters own all harness-specific knowledge.

**Why:** there is no universal, OS-level point where a tool can intercept every
harness's actions, so enforcement must go through each harness's own extension
point. Keeping the policy independent of those mechanisms means one rule set
protects every harness, and adding a harness is a new adapter rather than a
redesign.

**Consequences:** coverage differs by harness (a harness that exposes no
per-call hook cannot enforce the fine-grained list); the tool must state that
difference honestly rather than imply a uniform guarantee.

### D-002 — The enforcement path depends on nothing

**Scope:** repo · **Decided:** 2026-08-15

The deployed enforcement (for a harness with a hook, a self-contained shell
script) requires no network and no other tool to run. Verification and update
machinery live outside the enforcement path.

**Why:** a security control that stops working when a dependency is missing is
worse than none. Keeping enforcement dependency-free means a fresh install
protects out of the box and keeps protecting regardless of what else is present.

**Consequences:** the enforcing hook cannot rely on this package at runtime;
richer checking is delivered separately and degrades to absence gracefully.

### D-003 — A curated, default-on baseline; user rules extend, never replace

**Scope:** repo · **Decided:** 2026-08-15

Every install ships a curated never-list on by default (credential reads,
fetched-code execution). A user policy file adds rules and can disable baseline
rules by id — per-rule and explicit, never "turn the guard off".

**Why:** a security tool that ships empty protects nobody on install day, and
"configure it first" is the friction that kills adoption. The baseline must be
high-confidence: a false positive in a default rule trains users to disable the
guard, which is worse than no guard.

**Consequences:** the baseline grows slowly and only with near-universally
never-legitimate rules; anything project-specific belongs in the user's policy.

### D-004 — Degrade loudly, never fail closed silently

**Scope:** repo · **Decided:** 2026-08-15

When the enforcement hook cannot parse its input it announces that enforcement is
off for that call and allows it; it never silently permits a matched action.

**Why:** hard-blocking on every unparseable call bricks the session, and silently
allowing a matched never-list action defeats the tool. Announcing the degraded
state keeps the user informed without breaking their work.

**Consequences:** a missing parser dependency reduces coverage visibly rather
than failing open in silence or closed in a way that halts the session.

### D-005 — An open rule's notice rides the harness's verified non-blocking channel

**Scope:** repo · **Decided:** 2026-09-17

An OPEN rule's message is surfaced on the `systemMessage` field of a JSON
object on stdout (exit 0) when the invoking harness is Claude Code; on any
other harness name (or none), the stderr line is the whole surface, as
before. The stderr line is printed in both cases, as it is collected.

**Why:** an independent review of a consumer repo's install pointed out that
stderr from a hook that exits 0 reaches only the harness debug log — the
model never sees it and the user never opens it — so an open rule was
announcing to nobody. Of the channels the hook protocol offers, every other
one breaks the rule's own contract: `permissionDecision: "deny"` and exit 2
block the call (an open rule must not block); `permissionDecision: "allow"`
bypasses the permission prompt (an open rule must not grant anything).
`systemMessage` is the one surface that is both visible and non-blocking.
Codex keeps stderr because its non-blocking output surface is unverified —
claiming it would be a guarantee herkos cannot keep; the hook branches on its
`--harness` argument, which every wiring herkos writes now passes.

**Consequences:** on Claude Code the user sees the notice, the model still
does not — no non-blocking channel reaches the model, which is stated rather
than hidden: an open rule guides the person, it cannot nudge the agent. The
DEGRADED and UNCOVERED announcements stay on stderr for now; surfacing
UNCOVERED on the user channel would speak on every call to a tool whose
arguments herkos cannot read, which is the noise that gets a guard muted —
that trade-off stays open for the maintainer.

### D-006 — One string value is one record: embedded newlines fold to spaces

**Scope:** repo · **Decided:** 2026-09-17

The extractor folds a value's embedded newlines to spaces before rule
matching, so each string value is checked as one whole subject. Previously
each line of a multi-line value was a separate record.

**Why:** line-by-line checking let a never-list rule be escaped by embedding
a newline inside the forbidden spelling — a fetched-code pipeline continued
onto the next line read as two harmless lines — and made a `^`-anchored
pattern fire at every embedded line start rather than at the value's start.
The corpus gained the pipeline-split case to pin it.

**Consequences:** a `^`-anchored command pattern now matches only at the
start of the whole value; a policy author who wants "any line" semantics
writes the pattern unanchored. Folding joins tokens that sat on adjacent
lines, so a pattern whose tokens are `[[:space:]]`-joined can now match
across a line break — accepted, because tokens split that way are far more
likely an attempted dodge than two coincidentally adjacent commands, and the
missed-attack cost of line-by-line checking exceeds this contrived
false-positive cost.

### D-007 — Token boundaries are asymmetric, and a pattern can only match ASCII

**Scope:** repo · **Decided:** 2026-09-17

A prefix rule's baked pattern keeps the leading boundary `(^|[^[:alnum:]_.-])`
but its trailing class is `([^[:alnum:]_-]|$)`: on the trailing side a dot or
hyphen TERMINATES the forbidden spelling rather than continuing the token.
And a pattern carrying non-ASCII text is warned against at validation: the
hook's reader decodes payload text to ASCII, so such a pattern can never match.

**Why:** an independent tier-1 review of a consumer repo's install measured
that only whitespace- or EOL-terminated spellings were caught — `sh
migrate-v2-reset.sh; echo done`, a pipe, a subshell-close, `bash -c` quoting
all passed, because shell punctuation directly after the spelling did not
match `[[:space:]]`. A shell would have run the forbidden program in every one
of those positions, so every one of them is the spelling. Keeping the leading
class wider (dot and hyphen continue a token there) preserves the
shared-prefix false-positive protection (`migrate-v2` must not catch
`migrate-v2.sh`); narrowing only the trailing side closes the dodge without
reopening that false positive — `migrate-v2-reset.sh.bin` is blocked, which is
the safe side for a never-list. The ASCII constraint is the matching half of
the same fact: non-ASCII in a pattern is dead text the author cannot see
failing (see D-008's W record for the value side).

**Consequences:** a command whose forbidden spelling is genuinely continued by
alphanumerics, `_` or `-` (`--force-with-lease` under a `--force` rule) still
passes — that is a different token, and pinning it is the policy author's
call, not the compiler's. A trailing `.` treats `name.sh.anything` as the
forbidden `name.sh`; accepted as the safe side. Rules naming non-ASCII text
are warned, not refused — a future reader that represents them would make the
warning obsolete.

### D-008 — Degradation is sticky and heard; the posture stays fail-open-loud

**Scope:** repo · **Decided:** 2026-09-17

Every degradation announcement (awk missing, unparseable payload, a rule's
pattern grep cannot evaluate, a value decoded lossily) rides the same heard
channel D-005 built for open-rule notices — the JSON `systemMessage` on
Claude Code, stderr as collected elsewhere — and a degradation MARKS the
session: later calls in the same session keep announcing it, keyed to the
payload's `session_id`, until the session ends (markers expire after a week).
An UNCOVERED tool reaches the user channel once per session and tool; its
stderr diagnostic stays on every call. The catastrophic-class posture —
`command-never` with hard-block disposition — STAYS fail-open-loud on
unparseable payloads, per D-004: the tier-1 review argued for fail-closed
(one weird payload re-issued versus a live install's data), and that argument
is recorded here rather than decided away — flipping it is the maintainer's
call, and the sticky announcements are what make fail-open honest enough to
revisit deliberately instead of urgently.

**Why:** D-005's own verification showed stderr at exit 0 reaches nobody, and
the DEGRADED lines were never moved onto the new channel — so a degraded
state was silent exactly when it mattered, once per call and then forgotten.
A degradation the session sees once is a degradation the session forgets;
stickiness makes the state follow the session instead of the call. UNCOVERED
is bounded to once per session and tool because D-005's noise warning stands:
a line on every call to a tool whose arguments herkos cannot read is how a
guard gets muted. Lossy decoding announces a W record rather than failing the
payload (E): the decoded text is still checked and every ASCII pattern sees
the ASCII stretches intact, so turning a whole call's enforcement off over
one non-ASCII character trades real coverage for ceremony.

**Consequences:** session state lives beside the blocked-call log, so a hook
that writes nothing (a committed project hook, or the user turning the log
off) announces per call but cannot be sticky — stated, and the reason: a
stranger-safe committed hook must not write machine-local state. On Claude
Code the user sees degradations now; the model still does not (no
non-blocking channel reaches it), as with notices. The marker file names the
first reason recorded; a session that degrades for a second reason announces
that too, on its own call. Fail-closed for catastrophic rules remains open to
the maintainer: if it flips, D-004's session-bricking argument needs an
answer first (a malformed-payload block loop with no user watching is a
session wedged by its own guard).

### D-009 — An unevaluable exclusion degrades the rule; subsumed prefixes warn

**Scope:** repo · **Decided:** 2026-09-17

A block rule's exclusion regex (`notPaths`) is now evaluated with the same
care as its main pattern in the generated hook: silenced, status-checked, and
an exit ≥ 2 turns that ONE rule off for the call with a loud, sticky
announcement naming the rule — instead of reading as "does not match" and
letting the rule fire on the main pattern as if the carve-out did not exist.
`validate` and `project init` also warn when one command prefix's generated
pattern subsumes another's within a rule, and `project init` names the
one-time settings backup it takes.

**Why:** the exclusion is half of the rule's verdict, so an unevaluable
exclusion is an unevaluable rule — treating grep's error exit as "no match"
was a silent verdict flip that only the main pattern's own failure caught.
Rule-off-loud matches the posture every other grep failure already takes
(D-004/D-008): the alternative, firing the main pattern as if no exclusion
existed, is fail-closed against exactly the benign spellings the exclusion
exists to spare (.env templates), and a false block is how a guard gets
disabled. The subsumption warning exists because the natural policy shape —
the same script spelled `./script` beside `script` — bakes two rule lines
whose boundary classes make the second redundant, printing the identical
notice twice on an open rule; it is a warning, not an error, because a
redundant prefix costs a duplicate line, not safety (curation bar: warnings
inform, errors refuse).

**Consequences:** a policy with a broken exclusion now leaves that rule
unenforced-but-announced rather than mis-enforced — the honest direction for
a guard whose loudness is the product. The subsumption probe tests one
prefix's compiled pattern against the other's space-delimited spelling, which
is exact for these boundary-anchored patterns; a policy carrying genuinely
overlapping prefixes on purpose (one line per spelling for readability) will
be told so on every validate and can ignore it. Re-running `project init`
over a registration the repo hardened itself replaces it with the stock
hardened command (fail-open guard, harness named) — equivalent hardening,
not byte-preservation of consumer edits; a repo needing MORE than that keeps
its own line by re-editing after init.
