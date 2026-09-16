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
