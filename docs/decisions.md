# Design decisions

What was decided and why, for anyone changing the code. Code comments cite an entry as
`docs/decisions.md, D-004`. An entry that no longer shapes the code is deleted.

### D-001 — One policy, compiled into each harness's native wiring

The user declares one never-list; one adapter per harness compiles it into that harness's
own enforcement mechanism. The policy knows nothing about harnesses; adapters own every
harness-specific detail.

**Why:** there is no OS-level point where one tool can intercept every harness's actions,
so enforcement has to go through each harness's own extension point. A harness-free policy
means one rule set protects every harness, and adding a harness is a new adapter, not a
redesign.

**Consequences:** coverage differs by harness (one without a per-call hook cannot enforce
the fine-grained list), and herkos says so rather than implying a uniform guarantee.

### D-002 — The enforcement path depends on nothing

The deployed enforcement (for a harness with hooks, a self-contained shell script) needs no
network and no other tool to run. Verification and update tooling live outside it.

**Why:** a security control that stops working when a dependency is missing is worse than
none. A dependency-free hook protects from the moment it is installed, whatever else is
present.

**Consequences:** the hook never calls this package at runtime; richer checking ships
separately and, when absent, is simply absent.

### D-003 — A curated, default-on baseline; user rules extend, never replace

Every install ships a curated never-list, on by default (credential reads, running fetched
code). A user policy adds rules and can disable baseline rules by id, one at a time; there
is no switch that turns the guard off.

**Why:** a security tool that ships empty protects nobody on install day, and "configure it
first" is the friction that stops people installing it. The baseline must be
high-confidence: a false positive in a default rule teaches users to disable the guard,
which is worse than no guard.

**Consequences:** the baseline grows slowly, and only with rules that are almost never
legitimate for anyone; project-specific rules belong in the user's policy.

### D-004 — Degrade loudly, never fail closed silently

When the hook cannot parse its input, it announces that enforcement is off for that call
and allows the call. It never silently permits a matched action.

**Why:** hard-blocking every call it cannot parse would lock the session up, and silently
allowing a matched action defeats the tool. Announcing the degraded state keeps the user
informed without stopping their work.

**Consequences:** a missing parser dependency reduces coverage visibly. Blocking
unparseable calls for the most dangerous rules (fail-closed) was considered and not
adopted: a block that repeats on every malformed payload, with nobody watching, leaves the
session stuck behind its own guard. Changing this needs an answer to that first.

### D-005 — An open rule's notice goes on a channel the user sees

On Claude Code, an open rule's message (a rule with `disposition: "open"`, which informs
instead of blocking) is printed as the `systemMessage` field of a JSON object on stdout,
with exit 0. On any other harness the stderr line is the whole notice. The stderr line is
printed in both cases.

**Why:** stderr from a hook that exits 0 reaches only the harness's debug log, so on its
own it announces to nobody. Every other channel in the hook protocol breaks the open rule's
contract: `permissionDecision: "deny"` and exit 2 block the call, and
`permissionDecision: "allow"` skips the permission prompt. `systemMessage` is the one
channel that is both visible and non-blocking. Codex keeps stderr because no non-blocking
visible channel is confirmed there. The hook picks the channel from its `--harness`
argument, which every wiring herkos writes passes.

**Consequences:** on Claude Code the user sees the notice; the model does not, because no
non-blocking channel reaches it. An open rule guides the person, not the agent, and the
docs say so.

### D-006 — One string value is one record

The extractor turns a value's embedded newlines into spaces before matching, so each
string value is checked as one whole subject.

**Why:** checking line by line let a rule be escaped by putting a newline inside the
forbidden spelling (a download piped to a shell, continued onto the next line, read as two
harmless lines), and made a `^`-anchored pattern fire at every line start inside a value.
The bypass corpus includes the split-pipeline case.

**Consequences:** a `^`-anchored command pattern matches only at the start of the whole
value; a policy author who wants "any line" writes the pattern unanchored. Joining lines
can make a pattern whose tokens are joined by `[[:space:]]` match across a line break;
that is accepted, because a token split across lines is far more likely a dodge than two
unrelated commands that happen to be adjacent.

### D-007 — Token boundaries are asymmetric, and patterns match ASCII only

A prefix rule's compiled pattern starts with the boundary `(^|[^[:alnum:]_.-])` and ends
with `([^[:alnum:]_-]|$)`: after the forbidden spelling, a dot or hyphen ends it instead of
continuing it. A pattern containing non-ASCII text gets a warning from `validate`, because
the hook's reader decodes payload text to ASCII and such a pattern can never match.

**Why:** with whitespace as the only trailing boundary, `sh migrate-v2-reset.sh; echo
done`, a pipe, a closing subshell or `bash -c` quoting all escaped the rule, although a
shell runs the forbidden program in every one of those positions. The wider leading class
keeps the shared-prefix protection (`migrate-v2` must not catch `migrate-v2.sh`), and
narrowing only the trailing side closes the dodge without reopening that false positive.
`migrate-v2-reset.sh.bin` is blocked, which is the safe side for a never-list.

**Consequences:** a spelling genuinely continued by letters, digits, `_` or `-`
(`--force-with-lease` under a `--force` rule) is a different token and passes; pinning it
is the policy author's call. Non-ASCII patterns are warned about, not refused, so a future
reader that decodes them makes the warning obsolete rather than breaking policies.

### D-008 — Degradation is sticky and visible; the posture stays fail-open-loud

Every degradation notice (awk missing, an unparseable payload, a rule pattern grep cannot
evaluate, a value decoded lossily) uses the channel from D-005: `systemMessage` on Claude
Code, stderr elsewhere. A degradation also marks the session: later calls in the same
session (keyed by the payload's `session_id`) repeat the notice until the session ends;
markers expire after a week. A tool whose arguments herkos cannot read (UNCOVERED) is
reported on the user channel once per session and tool, and on stderr on every call.

**Why:** a degradation the user sees once, on one call, is forgotten; a sticky marker makes
the state follow the session. UNCOVERED is limited to once per session and tool because a
line on every call to such a tool is noise, and noise gets a guard muted. A value that
decodes lossily (non-ASCII characters dropped) is announced but still checked, because
every ASCII pattern still sees the ASCII text intact; switching the whole call off over one
non-ASCII character would give up real coverage for nothing.

**Consequences:** session markers live beside the blocked-call log, so a hook that writes
nothing (a committed project hook, or a user who turned the log off) announces on each call
but cannot be sticky: a hook committed to a repository must not write machine-local state.
The marker names the first reason recorded; a second reason is announced on its own call.

### D-009 — An exclusion that cannot be evaluated turns its rule off, loudly

A block rule's exclusion pattern (`notPaths`) is evaluated with the same care as its main
pattern: silenced, exit status checked, and an exit of 2 or more turns that one rule off
for the call with a sticky notice naming the rule. `validate` and `project init` also warn
when one command prefix's compiled pattern already covers another's in the same rule, and
`project init` names the one-time settings backup it takes.

**Why:** the exclusion is half of the rule's verdict, so an exclusion grep cannot evaluate
makes the rule unevaluable. Treating grep's error exit as "no match" would fire the rule as
if the exclusion did not exist, blocking exactly the harmless spellings it exists to spare
(such as `.env` templates), and false blocks are how a guard gets disabled. Turning the
rule off loudly matches D-004 and D-008. The overlap warning exists because the natural
policy shape (`./script` beside `script`) compiles to two lines where the second adds
nothing and an open rule prints the same notice twice. It is a warning, not an error: in
herkos, warnings inform and errors refuse, and a redundant prefix costs a duplicate line,
not safety.

**Consequences:** a policy with a broken exclusion leaves that rule announced and
unenforced instead of wrongly enforced. A policy that lists overlapping prefixes on purpose
is told so on every `validate`. Re-running `project init` over a registration the repo
edited replaces it with the stock hardened command; a repo that needs more re-applies its
edit after init.
