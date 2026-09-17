---
"herkos": patch
---

Review residues from an independent read of a consumer install: a block rule's exclusion could flip verdicts silently, duplicate prefix spellings doubled notices, and several docs said less than they should.

- A block rule's exclusion regex (`notPaths`) was neither silenced nor status-checked in the generated hook. A broken exclusion dumped raw grep errors into the session with no framing, and worse, grep's exit ≥ 2 on the exclusion read as "does not match" — the rule then fired (or didn't) on its main pattern as if the carve-out did not exist, a silent verdict change. An unevaluable exclusion now rides the same degrade path as an unevaluable main pattern: that one rule is OFF for the call, announced with the rule named on the channel the session actually sees, sticky for the session, with no raw grep text.

- The generator bakes one notice/enforce line per command prefix, so a policy listing the same spelling twice — `scripts/deploy-lab.sh` beside `./scripts/deploy-lab.sh`, where the leading boundary class is satisfied by the slash of `./` — made every matching call print the identical notice twice on an open rule. `herkos validate` and `herkos project init` now warn when one prefix's generated pattern subsumes another's.

- The `commandPatterns` and `commandPrefixes` schema docs now say next to the ASCII requirement that both are single-line: command text is enforced line by line, so a pattern shaped to match across a line boundary is silently never-matching. And the notMatch example error says the call "would fire the rule" — true for a block rule (refused) and an open rule (noticed) alike.

- The one-time `.claude/settings.json.herkos-bak` backup `herkos project init` takes before first editing a repo's settings is now named in its output instead of being left silently, and a test pins that re-running init over a registration the repo hardened itself (fail-open guard, harness flag) still lands on a hardened command rather than the bare `sh` line.
