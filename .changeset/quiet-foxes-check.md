---
"herkos": patch
---

Four edge cases found in review of the open-rule and degradation work:

- `herkos check` could report success for a rule that runs with enforcement off. The hook's `--selftest` read a pattern or exclusion that grep cannot evaluate as "no match", so every `notMatch` example passed. It now fails the selftest and names the rule and whether the pattern or the exclusion is at fault.
- Session markers written for uncovered tools were never expired; only a degradation removed markers older than a week. Both kinds of marker now expire the same way.
- The duplicate-prefix warning launched one `grep` for every ordered pair of a rule's command prefixes. It now launches one per prefix, and a rule with more than 200 prefixes gets a warning that the check was skipped.
- The project hook registration accepted any readable file at the hook path, including a named pipe, which made every tool call wait forever. It now requires a regular file and otherwise degrades open, as it already did for a missing file.
