---
"herkos": minor
---

`herkos check` now runs an adversarial bypass corpus and reports a verdict per layer. A bare PASS proved the script runs, not that the never-list holds; the corpus attacks each baseline rule by other spellings — a glob in place of a key name, `cd` then a relative read, a symlink, a path built at run time, a vendor CLI reading the file itself, fetched code through `sudo`, process substitution or a `sh -c` string — alongside benign calls that must never be refused. Each case names the verdict the hook must return (measured on every run) and the native layer kinds that hold it when the hook cannot, as each harness documents them. `check` credits those layers only where `coverage()` reports them wired on this machine, and names every case no wired layer holds as UNGUARDED rather than hiding it. It fails on a regression, a refused benign call, or a hook error. The payloads live in a fixture file, `src/corpus/bypass.json`.

Found and closed by the corpus: the fetched-code rule now also refuses the download piped to `sudo sh` / `sudo -E bash`, run through process substitution (`bash <(curl …)`, `source <(curl …)`), or handed to `sh -c "$(curl …)"`. Recorded as known gaps no layer holds, because one text pattern cannot separate them from everyday use: downloading to a file and then running it, and piping a download to an interpreter such as `python3`.

Fixed: `check` ran its synthetic blocking payloads through a hook that writes the blocked-call log, so each run would have appended fake blocks to the user's record. Self-checks now generate the hook with the log off.

Rules gain optional `match` and `notMatch` example lists. `validate` runs each example through the rule with the hook's own evaluator and refuses to wire a rule that misses a `match` example or would refuse a `notMatch` one. `RuleCoverage` gains `kinds` (`hook`, `permission-deny`, `os-sandbox`, `prefix-rule`) and `HarnessAdapter` an optional `hookScope`.
