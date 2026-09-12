---
"herkos": patch
---

`herkos probe` refuses a non-numeric `--budget-usd` or `--timeout` up front, with a one-line diagnosis and exit 1 before any harness is even detected. `Number("abc")` is NaN and `Math.max(0.01, NaN)` stays NaN, so the old parse printed a "$NaN" ceiling and passed a NaN timeout to the child — the spend ceiling the user thought they set was silently absent. An empty value (`--budget-usd ""`, which `Number` reads as 0) and zero or negative values are refused with the same message.
