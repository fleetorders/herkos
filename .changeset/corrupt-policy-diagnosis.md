---
"herkos": patch
---

A corrupt `~/.config/herkos/policy.json` no longer crashes herkos with an uncaught exception and a stack trace. The loader's message was always fine ("user policy at … is not valid JSON"); the delivery was not — `status`, `init`, `check`, `rules`, `validate`, `discover` and `probe` all called it unguarded, so a typo in the policy file surfaced as a crash instead of the diagnosis. Every command now loads the policy through one gate that prints the message as a single `herkos:` line and exits 1.
