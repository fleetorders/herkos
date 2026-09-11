---
"herkos": patch
---

Three validation and labelling corrections:

- The `macos-keychain` baseline rule is now classed `credential-read`, which is what it is — dumping or exporting what the keychain holds. It was filed under `fetched-exec` since inception, so refusals and the session-start line grouped it with pipe-to-shell rules; the label is display and grouping only, and matching is unchanged.
- `validate` refuses a `:` in a `denyRead` / `codexDeny` target. Parentheses were already rejected because they would break the generated `Read(...)` rule; `:` is meaningful in the same permission-rule syntax (`Bash(curl:*)` spells its specifier after one), and unlike a regex there is no offline evaluator to prove a colon harmless — so, in the validator's usual stance, an unprovable character is refused rather than risk a corrupted deny rule.
- `validate` refuses a multi-line `id` or `description`. Both are safely shell-quoted so they could never break the generated script, but they print multi-line refusal and notice lines; the messages that reject them stay single-line themselves.
