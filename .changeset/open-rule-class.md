---
"herkos": minor
---

Rules can now carry their own class label and a message, and a rule can be advisory instead of blocking. Until now the policy had two closed classes (`credential-read`, `fetched-exec`) and every rule blocked, so a real rule like "never push without asking" could only be filed as one of the two — a refusal that then lied about what it was. Three additions fix that:

- **Open class labels.** A rule's `class` is now any simple label (letters, digits, hyphens); `credential-read` and `fetched-exec` remain the curated baseline classes, exported as `BASELINE_CLASSES`. A user rule names its own class (`shared-checkout-git`, `outbound-data`, …) and the refusal and `status` show that label, not a stand-in.
- **A per-rule `message`.** A block rule appends its message to the refusal; it is the whole point of an open rule.
- **An `open` disposition.** `disposition: "open"` lets a matched call through and surfaces the rule's message to the session as `herkos NOTICE (rule <id>): <message>`, instead of blocking. It is advisory, never a wall and never a permission or allow-list — it grants nothing, so it stays inside the boundary. `block` stays the default and every baseline rule. When a call trips both an open and a block rule, the notice surfaces first and the block still wins.

`validate` requires an open rule to carry a message or description, rejects a disposition other than `block`/`open`, and rejects a multi-line or non-string message. `status` reports an open rule as an advisory notice, never among the blocking layers, and `rules` shows each rule's disposition and message. The policy fingerprint covers disposition and message, so changing either is drift the stamp detects. API: `RuleClass` is now `string`; new `Disposition` type and `BASELINE_CLASSES` export.
