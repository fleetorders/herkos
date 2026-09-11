---
"herkos": minor
---

The `dotenv-files` baseline rule no longer refuses the committed placeholder templates. `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are read and written in everyday work and convention holds them secret-free — blocking them was the most user-visible false alarm in the baseline, and a false alarm in a default rule is what teaches users to disable the guard (D-003).

Rules gain a `notPaths` list: extended regexes that UN-match. A path (or command text) that matches a rule's `notPaths` never fires that rule, even when its `paths` fragment does. The dotenv rule excludes exactly the template suffixes at the end of the value, so a secret variant beside a template in one command still blocks. `validate` checks `notPaths` with the evaluator itself (like `commandPatterns`), honors exclusions when running a rule's `match`/`notMatch` examples, and the policy fingerprint covers them, so a changed exclusion is drift the wiring stamp detects.

The harness-native deny layers (Claude Code `permissions.deny` and its sandbox, Codex's permission profile) take gitignore-style globs, which cannot say "everything except the templates" — so their broad `**/.env.*` is replaced with the enumerated conventional variants (`.env`, `.env.local`, the framework-documented per-environment files and their `.local` composites, the common short spellings). An unconventional secret variant such as `.env.standby` is no longer held by those layers; the hook still blocks it, because its fragment matcher was narrowed by exclusion, not enumeration. A benign corpus case pins the template so it cannot regress.
