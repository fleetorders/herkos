---
"herkos": patch
---

Security: bump shell-quote 1.10.0 → 1.12.0 (clears GHSA-pqg4-j6r4-53mv, `quote()` command injection via a line terminator in a token after a `{ comment }` token; dev-only chain via @changesets/cli → launch-editor, lockfile-only change). The remaining audit items (tinypool criticals, the vite/@vitest/mocker and esbuild chains) all resolve through a vitest 4 → 5 semver-major upgrade, deliberately not taken in this patch.
