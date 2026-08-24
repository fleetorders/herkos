---
"herkos": patch
---

Security: bump vitest 2.1.8 → 2.1.9 (clears GHSA-9crc-q9x8-hgqq, RCE via the Vitest API server; vite transitively to 5.4.21). Remaining advisories (GHSA-5xrq-8626-4rwp critical, vite highs ≤6.4.2) require a semver-major vitest bump — parked for owner review.
