---
"herkos": patch
---

Security: bump source-map-js 1.2.1 → 1.2.2 (clears GHSA-68fv-2mgg-jv7q, event-loop denial of service via indexed source-map offsets; dev-only chain via postcss). The two tinypool criticals (GHSA-5gmw-xhrv-c9v3, GHSA-85c8-ppgw-ccpr) are patched only in 2.1.2+ while vitest 4 pins `tinypool ^1.0.1` with no patched 1.x — npm's computed fix is vitest 5.0.3, a semver-major upgrade deliberately not taken in this patch.
