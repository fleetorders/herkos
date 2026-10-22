---
"herkos": patch
---

Dev dependencies: vitest 2 → 5 (with vite 8 as its peer) and tsup 8.3.5 → 8.5.1. Clears the npm audit criticals in tinypool (GHSA-5gmw-xhrv-c9v3, GHSA-85c8-ppgw-ccpr) and shell-quote, the highs in vite, launch-editor (GHSA-587h-7wmj-h5pm) and source-map-js (GHSA-68fv-2mgg-jv7q), and the esbuild moderates. Test and build tooling only; nothing in the shipped package changes.
