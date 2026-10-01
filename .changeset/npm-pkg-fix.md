---
"herkos": patch
---

The `bin` entry in package.json is written as `dist/cli.js` instead of `./dist/cli.js`, the form npm normalises it to. npm no longer warns on publish that the bin script name was cleaned.
