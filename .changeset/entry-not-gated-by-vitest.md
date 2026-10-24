---
"herkos": patch
---

The published binary no longer checks a test runner's variable to decide whether to run. `program.parse()` was gated on `process.env.VITEST` inside the shipped entry, so anyone with that variable exported — a shell profile, a CI job, a repo's `.envrc` — got a security tool that silently did nothing (`VITEST=1 herkos status` printed no output and exited 0). argv parsing now lives in a thin entry file (`bin.ts` → `dist/bin.js`, what the package's `bin` field points at); `cli.ts` stays importable for the command bodies and never parses argv.
