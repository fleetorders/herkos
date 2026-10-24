---
"herkos": patch
---

Two long-standing rough edges, recovered from a review branch that never published. `herkos status` and `herkos uninstall` no longer crash on a corrupt harness settings file: verify reports it as a diagnosis (state `broken`, with the parse error and what to do), and uninstall still removes everything herkos owns — hook file, snapshot, ownership record — while naming the settings file it could not clean until you fix it. And policy validation refuses a `notPaths` exclusion that swallows the rule's own path fragment: `notPaths: ["."]` used to pass every other check and silently turn the rule off; now it is named as the error it is.
