---
"herkos": patch
---

Four long-standing rough edges, found in an independent read of the repo.
A hook path containing a space (a home directory with a space in it) no
longer reads as unwired: the registration check split words after
stripping quotes, tearing the quoted path in two — words are now split on
whitespace outside quotes first. A triple quote inside a comment or a
one-line string in Codex's config.toml is no longer read as opening a
multiline string, which hid every herkos table below it and made wire
write the table twice. The hook's selftest no longer pathname-expands
example tokens against your working directory (an example like
`cat secrets/*` expanded, the exclusion removed the expanded file names,
and a healthy rule reported as drifted). And a `notPaths` exclusion
anchored to the bare fragment — `paths: ["secrets/"]` with `notPaths:
["/$"]`, allowing `ls secrets/` while file reads still block — is no
longer refused as swallowing its own rule; the check now probes a token
that merely contains the fragment.
