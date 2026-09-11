---
"herkos": minor
---

The enforcement hook no longer needs `jq`. It parsed every tool call with jq, so a machine or container image without it announced "enforcement OFF" on every call — installed, present, and doing nothing — which contradicted the project's own rule that the enforcement path depends on nothing. The hook now reads the payload in one pass with a JSON extractor written in POSIX awk, which every such system and minimal image already ships (BusyBox included), beside the `sh` and `grep` it already used. There is no jq fallback: one parser cannot disagree with another.

The extractor reads every string under a command- or path-shaped key at any depth, one array element at a time, every copy of a duplicated key (a last-value-wins parser sees only the final one), and decodes `\uXXXX` escapes in keys and values, so an escaped spelling of a fragment is no way around a rule. Text that merely looks like JSON inside a string is never taken for structure, and each line of a multi-line command is checked. It skips values no rule reads without copying them, so a megabyte of file content adds no noticeable latency.

A payload that cannot be read — malformed, truncated, empty, or without a tool name — is now announced as `herkos DEGRADED` after whatever was read has been checked, instead of passing in silence as it did before. `init` and `check` warn about a missing `awk` instead of a missing `jq`. API: `jqAvailable()` is replaced by `awkAvailable()`, the self-check result's `jq` field by `awk`, and the extractor is exported as `EXTRACT_AWK`.
