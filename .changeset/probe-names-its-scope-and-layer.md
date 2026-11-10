---
"herkos": patch
---

The live probe now says what it actually does and measures, instead of implying more. Two honest statements were missing. The headless mode the probe runs in (`--dangerously-skip-permissions` on Claude Code) grants the agent **full tool access for that one turn** — the decoy bounds what the agent is asked to do, not what it can do, and the budget and timeout bound cost and time, not reach; the confirmation text, the module docs and the README all say so now. And because the decoy sits in a throwaway directory, the probe measures the **hook layer** specifically — home-anchored native layers (deny rules, the OS sandbox, Codex's permission profile) never see the decoy's path — so the per-run report now names the hook as the layer measured and points at `herkos check` for the native layers, where the old note read as proof that "a block" in general fires.
