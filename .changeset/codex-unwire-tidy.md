---
"herkos": patch
---

`herkos uninstall` no longer leaves an empty hooks skeleton in Codex's `hooks.json`. Unwire used to write back `{"hooks":{"PreToolUse":[]}}` even when every entry was ours; now an emptied event key is dropped, an emptied `hooks` wrapper is dropped, and a file that held nothing but herkos's registration — `wire` creates it when absent — is removed, restoring the pre-herkos state exactly. Foreign hook entries survive untouched, and an unreadable `hooks.json` is left alone rather than crashed on.

The backup policy is now the same across both adapters and documented: each adapter keeps the one pre-herkos backup it took before first editing a config file (`settings.json.herkos-bak`, `config.toml.herkos-bak`, `hooks.json.herkos-bak`) — never overwritten, and left in place by `uninstall`, because deleting the recovery copy exactly when you might want it is the wrong moment. The README's new "Removing it" section says so.
