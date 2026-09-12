---
"herkos": minor
---

Codex: command rules that are genuinely prefixes now also compile into Codex's own execpolicy, as `forbidden` prefix rules in `$CODEX_HOME/rules/herkos.rules`. Codex loads that file at startup with no `/hooks` trust step, so those rules hold from the first session; until now every Codex command rule rode the hook, which does nothing until the user trusts it once. Rules gain an optional `commandPrefixes` list of argument tokens (program first); the baseline keychain-dump rule carries its four prefixes. A rule with prefixes but no `commandPatterns` has its hook patterns derived from the prefixes, so every harness still enforces it. A pipeline — fetched code piped to a shell — is not a prefix and stays with the hook.

herkos asks Codex to check the generated file (`codex execpolicy check`) before installing it: a file Codex refuses installs nothing, withdraws any earlier copy, and is reported by `init` and `status`; if the binary cannot run, the file is installed and marked unvalidated. Each rule carries its own prefix as a `match` example, which Codex verifies when it loads the file. `uninstall` removes the file, and the rules directory only if herkos created it and it is empty.

`status` now names, per harness, which layer holds each rule — for Codex the permission profile (OS deny), the execpolicy rules, and the hook (after trust); for Claude Code the permission deny rules and the hook — and lists any rule no layer holds as NOT enforced. Measured on codex-cli 0.154.0: the offline checker matches a program called by full path only when executables are resolved, and does not split a command inside `bash -lc`; the hook keeps covering both. `HarnessAdapter` gains an optional `coverage()`.
