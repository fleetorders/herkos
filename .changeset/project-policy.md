---
"herkos": minor
---

New `herkos project` — a per-repository never-list. A repo commits a `herkos.json` at its root declaring rules its contributors must never take (read `secrets/prod`, run the reset script), and `herkos project init` compiles it into the repo's Claude Code project layer: a self-contained hook checked in at `.claude/hooks/herkos-project.sh` and registered on `PreToolUse` in `.claude/settings.json` via `$CLAUDE_PROJECT_DIR`. Commit `.claude/` and every clone is guarded — even a contributor who has never installed herkos, because the hook needs only `sh`, `awk` and `grep`.

It composes, and it can only add. The project hook runs alongside each contributor's machine hook; Claude Code runs hooks from every settings level and any exit-2 blocks, so a repo's policy can only ADD refusals — it structurally cannot disable the machine's baseline. That is why `herkos.json` has no `disable` (validation rejects one, with a message). The committed hook carries the policy stamp, so `herkos project check` (for CI) exits non-zero on drift — someone edited `herkos.json` without re-running init. `herkos project uninstall` removes exactly what init added and leaves the user's own project settings intact.

The committed hook carries no machine-specific path — it names the repo-relative `herkos.json` — so it is clean to commit to a public repository. Claude Code only: Codex resolves config from `~/.codex` (global) plus `-c` overrides and `-p` profiles, with no repo-local layer, so a repo's Codex sessions rest on the machine policy rather than the repo's own list; herkos states that rather than pretend a per-repo Codex guard exists.

API: `loadProjectPolicy`, `validateProjectPolicy`, `projectPolicyPath`, `PROJECT_POLICY_FILE`, `ProjectPolicy`, and from a new `project` module `wireProject` / `unwireProject` / `verifyProject` / `compileProjectPolicy` / `validateRepoPolicy` / `projectHookPath` / `projectSettingsPath`.
