# A never-list a repo commits (`herkos project`)

How a repository carries its own never-list for every contributor. Linked from the [README](../README.md).

The machine policy protects every session on your machine. A **project policy**
lets a repository carry its own never-list for every contributor — "never read
`secrets/prod`", "never run the reset script". Commit a `herkos.json` at the repo
root and run `herkos project init`:

```sh
herkos project init      # compile ./herkos.json into the repo's .claude project hook
herkos project check     # CI: fail if the committed hook drifted from herkos.json
```

It compiles the repo's rules into a **self-contained hook checked into the repo**
(`.claude/hooks/herkos-project.sh`, registered on `PreToolUse` in
`.claude/settings.json` via `$CLAUDE_PROJECT_DIR`). Commit `.claude/` and every
clone is guarded — **even a contributor who has never installed herkos**, because
the hook needs only `sh`, `awk` and `grep`.

Two properties keep it safe:

- **It composes; it can only add.** The project hook runs _alongside_ each
  contributor's machine hook — Claude Code runs hooks from every settings level
  and any refusal blocks — so a repo's policy can only _add_ to the machine's
  never-list, never weaken it. That's why `herkos.json` has no `disable`
  (herkos rejects one). A checked-out repo can't turn your protection off.
- **It carries nothing machine-specific.** The committed hook names the
  repo-relative `herkos.json`, no home path — clean to commit to a public repo.
  It carries the policy stamp, so `herkos project check` in CI fails when someone
  edits `herkos.json` without re-running init.

A `herkos.json` at the repo root (the file is strict JSON — comments are not
valid in it, so a copy of this example works as-is):

```json
{
  "rules": [
    {
      "id": "no-prod-secrets",
      "class": "credential-read",
      "description": "the repo's production secrets",
      "paths": ["secrets/prod/"]
    },
    {
      "id": "no-reset-script",
      "class": "command-never",
      "description": "the destructive reset script",
      "commandPrefixes": [["./scripts/reset-db.sh"]]
    }
  ]
}
```

`commandPrefixes` is a list of prefixes, each prefix itself a list of tokens
with the program first: `[["git", "push"]]` refuses every `git push …`, and a
one-token prefix like the one above refuses that script however it is invoked.
A flat list (`["git", "push"]`) is rejected at `init` with the rule's id — the
nesting is what says "these tokens, in order, as one command".

**Claude Code only.** Codex resolves config from `~/.codex` with no repo-local
layer, so a repo's Codex sessions rest on the machine policy, not the repo's own
list — herkos says so rather than pretend a per-repo Codex guard exists.

**Blocked-call log (optional).** A committed hook logs nothing by default — a
stranger's clone must not be dirtied. `herkos.json` may set
`"logFile": "herkos-blocks.jsonl"`: every refusal then appends one JSON line
(time, harness, tool, rule — never the command text) to that file, resolved at
run time against the hook's own directory, so any clone or linked worktree
logs beside its own hook rather than a path baked on one machine. Gitignore
the file (and the `sessions/` state dir beside it); `herkos project check`
names it in CI when you haven't.
