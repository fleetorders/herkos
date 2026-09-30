# Proof against other spellings

What `herkos check` measures beyond "the hook runs", and how rule examples are checked. Linked from the [README](../README.md).

A PASS that only shows the script runs proves little. `herkos check` also runs a
**bypass corpus**: each baseline rule attacked by other spellings — a glob in
place of a file name, a `cd` then a relative read, a symlink, a path built at run
time, a vendor CLI reading the file itself, fetched code through `sudo` or
process substitution — plus benign calls that must never be refused. For every
case it measures the hook's verdict, credits the native layers (deny rules, OS
sandbox, prefix rules) only where they are wired on your machine, and names each
case nothing wired holds as **UNGUARDED**. Two gaps are recorded rather than
papered over, because one text pattern cannot tell them from everyday use:
downloading a script to a file and then running it, and piping a download to an
interpreter.

One class of refusal is **documented rather than fixed**: a shell command whose
_text_ names a credential path. `rg '.aws/credentials' .`, documentation that
mentions `~/.ssh/id_`, an echo of such a label — all refused, because the hook
matches Bash command text against the never-list's path fragments (that is also
how `cat ~/.ssh/id_rsa` is caught) and text cannot reveal intent: the same
string is a search term in one command and a file read in the next. The file
tools' search arguments are exempt by name — a `Grep` pattern is free text —
but inside a shell there is no such signal, and refusing is the safe side. The
corpus carries this as a known-refusal case, so the behavior stays pinned and
named, never silent.

Your own rules can carry examples, which `validate` runs with the hook's own
evaluator before anything is wired — and the generated hook re-checks the same
examples itself: `--selftest` (run by `herkos check`) fails if a baked rule no
longer behaves as its examples say:

```json
{
  "id": "no-force-push",
  "class": "fetched-exec",
  "description": "Force-pushing over shared history",
  "commandPrefixes": [["git", "push", "--force"]],
  "match": ["git push --force origin main"],
  "notMatch": ["git push origin main", "git push --force-with-lease"]
}
```

One semantics note on `commandPrefixes`, because the name under-sells what the
hook does: each spelling compiles to a bounded **token** match, not an anchored
prefix. It fires wherever the tokens stand as whole shell tokens in the line —
`bin/deploy.sh` also catches `sh bin/deploy.sh` and `./bin/deploy.sh`, and
`ls <token>` is not exempt. A harness-native prefix layer (Codex execpolicy)
reads them as true program prefixes; the hook is deliberately wider so a
called-by-path or wrapped invocation cannot dodge the rule.
