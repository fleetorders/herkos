---
"herkos": patch
---

A shell command whose text names a credential path — `rg '.aws/credentials' .`,
docs that mention `~/.ssh/id_` — is refused by the hook, and that refusal is now documented instead of silent. Command text is matched against the never-list's path fragments because that is how `cat ~/.ssh/id_rsa` is caught; text cannot reveal intent, and the file tools' search arguments are exempt by name (`Grep`'s `pattern` is free text) while a shell offers no such signal. The README names the trade-off under "Proof against other spellings", and the bypass corpus gains a `knownRefusal` marker: a benign case the hook is documented to refuse, which the run pins in BOTH directions — it fails if the hook stops refusing (the docs would be wrong) and reports the refusal as "a documented known refusal" rather than as a false alarm.
