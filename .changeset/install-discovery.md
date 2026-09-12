---
"herkos": minor
---

New `herkos discover`: it names credential-shaped files that exist on this machine but are not on your never-list, and offers to add each. A baseline of generic conventions cannot know this machine has a `~/.pgpass`, a `~/.config/gh/hosts.yml` or a `~/.git-credentials`; discovery finds those and proposes a rule for each. It is the one thing herkos does that a harness default cannot.

Paths only — a credential file's contents are never read. Discovery checks that a file exists (`lstat`, so a credential-shaped dangling symlink is still named and never followed) and reports its path; reading a credential file to decide whether to protect it would be the exact exposure it exists to prevent. The catalogue is generic conventions (git-credentials, GitHub CLI, PostgreSQL, MySQL, Google Cloud ADC, Terraform, Cargo, RubyGems, PyPI, rclone, s3cmd, Oracle Cloud, Databricks, DigitalOcean); the result is machine-specific and goes only into the user policy, never the baseline or any tracked file.

On a terminal it prompts once per candidate (`y`/`N`/`a` for all/`q` to quit); unattended it lists the findings and the exact `herkos discover --add <ids>` command to add them without blocking on input. Added rules are appended to the user policy, preserving what is there, skipping any already present, and the command names `herkos init` to compile them.
