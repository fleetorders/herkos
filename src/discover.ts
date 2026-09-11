/**
 * Install-time discovery: name credential-shaped files that exist on THIS
 * machine and are not yet on the never-list, and offer to add each.
 *
 * This is the one thing herkos does that a harness default cannot: a baseline
 * of generic conventions cannot know that this machine has a `~/.pgpass` or a
 * `~/.config/gh/hosts.yml`. Discovery finds those and proposes a rule for each,
 * one keypress to add.
 *
 * Two hard rules:
 * - PATHS ONLY, NEVER CONTENTS. Discovery checks that a file exists and reports
 *   its path. It never opens a credential file — reading one to decide whether
 *   to protect it would be the exact exposure it exists to prevent.
 * - The catalogue is generic conventions (safe to ship); the RESULT is
 *   machine-specific and goes only into the user's own policy, never the
 *   baseline and never a tracked file.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { EffectivePolicy, Rule, UserPolicy } from "./policy.js";
import { userPolicyPath } from "./policy.js";

/**
 * A credential-shaped location herkos knows by convention. `probe` is the path,
 * relative to home, whose existence makes this candidate real on a machine; the
 * rule it proposes protects it (and its siblings, where a directory holds more
 * than one secret file).
 */
export interface Candidate {
  /** Path under the home directory whose existence triggers the offer. */
  probe: string;
  /** One line naming what the file holds — shown to the user, no contents. */
  what: string;
  /** The rule added to the user policy when the candidate is accepted. */
  rule: Rule;
}

/**
 * The catalogue. Generic, credential-shaped locations that are NOT in the
 * baseline (the baseline already covers SSH keys, cloud credentials, kube
 * config, .env files, .netrc/.npmrc/.pypirc, GnuPG, Docker and the keychain).
 * Grown by convention, never from any real machine's contents.
 */
export const CANDIDATES: Candidate[] = [
  {
    probe: ".git-credentials",
    what: "git stored credentials (HTTPS tokens in plain text)",
    rule: {
      id: "git-credentials",
      class: "credential-read",
      description: "git stored credentials file",
      paths: [".git-credentials"],
      codexDeny: ["~/.git-credentials"],
      denyRead: ["~/.git-credentials"],
    },
  },
  {
    probe: ".config/gh/hosts.yml",
    what: "GitHub CLI OAuth tokens",
    rule: {
      id: "gh-cli-hosts",
      class: "credential-read",
      description: "GitHub CLI host tokens",
      paths: [".config/gh/hosts.yml"],
      codexDeny: ["~/.config/gh/hosts.yml"],
      denyRead: ["~/.config/gh/hosts.yml"],
    },
  },
  {
    probe: ".pgpass",
    what: "PostgreSQL password file",
    rule: {
      id: "pgpass",
      class: "credential-read",
      description: "PostgreSQL password file",
      paths: [".pgpass"],
      codexDeny: ["~/.pgpass"],
      denyRead: ["~/.pgpass"],
    },
  },
  {
    probe: ".my.cnf",
    what: "MySQL client password file",
    rule: {
      id: "mysql-cnf",
      class: "credential-read",
      description: "MySQL client config (may hold a password)",
      paths: [".my.cnf"],
      codexDeny: ["~/.my.cnf"],
      denyRead: ["~/.my.cnf"],
    },
  },
  {
    probe: ".config/gcloud/application_default_credentials.json",
    what: "Google Cloud application-default credentials",
    rule: {
      id: "gcloud-adc",
      class: "credential-read",
      description: "Google Cloud application-default credentials",
      paths: [".config/gcloud/application_default_credentials"],
      codexDeny: ["~/.config/gcloud/application_default_credentials.json"],
      denyRead: ["~/.config/gcloud/application_default_credentials.json"],
    },
  },
  {
    probe: ".terraform.d/credentials.tfrc.json",
    what: "Terraform Cloud API token",
    rule: {
      id: "terraform-credentials",
      class: "credential-read",
      description: "Terraform Cloud credentials",
      paths: [".terraform.d/credentials"],
      codexDeny: ["~/.terraform.d/credentials.tfrc.json"],
      denyRead: ["~/.terraform.d/credentials.tfrc.json"],
    },
  },
  {
    probe: ".cargo/credentials.toml",
    what: "Cargo (crates.io) registry token",
    rule: {
      id: "cargo-credentials",
      class: "credential-read",
      description: "Cargo registry credentials",
      paths: [".cargo/credentials"],
      codexDeny: ["~/.cargo/credentials.toml", "~/.cargo/credentials"],
      denyRead: ["~/.cargo/credentials.toml", "~/.cargo/credentials"],
    },
  },
  {
    probe: ".gem/credentials",
    what: "RubyGems API key",
    rule: {
      id: "rubygems-credentials",
      class: "credential-read",
      description: "RubyGems credentials",
      paths: [".gem/credentials"],
      codexDeny: ["~/.gem/credentials"],
      denyRead: ["~/.gem/credentials"],
    },
  },
  {
    probe: ".pypirc",
    what: "PyPI upload token",
    rule: {
      id: "pypirc-home",
      class: "credential-read",
      description: "PyPI upload credentials",
      paths: [".pypirc"],
      codexDeny: ["~/.pypirc"],
      denyRead: ["~/.pypirc"],
    },
  },
  {
    probe: ".config/rclone/rclone.conf",
    what: "rclone remote tokens",
    rule: {
      id: "rclone-conf",
      class: "credential-read",
      description: "rclone remote credentials",
      paths: [".config/rclone/rclone.conf", ".rclone.conf"],
      codexDeny: ["~/.config/rclone/rclone.conf", "~/.rclone.conf"],
      denyRead: ["~/.config/rclone/rclone.conf", "~/.rclone.conf"],
    },
  },
  {
    probe: ".s3cfg",
    what: "s3cmd access keys",
    rule: {
      id: "s3cfg",
      class: "credential-read",
      description: "s3cmd credentials",
      paths: [".s3cfg"],
      codexDeny: ["~/.s3cfg"],
      denyRead: ["~/.s3cfg"],
    },
  },
  {
    probe: ".oci/config",
    what: "Oracle Cloud API config and key",
    rule: {
      id: "oci-config",
      class: "credential-read",
      description: "Oracle Cloud Infrastructure credentials",
      paths: [".oci/config", ".oci/oci_api_key"],
      codexDeny: ["~/.oci"],
      denyRead: ["~/.oci/config", "~/.oci/*_key.pem", "~/.oci/oci_api_key*"],
    },
  },
  {
    probe: ".databricks/token",
    what: "Databricks personal access token",
    rule: {
      id: "databricks-token",
      class: "credential-read",
      description: "Databricks token",
      paths: [".databrickscfg", ".databricks/token"],
      codexDeny: ["~/.databrickscfg", "~/.databricks/token"],
      denyRead: ["~/.databrickscfg", "~/.databricks/token"],
    },
  },
  {
    probe: ".config/doctl/config.yaml",
    what: "DigitalOcean API token",
    rule: {
      id: "doctl-config",
      class: "credential-read",
      description: "DigitalOcean CLI credentials",
      paths: [".config/doctl/config.yaml"],
      codexDeny: ["~/.config/doctl/config.yaml"],
      denyRead: ["~/.config/doctl/config.yaml"],
    },
  },
];

/**
 * Is a candidate already covered by an effective rule? Reuses the hook's own
 * substring semantics: a rule with a path fragment F covers this candidate when
 * F appears in one of the candidate's own path fragments (so the baseline
 * `.pypirc` covers the `.pypirc` candidate), or the candidate id is already a
 * rule id.
 */
function isCovered(candidate: Candidate, effective: EffectivePolicy): boolean {
  if (effective.rules.some((r) => r.id === candidate.rule.id)) return true;
  const mine = candidate.rule.paths ?? [];
  for (const r of effective.rules) {
    for (const frag of r.paths ?? []) {
      if (mine.some((m) => m.includes(frag) || frag.includes(m))) return true;
    }
  }
  return false;
}

export interface Discovery {
  candidate: Candidate;
  /** The absolute path found (for display only — never read). */
  foundAt: string;
}

/**
 * Candidate credential files that EXIST on this machine and are not yet covered.
 * Existence only: `lstatSync` is the strongest thing touched — no file is ever
 * opened. `home` is injectable for testing; production passes the real home.
 */
export function discoverCandidates(
  effective: EffectivePolicy,
  home: string = os.homedir(),
): Discovery[] {
  const out: Discovery[] = [];
  for (const candidate of CANDIDATES) {
    if (isCovered(candidate, effective)) continue;
    const p = path.join(home, candidate.probe);
    let exists = false;
    try {
      // lstat, not stat: a dangling symlink shaped like a credential file is
      // still worth naming, and we never follow it to its target's contents.
      fs.lstatSync(p);
      exists = true;
    } catch {
      exists = false;
    }
    if (exists) out.push({ candidate, foundAt: p });
  }
  return out;
}

export interface AddResult {
  added: string[];
  /** Ids asked for that were not offered candidates (already covered, or unknown). */
  skipped: string[];
  policyPath: string;
}

/**
 * Add the chosen candidates' rules to the user policy file, preserving whatever
 * is already there. Only rules the machine actually has and that are not yet
 * covered are added; an unknown or already-present id is skipped, not an error.
 * Never writes a rule the user already has.
 */
export function addCandidatesToUserPolicy(
  ids: string[],
  effective: EffectivePolicy,
  home: string = os.homedir(),
): AddResult {
  const available = new Map(
    discoverCandidates(effective, home).map((d) => [d.candidate.rule.id, d]),
  );
  const p = userPolicyPath();
  let policy: UserPolicy = {};
  if (fs.existsSync(p)) {
    policy = JSON.parse(fs.readFileSync(p, "utf8")) as UserPolicy;
  }
  const rules = policy.rules ?? [];
  const added: string[] = [];
  const skipped: string[] = [];
  for (const id of ids) {
    const d = available.get(id);
    if (!d || rules.some((r) => r.id === id)) {
      skipped.push(id);
      continue;
    }
    rules.push(d.candidate.rule);
    added.push(id);
  }
  if (added.length > 0) {
    policy.rules = rules;
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(policy, null, 2) + "\n");
  }
  return { added, skipped, policyPath: p };
}
