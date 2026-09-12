import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy, validatePolicy } = await import(
  "../src/policy.js"
);
const { claudeCodeAdapter, claudeDenyRules } = await import(
  "../src/adapters/claude-code.js"
);

const policyFile = path.join(cfg, "policy.json");
const writePolicy = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));

describe("credential reads compile into Claude Code permission deny rules", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  it("emits a Read() rule per baseline target, precise where the hook is", () => {
    const rules = claudeDenyRules(compile(loadEffectivePolicy()));
    expect(rules).toContain("Read(~/.ssh/id_*)");
    expect(rules).toContain("Read(~/.kube/config)");
    expect(rules).toContain("Read(**/.env)");
    // The whole SSH directory is NOT denied: known_hosts and config stay readable.
    expect(rules).not.toContain("Read(~/.ssh/**)");
  });

  it("never turns a command-shaped rule into a deny rule", () => {
    // Denying a command prefix such as curl would refuse every download.
    const rules = claudeDenyRules(compile(loadEffectivePolicy()));
    expect(rules.every((r) => r.startsWith("Read("))).toBe(true);
  });

  it("drops the targets of a rule disabled by id", () => {
    writePolicy({ disable: ["kube-config"] });
    const rules = claudeDenyRules(compile(loadEffectivePolicy()));
    expect(rules).not.toContain("Read(~/.kube/config)");
  });

  it("writes an absolute target in the double-slash form the harness requires", () => {
    writePolicy({
      rules: [
        {
          id: "vault-token",
          class: "credential-read",
          description: "vault token",
          paths: ["vault/token"],
          denyRead: ["/etc/vault/token"],
        },
      ],
    });
    // A single leading slash would be read relative to the settings file.
    expect(claudeDenyRules(compile(loadEffectivePolicy()))).toContain(
      "Read(//etc/vault/token)",
    );
  });

  it("derives targets from codexDeny when a user rule has no denyRead", () => {
    writePolicy({
      rules: [
        {
          id: "vault-dir",
          class: "credential-read",
          description: "vault dir",
          paths: ["vault/"],
          codexDeny: ["~/.vault", "**/vault.key"],
        },
      ],
    });
    const rules = claudeDenyRules(compile(loadEffectivePolicy()));
    // A home target may be a file or a directory; cover both.
    expect(rules).toContain("Read(~/.vault)");
    expect(rules).toContain("Read(~/.vault/**)");
    expect(rules).toContain("Read(**/vault.key)");
  });

  it("rejects a target that would break the rule syntax", () => {
    writePolicy({
      rules: [
        {
          id: "bad",
          class: "credential-read",
          description: "bad",
          paths: ["x"],
          denyRead: ["~/a)b", 7],
        },
      ],
    });
    const v = validatePolicy(loadEffectivePolicy());
    expect(
      v.errors.some((e) => e.includes("denyRead") && e.includes(")")),
    ).toBe(true);
    expect(
      v.errors.some(
        (e) => e.includes("denyRead") && e.includes("not a non-empty string"),
      ),
    ).toBe(true);
  });
});

describe("wiring the deny rules is reversible and never claims the user's own", () => {
  let box = "";
  let prev: string | undefined;
  let settingsFile = "";

  beforeEach(() => {
    box = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-deny-"));
    prev = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = box;
    settingsFile = path.join(box, "settings.json");
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.CLAUDE_CONFIG_DIR;
    else process.env.CLAUDE_CONFIG_DIR = prev;
    fs.rmSync(box, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  const read = (): {
    permissions?: { deny?: string[]; allow?: string[] };
    model?: string;
  } => JSON.parse(fs.readFileSync(settingsFile, "utf8"));

  it("adds the rules once, keeps the user's entries, and removes only its own", () => {
    fs.writeFileSync(
      settingsFile,
      JSON.stringify({
        model: "keep-me",
        permissions: {
          allow: ["Bash(git status)"],
          // The user already denies one of the baseline targets by hand.
          deny: ["Read(~/.kube/config)", "Bash(git push --force)"],
        },
      }),
    );
    const policy = compile(loadEffectivePolicy());
    claudeCodeAdapter.wire(policy);
    claudeCodeAdapter.wire(policy); // idempotent

    const after = read();
    const deny = after.permissions?.deny ?? [];
    for (const r of claudeDenyRules(policy)) {
      expect(deny.filter((d) => d === r)).toHaveLength(1);
    }
    expect(claudeCodeAdapter.verify().ok).toBe(true);

    claudeCodeAdapter.unwire();
    const back = read();
    expect(back.model).toBe("keep-me");
    expect(back.permissions?.allow).toEqual(["Bash(git status)"]);
    // The user's own identical entry survives; herkos never owned it.
    expect(back.permissions?.deny).toEqual([
      "Read(~/.kube/config)",
      "Bash(git push --force)",
    ]);
  });

  it("removes the permissions block entirely when herkos created it", () => {
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(read().permissions?.deny?.length).toBeGreaterThan(0);
    claudeCodeAdapter.unwire();
    expect(read().permissions).toBeUndefined();
  });

  it("withdraws the rules of a rule disabled after the first wiring", () => {
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(read().permissions?.deny).toContain("Read(~/.kube/config)");
    writePolicy({ disable: ["kube-config"] });
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(read().permissions?.deny).not.toContain("Read(~/.kube/config)");
    claudeCodeAdapter.unwire();
  });

  it("reports a hand-deleted deny rule as stale wiring", () => {
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    const s = read();
    s.permissions!.deny = s.permissions!.deny!.filter(
      (d) => d !== "Read(~/.ssh/id_*)",
    );
    fs.writeFileSync(settingsFile, JSON.stringify(s));
    const v = claudeCodeAdapter.verify();
    expect(v.ok).toBe(false);
    expect(v.state).toBe("stale");
    expect(v.detail).toContain("Read(~/.ssh/id_*)");
    claudeCodeAdapter.unwire();
  });
});
