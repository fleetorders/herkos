import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { claudeCodeAdapter, claudeSandboxCredentialFiles } = await import(
  "../src/adapters/claude-code.js"
);

const policyFile = path.join(cfg, "policy.json");
const SANDBOX = "OS sandbox for shell commands";

interface Settings {
  sandbox?: {
    enabled?: boolean;
    credentials?: {
      files?: { path: string; mode: string }[];
      envVars?: unknown[];
    };
  };
}

describe("credential paths for the OS sandbox", () => {
  afterEach(() => fs.rmSync(policyFile, { force: true }));

  it("takes concrete home paths, turns a trailing /** into its directory, and leaves other globs to the merged deny rules", () => {
    const files = claudeSandboxCredentialFiles(compile(loadEffectivePolicy()));
    expect(files).toContain("~/.kube/config");
    expect(files).toContain("~/.config/gcloud");
    expect(files).toContain("~/.gnupg/private-keys-v1.d");
    expect(files.some((f) => /[*?]/.test(f))).toBe(false);
    // Workspace globs are not paths the sandbox list can hold.
    expect(files.some((f) => f.includes(".env"))).toBe(false);
  });

  it("keeps an absolute target absolute and leaves a relative one out", () => {
    fs.writeFileSync(
      policyFile,
      JSON.stringify({
        rules: [
          {
            id: "vault",
            class: "credential-read",
            description: "vault",
            paths: ["vault/"],
            denyRead: ["/etc/vault/token", "secrets/prod.key"],
          },
        ],
      }),
    );
    const files = claudeSandboxCredentialFiles(compile(loadEffectivePolicy()));
    expect(files).toContain("/etc/vault/token");
    expect(files).not.toContain("secrets/prod.key");
  });
});

describe("wiring the sandbox credential list", () => {
  let box = "";
  let prev: string | undefined;
  let sp = "";

  beforeEach(() => {
    box = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-sb-"));
    prev = process.env.CLAUDE_CONFIG_DIR;
    process.env.CLAUDE_CONFIG_DIR = box;
    sp = path.join(box, "settings.json");
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.CLAUDE_CONFIG_DIR;
    else process.env.CLAUDE_CONFIG_DIR = prev;
    fs.rmSync(box, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  const read = (): Settings => JSON.parse(fs.readFileSync(sp, "utf8"));

  it("adds deny entries without ever switching the sandbox on, and says it is off", () => {
    const r = claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    const s = read();
    expect(s.sandbox?.enabled).toBeUndefined();
    expect(s.sandbox?.credentials?.files).toContainEqual({
      path: "~/.kube/config",
      mode: "deny",
    });
    expect(r.detail).toContain("OFF");
    const v = claudeCodeAdapter.verify();
    expect(v.ok).toBe(true);
    expect(v.detail).toContain("not enabled");
    const cov = claudeCodeAdapter.coverage!(compile(loadEffectivePolicy()));
    expect(cov.find((c) => c.rule === "kube-config")!.layers).not.toContain(
      SANDBOX,
    );
    claudeCodeAdapter.unwire();
    expect(read().sandbox).toBeUndefined();
  });

  it("names the sandbox as the strongest layer when the user has it on, and leaves `enabled` on uninstall", () => {
    fs.writeFileSync(sp, JSON.stringify({ sandbox: { enabled: true } }));
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    const cov = claudeCodeAdapter.coverage!(compile(loadEffectivePolicy()));
    expect(cov.find((c) => c.rule === "kube-config")!.layers[0]).toBe(SANDBOX);
    // A glob-only rule reaches the sandbox through the merged Read deny rules.
    expect(cov.find((c) => c.rule === "ssh-private-keys")!.layers).toContain(
      SANDBOX,
    );
    // A command rule has no file to deny.
    expect(cov.find((c) => c.rule === "curl-pipe-shell")!.layers).not.toContain(
      SANDBOX,
    );
    expect(claudeCodeAdapter.verify().detail).toContain("OS sandbox on");
    claudeCodeAdapter.unwire();
    expect(read().sandbox).toEqual({ enabled: true });
  });

  it("never overrides the user's own entry for a path, whatever its mode", () => {
    const mine = {
      sandbox: {
        credentials: {
          files: [{ path: "~/.kube/config", mode: "mask" }],
          envVars: [{ name: "X", mode: "deny" }],
        },
      },
    };
    fs.writeFileSync(sp, JSON.stringify(mine));
    const policy = compile(loadEffectivePolicy());
    claudeCodeAdapter.wire(policy);
    claudeCodeAdapter.wire(policy); // idempotent
    const files = read().sandbox!.credentials!.files!;
    expect(files.filter((f) => f.path === "~/.kube/config")).toEqual([
      { path: "~/.kube/config", mode: "mask" },
    ]);
    for (const p of claudeSandboxCredentialFiles(policy)) {
      expect(files.filter((f) => f.path === p)).toHaveLength(1);
    }
    claudeCodeAdapter.unwire();
    expect(read().sandbox).toEqual(mine.sandbox);
  });

  it("reports a hand-deleted credential entry as stale", () => {
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    const s = read();
    s.sandbox!.credentials!.files = s.sandbox!.credentials!.files!.filter(
      (f) => f.path !== "~/.kube/config",
    );
    fs.writeFileSync(sp, JSON.stringify(s));
    const v = claudeCodeAdapter.verify();
    expect(v.state).toBe("stale");
    expect(v.detail).toContain("~/.kube/config");
    claudeCodeAdapter.unwire();
  });

  it("withdraws the entries of a rule disabled later", () => {
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    fs.writeFileSync(policyFile, JSON.stringify({ disable: ["kube-config"] }));
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(
      read().sandbox!.credentials!.files!.some(
        (f) => f.path === "~/.kube/config",
      ),
    ).toBe(false);
    claudeCodeAdapter.unwire();
  });
});
