import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { loadEffectivePolicy, loadValidatedPolicy, validatePolicy, compile } =
  await import("../src/policy.js");
const {
  CANDIDATES,
  discoverCandidates,
  addCandidatesToUserPolicy,
  discoverCommand,
} = await import("../src/discover.js");

const policyFile = path.join(cfg, "policy.json");

describe("the candidate catalogue is generic and valid", () => {
  it("proposes no rule the baseline already covers, and every rule validates", () => {
    const baseline = loadEffectivePolicy();
    for (const c of CANDIDATES) {
      expect(baseline.rules.some((r) => r.id === c.rule.id)).toBe(false);
    }
    // The catalogue, treated as a user policy, must pass validation as written.
    fs.writeFileSync(
      policyFile,
      JSON.stringify({ rules: CANDIDATES.map((c) => c.rule) }),
    );
    try {
      expect(validatePolicy(loadEffectivePolicy()).errors).toEqual([]);
    } finally {
      fs.rmSync(policyFile, { force: true });
    }
  });

  it("names only home-relative probe paths (nothing machine-specific)", () => {
    for (const c of CANDIDATES) {
      expect(c.probe.startsWith("/")).toBe(false);
      expect(c.probe.startsWith("~")).toBe(false);
    }
  });
});

describe("discovery finds what exists and is uncovered", () => {
  let home = "";
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-home-"));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  const plant = (rel: string, body = "secret"): string => {
    const p = path.join(home, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
    return p;
  };

  it("reports a planted credential file by path, and none that is absent", () => {
    const at = plant(".pgpass", "localhost:5432:db:user:PASSWORD");
    const found = discoverCandidates(loadEffectivePolicy(), home);
    const ids = found.map((d) => d.candidate.rule.id);
    expect(ids).toContain("pgpass");
    expect(ids).not.toContain("git-credentials"); // not planted
    expect(found.find((d) => d.candidate.rule.id === "pgpass")!.foundAt).toBe(
      at,
    );
  });

  it("does not offer a candidate the user has already added", () => {
    plant(".git-credentials");
    fs.writeFileSync(
      policyFile,
      JSON.stringify({
        rules: [
          {
            id: "git-credentials",
            class: "credential-read",
            description: "mine",
            paths: [".git-credentials"],
          },
        ],
      }),
    );
    const ids = discoverCandidates(loadEffectivePolicy(), home).map(
      (d) => d.candidate.rule.id,
    );
    expect(ids).not.toContain("git-credentials");
  });

  it("finds a dangling symlink shaped like a credential file, without following it", () => {
    fs.symlinkSync("/nowhere/secret", path.join(home, ".s3cfg"));
    const ids = discoverCandidates(loadEffectivePolicy(), home).map(
      (d) => d.candidate.rule.id,
    );
    expect(ids).toContain("s3cfg");
  });

  it("returns nothing on a home with no credential-shaped files", () => {
    expect(discoverCandidates(loadEffectivePolicy(), home)).toEqual([]);
  });
});

describe("adding discovered candidates to the user policy", () => {
  let home = "";
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-home-"));
    fs.mkdirSync(path.join(home, ".config", "gh"), { recursive: true });
    fs.writeFileSync(path.join(home, ".config", "gh", "hosts.yml"), "token");
    fs.writeFileSync(path.join(home, ".pgpass"), "pw");
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  it("writes only the chosen rules, and the result compiles and validates", () => {
    const r = addCandidatesToUserPolicy(
      ["pgpass", "gh-cli-hosts"],
      loadEffectivePolicy(),
      home,
    );
    expect(r.added.sort()).toEqual(["gh-cli-hosts", "pgpass"]);
    const eff = loadValidatedPolicy();
    expect(eff.rules.some((x) => x.id === "pgpass")).toBe(true);
    const compiled = compile(eff);
    expect(compiled.pathRegex).toContain(".pgpass");
  });

  it("skips an id that is unknown or not present on the machine, without failing", () => {
    const r = addCandidatesToUserPolicy(
      ["pgpass", "not-a-real-id", "git-credentials"],
      loadEffectivePolicy(),
      home,
    );
    expect(r.added).toEqual(["pgpass"]);
    expect(r.skipped.sort()).toEqual(["git-credentials", "not-a-real-id"]);
  });

  it("is idempotent: adding the same id twice does not duplicate the rule", () => {
    addCandidatesToUserPolicy(["pgpass"], loadEffectivePolicy(), home);
    const r = addCandidatesToUserPolicy(
      ["pgpass"],
      loadEffectivePolicy(),
      home,
    );
    expect(r.added).toEqual([]);
    expect(r.skipped).toEqual(["pgpass"]);
    const user = JSON.parse(fs.readFileSync(policyFile, "utf8"));
    expect(
      user.rules.filter((x: { id: string }) => x.id === "pgpass"),
    ).toHaveLength(1);
  });

  it("preserves rules the user already had", () => {
    fs.writeFileSync(
      policyFile,
      JSON.stringify({
        rules: [
          {
            id: "mine",
            class: "credential-read",
            description: "keep me",
            paths: ["secret/prod"],
          },
        ],
        disable: ["docker-auth"],
      }),
    );
    addCandidatesToUserPolicy(["pgpass"], loadEffectivePolicy(), home);
    const user = JSON.parse(fs.readFileSync(policyFile, "utf8"));
    expect(user.rules.map((x: { id: string }) => x.id)).toEqual([
      "mine",
      "pgpass",
    ]);
    expect(user.disable).toEqual(["docker-auth"]);
  });
});

describe("the discover command's --list flag", () => {
  let home = "";
  let captured = "";
  let restore: () => void;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-home-"));
    fs.writeFileSync(path.join(home, ".pgpass"), "pw");
    captured = "";
    const orig = process.stdout.write.bind(process.stdout);
    const spy = vi.spyOn(process.stdout, "write").mockImplementation(((
      chunk: string | Uint8Array,
    ) => {
      captured += typeof chunk === "string" ? chunk : "";
      return true;
    }) as typeof process.stdout.write);
    restore = () => spy.mockRestore();
  });
  afterEach(() => {
    restore();
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(policyFile, { force: true });
  });

  it("names the candidates and the add command, and never enters the prompt", async () => {
    await discoverCommand({ list: true }, home);
    expect(captured).toContain("pgpass");
    expect(captured).toContain("To add these, run:");
    expect(captured).toContain("herkos discover --add pgpass");
    // The per-candidate keypress prompt is never reached — not even printed.
    expect(captured).not.toContain("[y/N/a/q]");
    // Nothing was added: --list is read-only.
    expect(fs.existsSync(policyFile)).toBe(false);
  });

  it("is distinct from the unattended branch it resembles", async () => {
    // Without --list and off a terminal, the same hint carries the
    // not-a-terminal lead; --list must not claim that about a terminal.
    await discoverCommand({}, home);
    expect(captured).toContain("Not a terminal — to add these, run:");
  });
});
