import fs from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { call, fireHook, isolateConfig } from "./helpers.js";

isolateConfig();

const { loadProjectPolicy, validateProjectPolicy, projectPolicyPath } =
  await import("../src/policy.js");
const {
  compileProjectPolicy,
  wireProject,
  unwireProject,
  verifyProject,
  projectHookPath,
  projectSettingsPath,
} = await import("../src/project.js");

let repo = "";
beforeEach(() => {
  repo = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-repo-"));
});
afterEach(() => fs.rmSync(repo, { recursive: true, force: true }));

const writeJson = (rel: string, obj: unknown): void => {
  const p = path.join(repo, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
};

const PROJECT = {
  rules: [
    {
      id: "no-prod-secrets",
      class: "credential-read",
      description: "the repo's production secrets directory",
      paths: ["secrets/prod/"],
    },
    {
      id: "no-reset-script",
      class: "command-never",
      description: "the destructive database reset script",
      commandPrefixes: [["./scripts/reset-db.sh"]],
      message: "the reset script wipes prod data — never run it from an agent",
    },
  ],
};

describe("project policy loading and validation", () => {
  afterEach(() => {});

  it("loads only the repo's own rules, never the baseline", () => {
    writeJson("herkos.json", PROJECT);
    const eff = loadProjectPolicy(repo);
    expect(eff.userPolicyLoaded).toBe(true);
    expect(eff.rules.map((r) => r.id)).toEqual([
      "no-prod-secrets",
      "no-reset-script",
    ]);
    // No baseline rule leaked in — the machine hook carries those.
    expect(eff.rules.some((r) => r.id === "ssh-private-keys")).toBe(false);
  });

  it("rejects a project policy that tries to disable a baseline rule", () => {
    writeJson("herkos.json", { ...PROJECT, disable: ["ssh-private-keys"] });
    const v = validateProjectPolicy(loadProjectPolicy(repo));
    expect(v.errors.join("\n")).toContain("cannot disable baseline");
  });

  it("still validates rule shape (a bad regex is caught)", () => {
    writeJson("herkos.json", {
      rules: [
        {
          id: "bad",
          class: "command-never",
          description: "x",
          commandPatterns: ["foo("],
        },
      ],
    });
    const v = validateProjectPolicy(loadProjectPolicy(repo));
    expect(v.errors.some((e) => e.includes("not a valid extended regex"))).toBe(
      true,
    );
  });

  it("reports not-loaded when there is no herkos.json", () => {
    expect(loadProjectPolicy(repo).userPolicyLoaded).toBe(false);
  });
});

describe("wiring a repo's project policy", () => {
  const read = (): { hooks?: { PreToolUse?: { matcher?: string }[] } } =>
    JSON.parse(fs.readFileSync(projectSettingsPath(repo), "utf8"));

  it("writes a self-contained hook and registers it via $CLAUDE_PROJECT_DIR", () => {
    writeJson("herkos.json", PROJECT);
    const { compiled } = compileProjectPolicy(repo);
    const r = wireProject(repo, compiled);
    expect(r.ruleCount).toBe(2);

    // The hook is committed at the repo-relative path and self-contained.
    const hook = fs.readFileSync(projectHookPath(repo), "utf8");
    expect(hook).toContain("#!/bin/sh");
    expect(hook).toContain("no-prod-secrets");

    // Registered on PreToolUse with a $CLAUDE_PROJECT_DIR command.
    const pre = read().hooks!.PreToolUse!;
    expect(pre).toHaveLength(1);
    const cmd = (pre[0] as { hooks: { command: string }[] }).hooks[0]!.command;
    expect(cmd).toContain(
      "$CLAUDE_PROJECT_DIR/.claude/hooks/herkos-project.sh",
    );
  });

  it("bakes NO machine-specific path into the committed hook (public-repo safe)", () => {
    writeJson("herkos.json", PROJECT);
    const { compiled } = compileProjectPolicy(repo);
    wireProject(repo, compiled);
    const hook = fs.readFileSync(projectHookPath(repo), "utf8");
    expect(hook).not.toContain(os.homedir());
    expect(hook).not.toMatch(/\/Users\/|\/home\//);
    expect(hook).not.toContain(repo); // not even the temp repo's absolute path
    // The policy file it names is the repo-relative herkos.json.
    expect(hook).toContain("herkos.json");
  });

  it("the committed hook actually blocks the repo's rules and allows the rest", () => {
    writeJson("herkos.json", PROJECT);
    const { compiled } = compileProjectPolicy(repo);
    wireProject(repo, compiled);
    const hook = projectHookPath(repo);
    // A read of the repo's prod-secrets dir → blocked.
    expect(
      fireHook(hook, call("Read", { file_path: "secrets/prod/db.json" })).exit,
    ).toBe(2);
    // The reset script → blocked (prefix rule), and its message surfaces.
    const reset = fireHook(
      hook,
      call("Bash", { command: "./scripts/reset-db.sh --yes" }),
    );
    expect(reset.exit).toBe(2);
    expect(reset.stderr).toContain("no-reset-script");
    // A normal read → allowed.
    expect(
      fireHook(hook, call("Read", { file_path: "src/index.ts" })).exit,
    ).toBe(0);
  });

  it("runs with no herkos and no jq — only sh/awk/grep (the stranger case)", () => {
    writeJson("herkos.json", PROJECT);
    const { compiled } = compileProjectPolicy(repo);
    wireProject(repo, compiled);
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-bare-"));
    for (const t of [
      "sh",
      "cat",
      "grep",
      "awk",
      "sed",
      "tr",
      "date",
      "dirname",
      "mkdir",
      "wc",
      "mv",
    ]) {
      const where = spawnSync("sh", ["-c", `command -v ${t}`], {
        encoding: "utf8",
      }).stdout.trim();
      if (where.startsWith("/")) fs.symlinkSync(where, path.join(bare, t));
    }
    try {
      const r = fireHook(
        projectHookPath(repo),
        call("Read", { file_path: "secrets/prod/x" }),
        { ...process.env, PATH: bare },
      );
      expect(r.exit).toBe(2);
    } finally {
      fs.rmSync(bare, { recursive: true, force: true });
    }
  });

  it("is idempotent and preserves the user's other project settings", () => {
    writeJson(".claude/settings.json", {
      model: "keep-me",
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash",
            hooks: [{ type: "command", command: "echo mine" }],
          },
        ],
      },
    });
    writeJson("herkos.json", PROJECT);
    const { compiled } = compileProjectPolicy(repo);
    wireProject(repo, compiled);
    wireProject(repo, compiled); // twice
    const s = read() as {
      model?: string;
      hooks: {
        PreToolUse: { matcher?: string; hooks: { command: string }[] }[];
      };
    };
    expect(s.model).toBe("keep-me");
    const pre = s.hooks.PreToolUse;
    // The user's own hook survives; exactly one herkos entry.
    expect(pre.filter((e) => e.hooks[0]!.command === "echo mine")).toHaveLength(
      1,
    );
    expect(
      pre.filter((e) => e.hooks[0]!.command.includes("herkos-project.sh")),
    ).toHaveLength(1);
    // A pre-herkos backup was taken.
    expect(fs.existsSync(`${projectSettingsPath(repo)}.herkos-bak`)).toBe(true);
  });

  it("unwire removes exactly the hook entry and file, keeping the user's", () => {
    writeJson(".claude/settings.json", {
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash",
            hooks: [{ type: "command", command: "echo mine" }],
          },
        ],
      },
    });
    writeJson("herkos.json", PROJECT);
    wireProject(repo, compileProjectPolicy(repo).compiled);
    unwireProject(repo);
    expect(fs.existsSync(projectHookPath(repo))).toBe(false);
    const pre = read().hooks!.PreToolUse! as { hooks: { command: string }[] }[];
    expect(pre).toHaveLength(1);
    expect(pre[0]!.hooks[0]!.command).toBe("echo mine");
  });

  it("removes the hooks block entirely when herkos created it", () => {
    writeJson("herkos.json", PROJECT);
    wireProject(repo, compileProjectPolicy(repo).compiled);
    unwireProject(repo);
    const s = read() as Record<string, unknown>;
    expect(s.hooks).toBeUndefined();
  });
});

describe("verifyProject — the CI drift check", () => {
  it("no-policy when the repo has no herkos.json", () => {
    expect(verifyProject(repo).state).toBe("no-policy");
  });

  it("ok right after init", () => {
    writeJson("herkos.json", PROJECT);
    wireProject(repo, compileProjectPolicy(repo).compiled);
    const v = verifyProject(repo);
    expect(v.ok).toBe(true);
    expect(v.state).toBe("ok");
  });

  it("unwired when herkos.json exists but no hook is committed", () => {
    writeJson("herkos.json", PROJECT);
    expect(verifyProject(repo).state).toBe("unwired");
  });

  it("stale when herkos.json changed after init (drift)", () => {
    writeJson("herkos.json", PROJECT);
    wireProject(repo, compileProjectPolicy(repo).compiled);
    // Edit the policy without re-running init.
    writeJson("herkos.json", {
      rules: [
        ...PROJECT.rules,
        {
          id: "extra",
          class: "credential-read",
          description: "another",
          paths: ["config/keys/"],
        },
      ],
    });
    const v = verifyProject(repo);
    expect(v.ok).toBe(false);
    expect(v.state).toBe("stale");
  });
});
