import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { claudeCodeAdapter, commandRuns, pathSpellings } = await import(
  "../src/adapters/claude-code.js"
);
const { codexAdapter, hookWiredInHooksJson } = await import(
  "../src/adapters/codex.js"
);

/**
 * Re-running `init` over an install made by an earlier release, on a machine
 * where other tools have since touched the harness files. Both cases below
 * were seen on a live upgrade: the hook ended up registered twice, and Codex
 * refused its config.toml because herkos appended a second profile table.
 */
describe("re-running init over an earlier install", () => {
  const keys = ["HOME", "HERKOS_CONFIG", "CLAUDE_CONFIG_DIR", "CODEX_HOME"];
  const prev: Record<string, string | undefined> = {};
  let home: string;

  beforeEach(() => {
    for (const k of keys) prev[k] = process.env[k];
    home = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-upgrade-"));
    // The herkos dir sits under HOME, as it does on a real machine, so the
    // $HOME spelling an earlier release wrote can name it.
    process.env.HOME = home;
    process.env.HERKOS_CONFIG = path.join(home, ".config", "herkos");
    process.env.CLAUDE_CONFIG_DIR = path.join(home, ".claude");
    process.env.CODEX_HOME = path.join(home, ".codex");
    for (const d of [
      process.env.HERKOS_CONFIG,
      process.env.CLAUDE_CONFIG_DIR,
      process.env.CODEX_HOME,
    ])
      fs.mkdirSync(d!, { recursive: true });
  });
  afterEach(() => {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  const OLD_CMD = 'sh "$HOME/.config/herkos/hook-claude-code.sh"';

  it("spells a path under HOME every way a command can name it", () => {
    const abs = path.join(home, ".config", "herkos", "hook-claude-code.sh");
    expect(pathSpellings(abs)).toEqual([
      abs,
      "$HOME/.config/herkos/hook-claude-code.sh",
      "${HOME}/.config/herkos/hook-claude-code.sh",
      "~/.config/herkos/hook-claude-code.sh",
    ]);
    expect(pathSpellings("/opt/elsewhere/hook.sh")).toEqual([
      "/opt/elsewhere/hook.sh",
    ]);
  });

  it("Claude Code: replaces an entry registered as $HOME/... instead of adding a second", () => {
    const sp = path.join(process.env.CLAUDE_CONFIG_DIR!, "settings.json");
    fs.writeFileSync(
      sp,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            { matcher: "*", hooks: [{ type: "command", command: OLD_CMD }] },
            {
              matcher: "Bash",
              hooks: [{ type: "command", command: "sh other-guard.sh" }],
            },
          ],
        },
      }),
    );
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    const s = JSON.parse(fs.readFileSync(sp, "utf8")) as {
      hooks: { PreToolUse: { hooks: { command: string }[] }[] };
    };
    const cmds = s.hooks.PreToolUse.flatMap((e) =>
      e.hooks.map((h) => h.command),
    );
    expect(cmds.filter((c) => c.includes("hook-claude-code.sh"))).toHaveLength(
      1,
    );
    expect(cmds).toContain("sh other-guard.sh"); // someone else's entry stays
  });

  it("Codex: replaces a hooks.json entry registered as $HOME/... instead of adding a second", () => {
    const hp = path.join(process.env.CODEX_HOME!, "hooks.json");
    fs.writeFileSync(
      hp,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: "^Bash$",
              hooks: [{ type: "command", command: OLD_CMD }],
            },
          ],
        },
      }),
    );
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const text = fs.readFileSync(hp, "utf8");
    expect(text.match(/hook-claude-code\.sh/g)).toHaveLength(1);
  });

  // The shape found on disk: a tool that rewrote config.toml dropped the
  // opening marker and its comments, and new tables landed after the block.
  const ORPHANED =
    'default_permissions = "herkos" # >>> herkos managed root key (see the herkos block at the end) <<<\n' +
    'model = "x"\n\n' +
    '[projects."/work/a"]\ntrust_level = "trusted"\n\n' +
    "[permissions.herkos]\n" +
    'description = "herkos never-list: credential reads denied"\n' +
    'extends = ":workspace"\n' +
    "[permissions.herkos.filesystem]\n" +
    '"~/.ssh" = "deny"\n' +
    '[permissions.herkos.filesystem.":workspace_roots"]\n' +
    "# <<< herkos managed <<<\n\n" +
    "# my own note about the next project\n" +
    '[projects."/work/b"]\ntrust_level = "trusted"\n';

  it("Codex: finds a herkos table whose opening marker is gone, and writes the profile once", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, ORPHANED);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const out = fs.readFileSync(cfg, "utf8");
    expect(out.match(/^\[permissions\.herkos\]$/gm)).toHaveLength(1);
    expect(out.match(/^\[permissions\.herkos\.filesystem\]$/gm)).toHaveLength(
      1,
    );
    expect(out.match(/^default_permissions = "herkos"/gm)).toHaveLength(1);
    // Everything that was not herkos's survives, the user's comment included.
    expect(out).toContain('[projects."/work/a"]');
    expect(out).toContain('[projects."/work/b"]');
    expect(out).toContain("# my own note about the next project");
    expect(out).toContain('model = "x"');
  });

  it("Codex: unwire removes a herkos table whose opening marker is gone", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, ORPHANED);
    codexAdapter.unwire();
    const out = fs.readFileSync(cfg, "utf8");
    expect(out).not.toMatch(/permissions\.herkos/);
    expect(out).not.toContain("herkos managed");
    expect(out).toContain('[projects."/work/b"]');
    expect(out).toContain("# my own note about the next project");
  });

  // The comment-stripped shape: a formatter took every marker and comment
  // with it, leaving the selector bare and a blank line inside the orphaned
  // table. A TOML table runs to the next header, never to a blank line.
  const STRIPPED =
    'default_permissions = "herkos"\n' +
    'model = "x"\n\n' +
    '[projects."/work/a"]\ntrust_level = "trusted"\n\n' +
    "[permissions.herkos]\n\n" +
    'extends = ":workspace"\n' +
    "[permissions.herkos.filesystem]\n" +
    '"~/.ssh" = "deny"\n\n' +
    '[projects."/work/b"]\ntrust_level = "trusted"\n';

  it("Codex: an orphaned table does not end at a blank line — its keys go with it", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, STRIPPED);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const out = fs.readFileSync(cfg, "utf8");
    // One extends: the fresh block's. The orphan's copy used to survive the
    // blank line and land inside [projects."/work/a"], the user's table.
    expect(out.match(/^extends = ":workspace"$/gm)).toHaveLength(1);
    expect(out.match(/^\[permissions\.herkos\]$/gm)).toHaveLength(1);
    expect(out.match(/^default_permissions = "herkos"/gm)).toHaveLength(1);
    expect(out).toContain('[projects."/work/a"]');
    expect(out).toContain('[projects."/work/b"]');
    expect(out).toContain('model = "x"');
  });

  it("Codex: uninstall takes the bare selector too, not just the marked one", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, STRIPPED);
    codexAdapter.unwire();
    const out = fs.readFileSync(cfg, "utf8");
    // The profile table is gone, so a surviving selector would name a profile
    // that no longer exists — a config Codex refuses to load.
    expect(out).not.toMatch(/default_permissions/);
    expect(out).not.toMatch(/permissions\.herkos/);
    expect(out).toContain('[projects."/work/b"]');
    expect(out).toContain('model = "x"');
  });

  it("Codex: still sees the profile as selected when the selector's marker was stripped", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, STRIPPED);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    // Rewrite the root line as a comment-stripper would: same key, no marker.
    const stripped = fs
      .readFileSync(cfg, "utf8")
      .replace(
        " # >>> herkos managed root key (see the herkos block at the end) <<<",
        "",
      );
    fs.writeFileSync(cfg, stripped);
    expect(codexAdapter.verify().ok).toBe(true);
  });

  // A `[permissions.herkos]` example inside a triple-quoted string is text,
  // not a table header.
  const STRING_EXAMPLE =
    'model = "x"\n' +
    'developer_instructions = """\n' +
    "[permissions.herkos]  # an example, inside a string\n" +
    'extends = ":workspace"\n' +
    '"""\n\n' +
    '[projects."/work/a"]\ntrust_level = "trusted"\n';

  it("Codex: a herkos table inside a multiline string is an example, not a table", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, STRING_EXAMPLE);
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const out = fs.readFileSync(cfg, "utf8");
    expect(out).toContain(
      "[permissions.herkos]  # an example, inside a string",
    );
    // The closing quotes survived: cleanup used to eat them and leave an
    // unterminated string.
    expect(out.match(/"""/g)).toHaveLength(2);
    expect(out.match(/^\[permissions\.herkos\]$/gm)).toHaveLength(1);
    expect(out).toContain('[projects."/work/a"]');
  });

  it("Codex: refuses a herkos table in a spelling it does not rewrite, writing nothing", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    const before = '[permissions."herkos"]\nextends = ":workspace"\n';
    fs.writeFileSync(cfg, before);
    // Same table, different bytes: appending the managed block would define
    // [permissions.herkos] twice and Codex refuses the file.
    expect(() => codexAdapter.wire(compile(loadEffectivePolicy()))).toThrow(
      "more than once",
    );
    expect(fs.readFileSync(cfg, "utf8")).toBe(before);
  });

  it("claims a command only when the path stands on its own", () => {
    const abs = path.join(home, ".config", "herkos", "hook-claude-code.sh");
    expect(commandRuns(OLD_CMD, abs)).toBe(true);
    expect(commandRuns(`sh '${abs}' --harness codex`, abs)).toBe(true);
    // Quote-split spellings expand to the same file: unmatched, init appended
    // a second entry — the 0.4.1 double registration, in its quoted form.
    expect(
      commandRuns('sh "$HOME"/.config/herkos/hook-claude-code.sh', abs),
    ).toBe(true);
    expect(
      commandRuns('sh "${HOME}"/.config/herkos/hook-claude-code.sh', abs),
    ).toBe(true);
    // A command that NAMES the path without running it is not a wiring.
    expect(commandRuns(`cat ${abs}`, abs)).toBe(false);
    expect(commandRuns(`grep -q x "${abs}" && echo found`, abs)).toBe(false);
    // Knowingly unclaimed: a genuine invocation the runner set cannot see
    // (the path feeds xargs, not a runner). A miss costs a duplicate
    // registration; a false claim costs silent enforcement loss.
    expect(commandRuns(`echo ${abs} | xargs`, abs)).toBe(false);
    // Someone else's file that merely starts or ends with our path.
    expect(commandRuns(`sh "${abs}.backup"`, abs)).toBe(false);
    expect(commandRuns(`sh "/mirror${abs}"`, abs)).toBe(false);
    expect(
      commandRuns('sh "$HOME/.config/herkos/hook-claude-code.sh-old"', abs),
    ).toBe(false);
    // The editor-backup suffix is a path character, not a boundary: claiming
    // it silently removed a registration that was never herkos's.
    expect(
      commandRuns('sh "$HOME/.config/herkos/hook-claude-code.sh~"', abs),
    ).toBe(false);
    expect(commandRuns(`sh "${abs}~"`, abs)).toBe(false);
    // The ~-spelling of our own path is still ours, marker or not.
    expect(commandRuns("sh ~/.config/herkos/hook-claude-code.sh", abs)).toBe(
      true,
    );
  });

  it("Codex: the wired-check parses the hooks file instead of matching text in it", () => {
    const abs = path.join(home, ".config", "herkos", "hook-claude-code.sh");
    const file = (command: string): string =>
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              {
                matcher: "^Bash$",
                hooks: [{ type: "command", command }],
              },
            ],
          },
        },
        null,
        2,
      );
    // The registered command as the file serializes it: quotes escaped,
    // multi-line. Still a wiring.
    expect(hookWiredInHooksJson(file(`sh "${abs}" --harness codex`))).toBe(
      true,
    );
    // A wrapper that merely NAMES the script is not a wiring — the raw-text
    // match used to claim it, and status reported enforcement that was not
    // there.
    expect(hookWiredInHooksJson(file(`cat "${abs}" | wc -l`))).toBe(false);
    // A file that is not JSON says "not wired", never "maybe".
    expect(hookWiredInHooksJson("{not json")).toBe(false);
  });

  const SHARED = {
    matcher: "*",
    hooks: [
      { type: "command", command: OLD_CMD },
      { type: "command", command: "sh my-own-check.sh" },
    ],
  };

  it("Claude Code: keeps a user command that shares an entry with herkos, on wire and unwire", () => {
    const sp = path.join(process.env.CLAUDE_CONFIG_DIR!, "settings.json");
    fs.writeFileSync(sp, JSON.stringify({ hooks: { PreToolUse: [SHARED] } }));
    const commands = (): string[] =>
      (
        JSON.parse(fs.readFileSync(sp, "utf8")) as {
          hooks?: { PreToolUse?: { hooks: { command: string }[] }[] };
        }
      ).hooks?.PreToolUse?.flatMap((e) => e.hooks.map((h) => h.command)) ?? [];
    claudeCodeAdapter.wire(compile(loadEffectivePolicy()));
    expect(commands()).toContain("sh my-own-check.sh");
    expect(
      commands().filter((c) => c.includes("hook-claude-code.sh")),
    ).toHaveLength(1);
    claudeCodeAdapter.unwire();
    expect(commands()).toEqual(["sh my-own-check.sh"]);
  });

  it("Codex: keeps a user command that shares an entry with herkos, on wire and unwire", () => {
    const hp = path.join(process.env.CODEX_HOME!, "hooks.json");
    fs.writeFileSync(hp, JSON.stringify({ hooks: { PreToolUse: [SHARED] } }));
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const wired = fs.readFileSync(hp, "utf8");
    expect(wired).toContain("sh my-own-check.sh");
    expect(wired.match(/hook-claude-code\.sh/g)).toHaveLength(1);
    codexAdapter.unwire();
    const left = fs.readFileSync(hp, "utf8");
    expect(left).toContain("sh my-own-check.sh");
    expect(left).not.toContain("hook-claude-code.sh");
  });

  it("Codex: always writes its block after a blank line, idempotently", () => {
    const cfg = path.join(process.env.CODEX_HOME!, "config.toml");
    fs.writeFileSync(cfg, '[projects."/work/a"]\ntrust_level = "trusted"\n');
    codexAdapter.wire(compile(loadEffectivePolicy()));
    const out = fs.readFileSync(cfg, "utf8");
    expect(out).toContain('trust_level = "trusted"\n\n# >>> herkos managed');
    codexAdapter.wire(compile(loadEffectivePolicy()));
    expect(fs.readFileSync(cfg, "utf8")).toBe(out); // idempotent
  });
});
