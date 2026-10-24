import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const {
  claudeCodeAdapter,
  hookPath,
  sessionStartHookPath,
  policySnapshotPath,
  ownedSettingsPath,
} = await import("../src/adapters/claude-code.js");
const { compile, loadEffectivePolicy } = await import("../src/policy.js");

/**
 * The settings file is the one the user hand-edits most, so a corrupted copy
 * must reach the user as a diagnosis, never as a stack trace: verify() says
 * what is wrong and what to do; unwire() cannot clean a file it cannot read,
 * and it keeps every herkos file in place (above all the ownership record,
 * the only list of the deny and sandbox entries a repaired re-run removes)
 * so the re-run it points to can actually finish.
 */
describe("a corrupt harness settings file is a diagnosis, not a crash", () => {
  let configDir: string;
  const prev = {
    CLAUDE_CONFIG_DIR: process.env.CLAUDE_CONFIG_DIR,
    HERKOS_CONFIG: process.env.HERKOS_CONFIG,
  };

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-sr-"));
    process.env.CLAUDE_CONFIG_DIR = configDir;
    process.env.HERKOS_CONFIG = cfg;
    // The herkos dir sits under HERKOS_CONFIG, shared by every test here;
    // unwire no longer deletes the files it refuses to touch, so each test
    // starts from none of them existing.
    for (const p of [
      hookPath(),
      sessionStartHookPath(),
      policySnapshotPath(),
      ownedSettingsPath(),
    ])
      fs.rmSync(p, { force: true });
  });
  afterEach(() => {
    if (prev.CLAUDE_CONFIG_DIR === undefined)
      delete process.env.CLAUDE_CONFIG_DIR;
    else process.env.CLAUDE_CONFIG_DIR = prev.CLAUDE_CONFIG_DIR;
    if (prev.HERKOS_CONFIG === undefined) delete process.env.HERKOS_CONFIG;
    else process.env.HERKOS_CONFIG = prev.HERKOS_CONFIG;
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  const settingsFile = (): string => path.join(configDir, "settings.json");
  const brokenCases: [name: string, contents: string, message: RegExp][] = [
    ["not valid JSON", "{oops", /is not valid JSON/],
    ["an array, not an object", "[]", /holds an array, not a JSON object/],
  ];

  // verify() needs the hook file to exist before it reads the settings, or it
  // reports "hook missing" first — plant an empty one so the settings read is
  // the code path under test.
  const plantHook = (): void => fs.writeFileSync(hookPath(), "");

  it.each(brokenCases)(
    "verify() reports broken settings (%s) as a diagnosis",
    (_name, contents, message) => {
      plantHook();
      fs.writeFileSync(settingsFile(), contents);
      const v = claudeCodeAdapter.verify();
      expect(v.ok).toBe(false);
      expect(v.state).toBe("broken");
      expect(v.detail).toMatch(message);
      expect(v.detail).toMatch(/re-run 'herkos status'/);
    },
  );

  it.each(brokenCases)(
    "unwire() over herkos files and broken settings (%s) touches nothing, so the re-run it names can finish",
    (_name, contents) => {
      plantHook();
      fs.writeFileSync(policySnapshotPath(), "{}");
      fs.writeFileSync(
        ownedSettingsPath(),
        JSON.stringify({ deny: ["Read(//opt/herkos-fixture/token)"] }),
      );
      fs.writeFileSync(settingsFile(), contents);
      const r = claudeCodeAdapter.unwire();
      // The ownership record is the only list of the deny and sandbox entries
      // the promised re-run removes, and the hook entries still sit inside
      // the broken settings file; taking any of it out now would leave the
      // re-run unable to finish or the registrations dangling.
      expect(r.changed).toEqual([]);
      expect(fs.existsSync(hookPath())).toBe(true);
      expect(fs.existsSync(policySnapshotPath())).toBe(true);
      expect(fs.existsSync(ownedSettingsPath())).toBe(true);
      expect(r.detail).toMatch(/uninstall could not finish/);
      expect(r.detail).toMatch(/not valid JSON/);
      expect(r.detail).toMatch(/re-run 'herkos uninstall' to finish/);
    },
  );

  it("unwire() with broken settings and no herkos files says nothing was found, not that uninstall paused", () => {
    fs.writeFileSync(settingsFile(), "{oops");
    const r = claudeCodeAdapter.unwire();
    expect(r.changed).toEqual([]);
    expect(r.detail).toMatch(/nothing of herkos found on disk/);
  });

  it("the repair-and-re-run unwire promises over broken settings actually finishes", () => {
    const policy = compile(loadEffectivePolicy());
    claudeCodeAdapter.wire(policy);
    const wired = JSON.parse(fs.readFileSync(settingsFile(), "utf8")) as {
      hooks?: unknown;
      permissions?: { deny?: string[] };
      sandbox?: unknown;
    };
    expect(wired.permissions?.deny?.length ?? 0).toBeGreaterThan(0);
    // Break the file the way a hand edit does; every herkos registration is
    // still inside it, unreadable.
    fs.writeFileSync(settingsFile(), JSON.stringify(wired) + "\n}");
    const first = claudeCodeAdapter.unwire();
    expect(first.changed).toEqual([]);
    expect(fs.existsSync(ownedSettingsPath())).toBe(true);
    expect(fs.existsSync(hookPath())).toBe(true);
    expect(fs.existsSync(sessionStartHookPath())).toBe(true);
    // Repair: the entries herkos added are all still in the file.
    fs.writeFileSync(settingsFile(), JSON.stringify(wired));
    const second = claudeCodeAdapter.unwire();
    expect(second.detail).toBe("herkos wiring removed");
    const after = JSON.parse(
      fs.readFileSync(settingsFile(), "utf8"),
    ) as typeof wired;
    expect(after.hooks).toBeUndefined();
    // herkos created permissions and sandbox in this install; both go entirely.
    expect(after.permissions).toBeUndefined();
    expect(after.sandbox).toBeUndefined();
    expect(fs.existsSync(ownedSettingsPath())).toBe(false);
    expect(fs.existsSync(hookPath())).toBe(false);
  });

  it("unwire() over a clean, herkos-free settings file says so, with no note", () => {
    plantHook();
    fs.writeFileSync(settingsFile(), "{}");
    const r = claudeCodeAdapter.unwire();
    expect(r.detail).toBe("herkos wiring removed");
  });
});
