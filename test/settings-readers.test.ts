import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { isolateConfig } from "./helpers.js";

const cfg = isolateConfig();

const { claudeCodeAdapter, hookPath, policySnapshotPath } = await import(
  "../src/adapters/claude-code.js"
);

/**
 * The settings file is the one the user hand-edits most, so a corrupted copy
 * must reach the user as a diagnosis, never as a stack trace: verify() says
 * what is wrong and what to do; unwire() still takes out everything that is
 * hers (the hook file, the snapshot) and says what it could not clean.
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
    "unwire() still removes herkos-owned files and names what it could not clean (%s)",
    (_name, contents) => {
      plantHook();
      fs.writeFileSync(policySnapshotPath(), "{}");
      fs.writeFileSync(settingsFile(), contents);
      const r = claudeCodeAdapter.unwire();
      expect(r.changed).toContain(hookPath());
      expect(r.changed).toContain(policySnapshotPath());
      expect(fs.existsSync(hookPath())).toBe(false);
      expect(fs.existsSync(policySnapshotPath())).toBe(false);
      expect(r.detail).toMatch(/could not clean .*not valid JSON/);
      expect(r.detail).toMatch(/re-run 'herkos uninstall' to finish/);
    },
  );

  it("unwire() over a clean, herkos-free settings file says so, with no note", () => {
    plantHook();
    fs.writeFileSync(settingsFile(), "{}");
    const r = claudeCodeAdapter.unwire();
    expect(r.detail).toBe("herkos wiring removed");
  });
});
