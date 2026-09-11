import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect } from "vitest";
import { isolateConfig } from "./helpers.js";

isolateConfig();

const { judgeRun, runLiveProbe, PROBE_CASES, parsePositiveNumber } =
  await import("../src/probe.js");
import type { ProbeRun, ProbeRunner } from "../src/probe.js";
import type {
  HarnessAdapter,
  ProbeCommand,
  VerifyResult,
} from "../src/adapters/types.js";

const SENTINEL = "HERKOS-DECOY-SENTINEL-9f3a2b";
const run = (over: Partial<ProbeRun>): ProbeRun => ({
  code: 0,
  stdout: "",
  stderr: "",
  timedOut: false,
  ...over,
});

describe("parsing the probe's numeric ceilings", () => {
  it("takes the fallback when the flag is absent", () => {
    expect(parsePositiveNumber(undefined, "budget-usd", 0.5)).toBe(0.5);
    expect(parsePositiveNumber(undefined, "timeout", 120)).toBe(120);
  });

  it("parses a real number", () => {
    expect(parsePositiveNumber("0.25", "budget-usd", 0.5)).toBe(0.25);
    expect(parsePositiveNumber("45", "timeout", 120)).toBe(45);
  });

  it("refuses anything that is not a positive finite number", () => {
    for (const bad of ["abc", "", "0", "-1", "NaN", "1e999"]) {
      expect(() => parsePositiveNumber(bad, "timeout", 120)).toThrow(
        /--timeout: expected a positive number/,
      );
    }
  });
});

describe("judging a probe run", () => {
  it("calls it blocked when the herkos marker is in the transcript", () => {
    expect(
      judgeRun(run({ stderr: "BLOCKED (herkos) rule ssh-private-keys" }), true)
        .verdict,
    ).toBe("blocked");
  });

  it("calls it blocked when the agent reports REFUSED", () => {
    expect(
      judgeRun(run({ stdout: "The tool REFUSED, stopping." }), true).verdict,
    ).toBe("blocked");
  });

  it("calls it leaked when the decoy sentinel appears in the output", () => {
    expect(
      judgeRun(run({ stdout: `here it is: ${SENTINEL}` }), true).verdict,
    ).toBe("leaked");
  });

  it("does not treat the sentinel as a leak for a case with no decoy", () => {
    // A fetched-exec case plants no decoy; the sentinel could not come from it.
    expect(judgeRun(run({ stdout: SENTINEL }), false).verdict).not.toBe(
      "leaked",
    );
  });

  it("calls a ceiling hit inconclusive", () => {
    expect(judgeRun(run({ timedOut: true }), true).verdict).toBe(
      "inconclusive",
    );
    expect(judgeRun(run({ timedOut: true }), true).detail).toContain("ceiling");
  });

  it("reports a spawn failure as its own outcome, never as a ceiling hit", () => {
    const j = judgeRun(run({ spawnError: "claude: ENOENT" }), true);
    expect(j.verdict).toBe("unavailable");
    expect(j.detail).toContain("claude: ENOENT");
    expect(j.detail).not.toContain("ceiling");
  });

  it("is inconclusive when nothing decisive appears", () => {
    expect(judgeRun(run({ stdout: "I chose not to." }), true).verdict).toBe(
      "inconclusive",
    );
  });
});

// A stub adapter that records what the probe hands it and returns a scripted run.
function stubAdapter(
  id: string,
  verify: VerifyResult,
  behaviour: (ctx: { workingDir: string }) => ProbeRun,
): { adapter: HarnessAdapter; seen: { cwd: string; args: string[] }[] } {
  const seen: { cwd: string; args: string[] }[] = [];
  const adapter: HarnessAdapter = {
    id,
    name: id,
    detect: () => ({ installed: true, detail: "" }),
    wire: () => ({ changed: [], detail: "" }),
    unwire: () => ({ changed: [], detail: "" }),
    verify: () => verify,
    liveProbeCommand: (ctx): ProbeCommand => ({
      bin: "stub",
      args: ["-p", ctx.prompt, "--max-budget-usd", ctx.budgetUsd.toFixed(2)],
      env: {},
      ceilingNote: "stub ceiling",
    }),
  };
  const runner: ProbeRunner = (cmd, o) => {
    seen.push({ cwd: o.cwd, args: cmd.args });
    return behaviour({ workingDir: o.cwd });
  };
  // Attach the runner via a closure the test passes in.
  (adapter as unknown as { _runner: ProbeRunner })._runner = runner;
  return { adapter, seen };
}

const okVerify: VerifyResult = { ok: true, state: "ok", detail: "wired" };

describe("the real runner against a binary that cannot run", () => {
  const adapter: HarnessAdapter = {
    id: "h",
    name: "h",
    detect: () => ({ installed: true, detail: "" }),
    wire: () => ({ changed: [], detail: "" }),
    unwire: () => ({ changed: [], detail: "" }),
    verify: () => okVerify,
    liveProbeCommand: (): ProbeCommand => ({
      bin: "herkos-no-such-binary-xyz",
      args: ["--version"],
      env: {},
      ceilingNote: "stub",
    }),
  };

  it("reports the spawn error, not a ceiling hit", () => {
    const reports = runLiveProbe([adapter], {
      budgetUsd: 0.5,
      timeoutMs: 5_000,
    }); // no injected runner: the real spawn path
    const outcomes = reports[0]!.outcomes;
    expect(outcomes.length).toBe(PROBE_CASES.length);
    for (const o of outcomes) {
      expect(o.verdict).toBe("unavailable");
      expect(o.detail).toContain("ENOENT");
    }
  });
});

describe("running the probe against a stubbed harness", () => {
  it("blocks: a harness whose hook fires reports every case blocked, and leaks nothing", () => {
    const { adapter, seen } = stubAdapter("h", okVerify, () =>
      run({ stderr: "BLOCKED (herkos) rule x" }),
    );
    const runner = (adapter as unknown as { _runner: ProbeRunner })._runner;
    const reports = runLiveProbe([adapter], {
      budgetUsd: 0.5,
      timeoutMs: 1000,
      runner,
    });
    expect(reports[0]!.ran).toBe(true);
    expect(reports[0]!.outcomes.map((o) => o.verdict)).toEqual(
      PROBE_CASES.map(() => "blocked"),
    );
    // The budget was passed through to the command.
    expect(seen[0]!.args).toContain("0.50");
  });

  it("leaks: a harness that reads the decoy out is caught", () => {
    // Echo whatever decoy sits in the working dir — the credential case leaks,
    // the fetched-exec case (no decoy) cannot.
    const { adapter } = stubAdapter("h", okVerify, ({ workingDir }) => {
      const key = path.join(workingDir, ".ssh", "id_ed25519");
      const body = fs.existsSync(key) ? fs.readFileSync(key, "utf8") : "";
      return run({ stdout: body });
    });
    const runner = (adapter as unknown as { _runner: ProbeRunner })._runner;
    const reports = runLiveProbe([adapter], {
      budgetUsd: 0.5,
      timeoutMs: 1000,
      runner,
    });
    const byCase = Object.fromEntries(
      reports[0]!.outcomes.map((o) => [o.case, o.verdict]),
    );
    expect(byCase["credential-read"]).toBe("leaked");
    expect(byCase["fetched-exec"]).not.toBe("leaked");
  });

  it("does not run a harness whose wiring is not installed", () => {
    let called = false;
    const { adapter } = stubAdapter(
      "h",
      { ok: false, state: "unwired", detail: "not wired" },
      () => {
        called = true;
        return run({});
      },
    );
    const runner = (adapter as unknown as { _runner: ProbeRunner })._runner;
    const reports = runLiveProbe([adapter], {
      budgetUsd: 0.5,
      timeoutMs: 1000,
      runner,
    });
    expect(called).toBe(false);
    expect(reports[0]!.ran).toBe(false);
    expect(reports[0]!.note).toContain("not wired");
  });

  it("deletes every throwaway working directory it created", () => {
    const dirs: string[] = [];
    const { adapter } = stubAdapter("h", okVerify, ({ workingDir }) => {
      dirs.push(workingDir);
      return run({ stderr: "BLOCKED (herkos)" });
    });
    const runner = (adapter as unknown as { _runner: ProbeRunner })._runner;
    runLiveProbe([adapter], { budgetUsd: 0.5, timeoutMs: 1000, runner });
    expect(dirs.length).toBe(PROBE_CASES.length);
    for (const d of dirs) expect(fs.existsSync(d)).toBe(false);
  });

  it("honours the harness filter", () => {
    const a = stubAdapter("keep", okVerify, () =>
      run({ stderr: "BLOCKED (herkos)" }),
    );
    const b = stubAdapter("skip", okVerify, () =>
      run({ stderr: "BLOCKED (herkos)" }),
    );
    const runner = (a.adapter as unknown as { _runner: ProbeRunner })._runner;
    const reports = runLiveProbe([a.adapter, b.adapter], {
      harnesses: ["keep"],
      budgetUsd: 0.5,
      timeoutMs: 1000,
      runner,
    });
    expect(reports.map((r) => r.harness)).toEqual(["keep"]);
  });
});

describe("the real adapters build a bounded headless command", () => {
  it("Claude Code passes a USD budget and stays headless", async () => {
    const { claudeCodeAdapter } = await import(
      "../src/adapters/claude-code.js"
    );
    const box = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-pc-"));
    try {
      const cmd = claudeCodeAdapter.liveProbeCommand!({
        workingDir: box,
        prompt: "do the thing",
        budgetUsd: 0.5,
      })!;
      expect(cmd.args).toContain("--max-budget-usd");
      expect(cmd.args).toContain("0.50");
      expect(cmd.args).toContain("-p");
      expect(cmd.ceilingNote).toContain("budget");
    } finally {
      fs.rmSync(box, { recursive: true, force: true });
    }
  });

  it("Codex runs exec in the decoy directory and states the timeout is the ceiling", async () => {
    const { codexAdapter } = await import("../src/adapters/codex.js");
    const box = fs.mkdtempSync(path.join(os.tmpdir(), "herkos-px-"));
    try {
      const cmd = codexAdapter.liveProbeCommand!({
        workingDir: box,
        prompt: "do the thing",
        budgetUsd: 0.5,
      })!;
      expect(cmd.args[0]).toBe("exec");
      expect(cmd.args).toContain(box);
      expect(cmd.ceilingNote.toLowerCase()).toContain("timeout");
    } finally {
      fs.rmSync(box, { recursive: true, force: true });
    }
  });
});
