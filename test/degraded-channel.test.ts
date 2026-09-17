import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { call, fireHook, isolateConfig, writeHook } from "./helpers.js";

const cfg = isolateConfig();

const { compile, loadEffectivePolicy } = await import("../src/policy.js");
const { generateHook } = await import("../src/adapters/claude-code.js");

const policyFile = path.join(cfg, "policy.json");
const write = (p: unknown): void =>
  fs.writeFileSync(policyFile, JSON.stringify(p));
// Unlike most suites, this one KEEPS the log file (it lives in the isolated
// config dir): a hook that may write machine-local state is the one whose
// stickiness is under test — STATE_DIR is derived beside LOG_FILE.
const hookFor = () => writeHook(generateHook(compile(loadEffectivePolicy())));
const stateDir = path.join(cfg, "sessions");

/** Splice a session id into a payload — works on malformed JSON too. */
const withSession = (sid: string, payload: string): string =>
  payload.replace(/^\{/, `{"session_id":${JSON.stringify(sid)},`);
const fire = (payload: string, args: string[] = []) =>
  fireHook(hookFor(), payload, process.env, args);

const cc = ["--harness", "claude-code"];
const MALFORMED = '{"tool_name":"Bash","tool_input":{"command":"unterminated';
const FINE = call("Bash", { command: "git status" });

afterEach(() => fs.rmSync(policyFile, { force: true }));

const systemMessage = (stdout: string): string =>
  (JSON.parse(stdout) as { systemMessage: string }).systemMessage;

describe("a degradation is heard, not only logged (D-008)", () => {
  it("puts an unparseable payload's DEGRADED line on the heard channel on Claude Code", () => {
    const r = fire(MALFORMED, cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("herkos DEGRADED");
    expect(systemMessage(r.stdout)).toContain("herkos DEGRADED");
  });

  it("keeps stderr as the whole surface on a harness whose channel is unverified", () => {
    const r = fire(MALFORMED);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("herkos DEGRADED");
    expect(r.stdout).toBe("");
  });

  it("puts a rule whose pattern grep cannot evaluate on the heard channel too", () => {
    write({
      rules: [
        {
          id: "broken",
          class: "note",
          description: "pattern grep will refuse",
          commandPatterns: ["("],
        },
      ],
    });
    const r = fire(call("Bash", { command: "echo hi" }), cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("could not be evaluated");
    expect(systemMessage(r.stdout)).toContain("could not be evaluated");
  });

  it("announces a value the reader decoded lossily instead of silently mangling it", () => {
    const raw =
      '{"tool_name":"Bash","tool_input":{"command":"caf\\u00e9 au lait"}}';
    const r = fire(raw, cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("cannot represent");
    expect(systemMessage(r.stdout)).toContain("cannot represent");
  });
});

describe("degradation is sticky for the session (D-008)", () => {
  it("a later well-formed call in the same session keeps announcing it", () => {
    const first = fire(withSession("sess-1", MALFORMED), cc);
    expect(first.exit).toBe(0);
    expect(fs.existsSync(path.join(stateDir, "degraded-sess-1"))).toBe(true);

    const second = fire(withSession("sess-1", FINE), cc);
    expect(second.exit).toBe(0);
    expect(second.stderr).toContain(
      "an earlier call in this session could not be checked",
    );
    expect(systemMessage(second.stdout)).toContain(
      "an earlier call in this session could not be checked",
    );
  });

  it("a fresh session starts clean", () => {
    fire(withSession("sess-2", MALFORMED), cc);
    const other = fire(withSession("sess-3", FINE), cc);
    expect(other.exit).toBe(0);
    expect(other.stderr).not.toContain("DEGRADED");
    expect(other.stdout).toBe("");
  });

  it("a payload without a session id cannot mark anything", () => {
    expect(fire(MALFORMED, cc).stderr).toContain("herkos DEGRADED");
    const after = fire(FINE, cc);
    expect(after.stderr).not.toContain("DEGRADED");
    expect(after.stdout).toBe("");
  });

  it("still flushes the sticky line when the later call itself gets blocked", () => {
    write({
      rules: [
        {
          id: "never-echo",
          class: "command-never",
          description: "echo",
          commandPrefixes: [["echo"]],
        },
      ],
    });
    fire(withSession("sess-4", MALFORMED), cc);
    const blocked = fire(
      withSession("sess-4", call("Bash", { command: "echo x" })),
      cc,
    );
    expect(blocked.exit).toBe(2);
    expect(blocked.stderr).toContain("rule never-echo");
    expect(blocked.stderr).toContain(
      "an earlier call in this session could not be checked",
    );
  });
});

describe("an UNCOVERED tool reaches the user once per session and tool (D-008)", () => {
  const uncovered = (sid: string, tool: string) =>
    withSession(
      sid,
      call(
        tool,
        tool === "mcp__vault__fetch" ? { secret_ref: "x" } : { blob: "y" },
      ),
    );

  it("rides the heard channel the first time, then stays a stderr diagnostic", () => {
    const first = fire(uncovered("sess-5", "mcp__vault__fetch"), cc);
    expect(first.exit).toBe(0);
    expect(first.stderr).toContain("herkos UNCOVERED");
    expect(systemMessage(first.stdout)).toContain("herkos UNCOVERED");

    const second = fire(uncovered("sess-5", "mcp__vault__fetch"), cc);
    expect(second.exit).toBe(0);
    expect(second.stderr).toContain("herkos UNCOVERED");
    expect(second.stdout).toBe("");
  });

  it("another tool in the same session still gets its own one announcement", () => {
    fire(uncovered("sess-6", "mcp__vault__fetch"), cc);
    const other = fire(uncovered("sess-6", "mcp__other__thing"), cc);
    expect(other.exit).toBe(0);
    expect(systemMessage(other.stdout)).toContain("mcp__other__thing");
  });
});
