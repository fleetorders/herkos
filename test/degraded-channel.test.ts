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

describe("a degradation is heard, not only logged (docs/decisions.md, D-008)", () => {
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

  it("degrades loudly, rule named, when a block rule's EXCLUDE regex breaks", () => {
    // Read as "does not match", a broken exclusion would silently flip the
    // verdict as if the carve-out did not exist. It takes the same degrade
    // path as the main pattern: rule off for the call, said on the
    // user-visible channel, no raw grep text.
    write({
      rules: [
        {
          id: "no-secrets",
          class: "credential-read",
          description: "secrets dir",
          paths: ["secrets/"],
          notPaths: ["("],
        },
      ],
    });
    const r = fire(
      withSession(
        "sess-excl",
        call("Read", { file_path: "secrets/prod/db.json" }),
      ),
      cc,
    );
    // The main pattern would match — but an unevaluable exclusion means the
    // rule cannot be applied correctly, so it is OFF for the call, loudly.
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain(
      "rule no-secrets exclude pattern could not be evaluated",
    );
    expect(r.stderr).not.toMatch(/grep:/); // no raw grep error text
    expect(systemMessage(r.stdout)).toContain(
      "exclude pattern could not be evaluated",
    );
    // And it is sticky: the session marker a later call re-announces.
    expect(fs.existsSync(path.join(stateDir, "degraded-sess-excl"))).toBe(true);
  });

  it("an OPEN rule's broken exclusion degrades too — a notice decided by a pattern that cannot be read is not sent", () => {
    write({
      rules: [
        {
          id: "note-secrets",
          class: "note",
          disposition: "open",
          description: "near secrets",
          message: "you are near the secrets directory",
          paths: ["secrets/"],
          notPaths: ["("],
        },
      ],
    });
    const r = fire(
      withSession(
        "sess-open-excl",
        call("Read", { file_path: "secrets/prod/db.json" }),
      ),
      cc,
    );
    // The benign carve-out cannot be evaluated; before the guard its grep
    // error read as "no match" and the notice fired on exactly the
    // spellings the carve-out exists to spare — D-009's silent flip, in the
    // noisy direction.
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain(
      "rule note-secrets exclude pattern could not be evaluated",
    );
    expect(r.stderr).not.toContain("herkos NOTICE (rule note-secrets)");
    expect(systemMessage(r.stdout)).toContain(
      "exclude pattern could not be evaluated",
    );
  });

  it("folds a session id that is not a flat filename before it names a marker", () => {
    // A session_id is payload input. The "degraded-" prefix already kept a
    // bare "../../evil" from traversing; the fold makes the flat-directory
    // invariant unconditional rather than an accident of the prefix, the
    // same fold the uncovered marker applies to tool names.
    const r = fire(withSession("../../evil", MALFORMED), cc);
    expect(r.exit).toBe(0);
    expect(fs.existsSync(path.join(stateDir, "degraded-.._.._evil"))).toBe(
      true,
    );
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

describe("degradation is sticky for the session (docs/decisions.md, D-008)", () => {
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

describe("an UNCOVERED tool reaches the user once per session and tool (docs/decisions.md, D-008)", () => {
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

  it("writing an UNCOVERED marker expires week-old markers, without any degradation", () => {
    // Expiry must run on every marker-writing path, or a machine that only
    // ever sees uncovered tools keeps every marker forever.
    fs.mkdirSync(stateDir, { recursive: true });
    const stale = path.join(stateDir, "uncovered-old-session-mcp__x");
    fs.writeFileSync(stale, "");
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    fs.utimesSync(stale, eightDaysAgo, eightDaysAgo);
    const r = fire(uncovered("sess-7", "mcp__vault__fetch"), cc);
    expect(r.stderr).toContain("herkos UNCOVERED");
    expect(r.stderr).not.toContain("herkos DEGRADED");
    expect(fs.existsSync(stale)).toBe(false);
    expect(
      fs.existsSync(path.join(stateDir, "uncovered-sess-7-mcp__vault__fetch")),
    ).toBe(true);
  });
});

describe("a path-bearing tool that yields nothing is drift, not quiet", () => {
  // A payload whose command key was renamed parses cleanly and extracts
  // nothing; muting that for Bash would leave the one class of call that can
  // trip the never-list unchecked with no word. So tools whose arguments are paths or commands announce on the existing
  // UNCOVERED path; tools whose arguments never are stay quiet.
  const drift = (sid: string, tool: string) =>
    withSession(
      sid,
      call(tool, { totally_unreadable_key: "cat ~/.ssh/id_ed25519" }),
    );

  it("announces UNCOVERED for a Bash call whose command key was renamed", () => {
    const r = fire(drift("sess-drift-1", "Bash"), cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).toContain("herkos UNCOVERED");
    expect(r.stderr).toContain("Bash");
    expect(systemMessage(r.stdout)).toContain("herkos UNCOVERED");
    expect(systemMessage(r.stdout)).toContain("Bash");
  });

  it("once per session and tool on the heard channel — the diagnostic stays on stderr", () => {
    fire(drift("sess-drift-2", "Bash"), cc);
    const second = fire(drift("sess-drift-2", "Bash"), cc);
    expect(second.exit).toBe(0);
    expect(second.stderr).toContain("herkos UNCOVERED");
    expect(second.stdout).toBe("");
  });

  it("stays quiet for a tool whose arguments never carry paths or commands", () => {
    const r = fire(drift("sess-drift-3", "TodoWrite"), cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).not.toContain("UNCOVERED");
    expect(r.stdout).toBe("");
  });

  it("a call that passed NO arguments stays quiet — nothing passed, nothing to check", () => {
    const r = fire(withSession("sess-drift-4", call("Bash", {})), cc);
    expect(r.exit).toBe(0);
    expect(r.stderr).not.toContain("UNCOVERED");
  });

  it("every path-bearing tool is in the announce class", () => {
    for (const tool of [
      "Bash",
      "PowerShell",
      "Read",
      "Write",
      "Edit",
      "MultiEdit",
      "NotebookEdit",
      "NotebookRead",
      "LS",
    ]) {
      const r = fire(drift("sess-drift-5", tool), cc);
      expect(r.stderr).toContain("herkos UNCOVERED");
      expect(r.stderr).toContain(tool);
    }
  });

  it("Glob and Grep stay quiet — `pattern` is deliberately unread, so zero yield is their normal shape", () => {
    for (const tool of ["Glob", "Grep", "WebFetch", "WebSearch"]) {
      const r = fire(
        withSession("sess-drift-6", call(tool, { pattern: "id_ed25519" })),
        cc,
      );
      expect(r.exit).toBe(0);
      expect(r.stderr).not.toContain("UNCOVERED");
      expect(r.stdout).toBe("");
    }
  });
});
