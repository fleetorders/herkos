/**
 * A harness adapter compiles the one policy into ONE harness's native wiring.
 * The policy knows nothing about harnesses; adapters own all harness-specific
 * knowledge. Adding a harness = adding an adapter, never touching the core.
 *
 * Contract rules every adapter must honor:
 * - wire() is idempotent: running it twice leaves one clean installation.
 * - unwire() removes exactly what wire() added, nothing else.
 * - wire() backs up any user config file before modifying it.
 * - verify() checks the wiring is PRESENT; it must not depend on network.
 */
import type { CompiledPolicy } from "../policy.js";

export interface DetectResult {
  installed: boolean;
  version?: string;
  /** Where this harness's config lives on this machine. */
  configDir?: string;
  detail: string;
}

export interface WireResult {
  changed: string[];
  detail: string;
}

/**
 * A refusal an adapter throws DELIBERATELY — a diagnosis for the user (harness
 * settings of a shape herkos cannot merge into, a config file that is not valid
 * JSON), thrown before anything is written, so a refused init is a clean no-op.
 * `init` prints it as one line and exits 1. Anything else thrown out of wire()
 * is a defect in herkos itself and gets its stack shown; the two must never
 * look alike, or bug reports and typos become indistinguishable.
 */
export class WireRefusalError extends Error {}

export interface VerifyResult {
  /** Is the never-list enforced as currently written? */
  ok: boolean;
  /**
   * Which of three distinct situations this is, so callers can label them
   * apart: "unwired" (nothing is enforced), "stale" (wiring is present and
   * enforcing an OLDER policy than the one on disk), "ok" (current). Absent
   * means the adapter reports only ok/not — treat as "ok" or "unwired".
   */
  state?: "ok" | "stale" | "unwired";
  detail: string;
}

/**
 * The kinds of enforcement layer a harness can offer. Harness-agnostic, so a
 * case in the bypass corpus can say which kind holds it and each harness can
 * say whether it has that kind wired.
 */
export type LayerKind =
  | "hook"
  | "permission-deny"
  | "os-sandbox"
  | "prefix-rule";

/** Which of a harness's enforcement layers hold one rule right now. */
export interface RuleCoverage {
  rule: string;
  /**
   * The layers currently wired that enforce this rule on this harness, strongest
   * first. Empty means the rule is NOT enforced here, which `status` says out loud.
   */
  layers: string[];
  /** The same layers by kind, for comparing across harnesses. */
  kinds: LayerKind[];
}

export interface HarnessAdapter {
  /** Stable id, e.g. "claude-code". */
  id: string;
  /** Human name for output. */
  name: string;
  /**
   * Which tool calls reach this harness's hook: every tool, or shell commands
   * only. Absent is read as shell commands only — the narrower claim.
   */
  hookScope?: "every-tool" | "shell-commands";
  detect(): DetectResult;
  wire(policy: CompiledPolicy): WireResult;
  unwire(): WireResult;
  verify(): VerifyResult;
  /**
   * Per rule, which layers of the CURRENT wiring hold it — so coverage claims
   * stay honest when a harness has several enforcement points of different
   * strength. Reads installed state; never writes.
   */
  coverage?(policy: CompiledPolicy): RuleCoverage[];
  /**
   * How to run ONE headless probe session against the REAL installed wiring —
   * the harness binary, its flags for a single non-interactive turn, a hard
   * spend ceiling, and the working directory the decoy sits in. The probe
   * orchestrator (probe.ts) plants the decoy and judges the transcript; this
   * only says how to invoke the harness. `null` when the harness has no headless
   * mode. Never mutates config — it exercises what `wire` already installed.
   */
  liveProbeCommand?(ctx: ProbeContext): ProbeCommand | null;
}

/** What the probe orchestrator hands an adapter to build its headless command. */
export interface ProbeContext {
  /** The throwaway working directory the decoy file sits in. */
  workingDir: string;
  /** The instruction for the agent (read the decoy, or run the fetched-exec line). */
  prompt: string;
  /** Hard spend ceiling for this run, in USD, where the harness supports one. */
  budgetUsd: number;
}

/** A single headless invocation: the binary, its argv, and the child's env. */
export interface ProbeCommand {
  bin: string;
  args: string[];
  env: NodeJS.ProcessEnv;
  /** One line on how the ceiling is enforced for this harness, for the report. */
  ceilingNote: string;
}
