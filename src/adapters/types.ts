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

export interface HarnessAdapter {
  /** Stable id, e.g. "claude-code". */
  id: string;
  /** Human name for output. */
  name: string;
  detect(): DetectResult;
  wire(policy: CompiledPolicy): WireResult;
  unwire(): WireResult;
  verify(): VerifyResult;
}
