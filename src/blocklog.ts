/**
 * The blocked-call log, read back.
 *
 * The enforcement hook appends one JSON line per refusal — time, harness, tool,
 * rule id and working directory — and never the command text, which can itself
 * carry a secret. Without it nothing records what was blocked: a user cannot
 * tell whether the guard ever fired, and nobody can see a rule firing on
 * legitimate work, which is the one signal the curation bar depends on. `status`
 * reads it back as per-rule counts and the most recent blocks.
 *
 * Reading is forgiving by design: the file is appended by a shell script that
 * may be killed mid-write or rotated underneath the reader, so a malformed line
 * is skipped, never fatal.
 */
import fs from "node:fs";
import { blockLogFile } from "./policy.js";

export interface BlockEntry {
  event: "block";
  time: string;
  harness: string;
  tool: string;
  rule: string;
  cwd: string;
}

export interface BlockSummary {
  total: number;
  perRule: Record<string, number>;
  /** Newest first. */
  recent: BlockEntry[];
}

function parseLines(raw: string): BlockEntry[] {
  const out: BlockEntry[] = [];
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const e = JSON.parse(line) as Partial<Record<keyof BlockEntry, unknown>>;
      if (
        e.event === "block" &&
        typeof e.rule === "string" &&
        typeof e.time === "string"
      ) {
        out.push({
          event: "block",
          time: e.time,
          harness: typeof e.harness === "string" ? e.harness : "unknown",
          tool: typeof e.tool === "string" ? e.tool : "",
          rule: e.rule,
          cwd: typeof e.cwd === "string" ? e.cwd : "",
        });
      }
    } catch {
      // A torn or foreign line — skip it.
    }
  }
  return out;
}

/** Every block on record: the rotated file first, then the live one. */
export function readBlockLog(file: string = blockLogFile()): BlockEntry[] {
  const out: BlockEntry[] = [];
  for (const f of [`${file}.1`, file]) {
    try {
      out.push(...parseLines(fs.readFileSync(f, "utf8")));
    } catch {
      // Absent is normal: nothing has been blocked, or it has not rotated yet.
    }
  }
  return out;
}

export function summariseBlocks(
  entries: BlockEntry[],
  recentCount = 5,
): BlockSummary {
  const perRule: Record<string, number> = {};
  for (const e of entries) perRule[e.rule] = (perRule[e.rule] ?? 0) + 1;
  const recent = [...entries]
    .sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0))
    .slice(0, recentCount);
  return { total: entries.length, perRule, recent };
}
