import { spawnSync } from "node:child_process";
import { describe, it, expect } from "vitest";

const { EXTRACT_AWK } = await import("../src/extract.js");
const { PATH_KEYS, COMMAND_KEYS } = await import("../src/matchers.js");

/**
 * The property test D-008 asked for: whatever a real JSON encoder emits, the
 * awk reader decodes it to exactly the text a rule is checked against — or
 * says (W) that it could not. The model below IS the decoder's contract:
 * printable ASCII passes through, shell-whitespace escapes become spaces, a
 * non-ASCII escape becomes "?", raw non-ASCII bytes pass through untouched
 * (a real encoder emits them raw), and anything replaced is announced.
 */

/** Run the extractor the way the hook does and return its record lines. */
function extract(payload: string): string[] {
  const r = spawnSync(
    "awk",
    [
      "-v",
      `pkeys=${PATH_KEYS.join(" ")}`,
      "-v",
      `ckeys=${COMMAND_KEYS.join(" ")}`,
      EXTRACT_AWK,
    ],
    { input: payload, encoding: "utf8", timeout: 10_000 },
  );
  if (r.status !== 0) throw new Error(`awk exited ${r.status}: ${r.stderr}`);
  return (r.stdout ?? "").split("\n").filter((l) => l !== "");
}

/** The single C record's value — the text rules are checked against. */
const commandOf = (lines: string[]): string | null =>
  lines.find((l) => l.startsWith("C\t"))?.slice(2) ?? null;

/** What the decoder must produce for a command value (see extract.ts). */
function model(s: string): string {
  return Array.from(s)
    .map((ch) => {
      const c = ch.codePointAt(0)!;
      if (c >= 0xd800 && c <= 0xdfff) return "?"; // lone surrogate: escaped by a well-formed encoder
      if (ch === "\n" || ch === "\t" || ch === "\r") return " ";
      if (c < 0x20) return " "; // control codepoint: \uXXXX-escaped, decoded to a space
      return ch; // printable ASCII and raw non-ASCII pass through
    })
    .join("");
}

/** When the decoder must say W: it replaced something a rule could have named. */
function isLossy(s: string): boolean {
  return Array.from(s).some((ch) => {
    const c = ch.codePointAt(0)!;
    if (c >= 0xd800 && c <= 0xdfff) return true; // → "?"
    if (ch === "\n" || ch === "\t" || ch === "\r") return false; // whitespace-equivalent
    if (c < 0x20) return true; // → " " via \uXXXX
    return false;
  });
}

// A deterministic generator (an LCG — no dependency, same sequence every run).
let seed = 0x2a2a2a2a;
const rnd = (): number => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 0x100000000;
};
const POOL = [
  "a",
  "Z",
  "0",
  "-",
  "_",
  ".",
  "/",
  " ",
  "\t",
  ";",
  "|",
  "(",
  ")",
  "&",
  "$",
  "'",
  '"',
  "\\",
  "\n",
  "\r",
  "\b",
  "\f",
  "\u0001",
  "\u001f",
  "é",
  "中",
  "€",
  "😀",
  String.fromCodePoint(0xd800),
];

describe("the decoder against a real encoder's output (property)", () => {
  it("decodes every generated value to the model, and announces exactly the lossy ones", () => {
    for (let i = 0; i < 200; i++) {
      const len = Math.floor(rnd() * 40);
      let s = "";
      for (let j = 0; j < len; j++) s += POOL[Math.floor(rnd() * POOL.length)]!;
      const lines = extract(
        JSON.stringify({ tool_name: "Bash", tool_input: { command: s } }),
      );
      // The whole case rides in the assertion, so a failure names its input.
      expect({
        i,
        s,
        got: commandOf(lines),
        lossy: lines.some((l) => l.startsWith("W\t")),
        failed: lines.some((l) => l.startsWith("E\t")),
      }).toEqual({
        i,
        s,
        // An empty value emits no record at all — there is nothing to check.
        got: s === "" ? null : model(s),
        lossy: isLossy(s),
        failed: false,
      });
    }
  });
});

describe("the decoder's pinned escapes (hand-written payloads)", () => {
  const raw = (command: string): string =>
    `{"tool_name":"Bash","tool_input":{"command":"${command}"}}`;

  it("decodes an ASCII \\u escape to the character — an escaped spelling is no bypass", () => {
    const lines = extract(raw("x\\u002ekube/config"));
    expect(lines.some((l) => l === "C\tx.kube/config")).toBe(true);
    expect(lines.some((l) => l.startsWith("W\t"))).toBe(false);
  });

  it("decodes a non-ASCII \\u escape to ? and says so (W)", () => {
    const lines = extract(raw("caf\\u00e9"));
    expect(lines.some((l) => l === "C\tcaf?")).toBe(true);
    expect(lines.some((l) => l.startsWith("W\t"))).toBe(true);
  });

  it("decodes DEL (\\u007f) to ? and says so", () => {
    const lines = extract(raw("a\\u007fb"));
    expect(lines.some((l) => l === "C\ta?b")).toBe(true);
    expect(lines.some((l) => l.startsWith("W\t"))).toBe(true);
  });

  it("decodes a malformed \\u sequence to a space — the old index()-1 garbage — and says so", () => {
    const lines = extract(raw("a\\uZZZZb"));
    expect(lines.some((l) => l === "C\ta b")).toBe(true);
    expect(lines.some((l) => l.startsWith("W\t"))).toBe(true);
  });

  it("maps \\b and \\f to a space and says so; \\t and \\r quietly", () => {
    for (const [esc, want] of [
      ["b", "a b"],
      ["f", "a b"],
    ] as const) {
      const lines = extract(raw(`a\\${esc}b`));
      expect(lines.some((l) => l === `C\t${want}`)).toBe(true);
      expect(lines.some((l) => l.startsWith("W\t"))).toBe(true);
    }
    for (const esc of ["t", "r"] as const) {
      const lines = extract(raw(`a\\${esc}b`));
      expect(lines.some((l) => l === "C\ta b")).toBe(true);
      expect(lines.some((l) => l.startsWith("W\t"))).toBe(false);
    }
  });

  it("passes raw non-ASCII through unchanged — a real encoder emits it raw", () => {
    const lines = extract(raw("café 中"));
    expect(lines.some((l) => l === "C\tcafé 中")).toBe(true);
    expect(lines.some((l) => l.startsWith("W\t"))).toBe(false);
  });
});
