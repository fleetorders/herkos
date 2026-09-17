/**
 * The hook's payload reader: a JSON extractor written in POSIX awk.
 *
 * The enforcement path must depend on nothing. It used to parse the tool call
 * with `jq`, so a machine or container image without jq announced "enforcement
 * OFF" on every call — the guard present, installed, and doing nothing. awk is a
 * POSIX utility that every such system and minimal image already has (BusyBox
 * included), and the hook already needs `grep` and `sh` from the same set.
 *
 * One pass over the payload emits one record per line:
 *
 *   T<TAB>tool name   the top-level "tool_name"
 *   S<TAB>session id  the top-level "session_id", when the harness sends one
 *   C<TAB>value       a string under a command-shaped key, at any depth of tool_input
 *   P<TAB>value       a string under a path-shaped key, at any depth of tool_input
 *   N<TAB>count       how many keys tool_input has directly
 *   E<TAB>reason      the payload could not be read (records before it still count)
 *   W<TAB>note        a checked value decoded lossily (see below) — records stand
 *
 * A tool_input that is present but not an object (an array, a string, a bare
 * literal) emits E rather than nothing: the argument vocabularies are keyed by
 * NAME, so a container without names cannot be read — it is announced, never
 * assumed safe.
 *
 * A value's embedded newlines are folded to spaces, so one value is always ONE
 * record, checked whole: a forbidden spelling cannot be split by a newline
 * inside it (a pipeline continued onto the next line), and a `^`-anchored
 * pattern anchors at the value's start, never at an embedded line start.
 * Array elements are read one by one,
 * nested arrays included. Every copy of a duplicated key is read — a
 * last-value-wins parser would see only the final copy. `\uXXXX` escapes are
 * decoded in keys and values (non-ASCII becomes "?"), so an escaped spelling of
 * a fragment is no way around it. Text that merely looks like JSON inside a
 * string is never taken for structure.
 *
 * The decoder is honest about what it cannot represent (D-008): a `\u` escape
 * of a non-ASCII codepoint decodes to "?", a control codepoint (or a malformed
 * `\u` sequence, or `\b`/`\f` — not shell whitespace) decodes to a space, and
 * the payload then carries a W record — the hook announces it rather than let
 * a rule silently not match text the decoder mangled. W rather than E on
 * purpose: the decoded text is still checked, and everything an ASCII pattern
 * can see is intact, so turning the whole call's enforcement off over one
 * non-ASCII character would trade real coverage for ceremony. Raw non-ASCII
 * bytes pass through unchanged — a real JSON encoder emits them raw, and only
 * escaped spellings are mapped. Patterns must be ASCII (policy.ts warns at
 * authoring); that is the note's other half.
 *
 * Built for large payloads: a value no rule reads (a megabyte of file content)
 * is skipped without being copied, the scan window grows over plain text and
 * shrinks around escapes, and a value that is read streams straight to output.
 *
 * Deliberately free of single quotes, so it embeds in the hook as one quoted
 * shell word.
 */
export const EXTRACT_AWK = String.raw`
BEGIN {
  n = split(pkeys, tmp, " ")
  for (i = 1; i <= n; i++) PK[tmp[i]] = 1
  n = split(ckeys, tmp, " ")
  for (i = 1; i <= n; i++) CK[tmp[i]] = 1
  HEX = "0123456789abcdef"
  openRec = 0
  badInput = 0
  lossyRead = 0
  sess = ""
}
{ doc = doc $0 "\n" }
END {
  s = doc; len = length(s); pos = 1; d = 0; failed = 0; sawTool = 0
  if (len <= 1) { fail("empty payload"); exit }
  while (pos <= len && !failed) {
    c = substr(s, pos, 1)
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { pos++; continue }
    if (c == ",") { if (d > 0 && ctype[d] == "o") wantkey[d] = 1; pos++; continue }
    if (c == ":") { pos++; continue }
    if (c == "{" || c == "[") {
      owner = ""
      if (d > 0) owner = (ctype[d] == "o") ? curkey[d] : ckey[d]
      root = (d == 1 && ctype[1] == "o" && curkey[1] == "tool_input" && c == "{")
      if (d == 1 && ctype[1] == "o" && curkey[1] == "tool_input" && c == "[") badInput = 1
      inner = (d > 0 && inInput[d])
      d++
      ctype[d] = (c == "{") ? "o" : "a"
      ckey[d] = owner
      curkey[d] = ""
      wantkey[d] = (c == "{")
      inInput[d] = (inner || root)
      isRoot[d] = root
      nkeys[d] = 0
      pos++
      continue
    }
    if (c == "}" || c == "]") {
      if (d == 0) { fail("unbalanced brackets"); break }
      if (isRoot[d]) printf "N\t%d\n", nkeys[d]
      d--
      pos++
      continue
    }
    if (c == "\"") {
      if (d > 0 && ctype[d] == "o" && wantkey[d]) {
        k = readstr(1, "")
        if (failed) break
        curkey[d] = k
        wantkey[d] = 0
        if (isRoot[d]) nkeys[d]++
        continue
      }
      if (d == 1 && ctype[1] == "o" && curkey[1] == "tool_input") badInput = 1
      tag = ""
      if (d == 1 && ctype[1] == "o" && curkey[1] == "tool_name") { tag = "T"; sawTool = 1 }
      else if (d == 1 && ctype[1] == "o" && curkey[1] == "session_id") {
        sess = readstr(1, "")
        if (failed) break
        gsub(/\n/, " ", sess)
        if (sess != "") printf "S\t%s\n", sess
        continue
      }
      else if (d >= 2 && inInput[d]) {
        k = (ctype[d] == "o") ? curkey[d] : ckey[d]
        if (k in CK) tag = "C"
        else if (k in PK) tag = "P"
      }
      readstr(tag == "" ? 0 : 2, tag)
      continue
    }
    if (match(substr(s, pos, 64), /^[-+.0-9A-Za-z]+/)) {
      if (d == 1 && ctype[1] == "o" && curkey[1] == "tool_input") badInput = 1
      pos += RLENGTH
      continue
    }
    fail("unexpected character")
  }
  if (!failed && lossyRead) printf "W\tlossy decode\n"
  if (!failed && d != 0) fail("truncated payload")
  if (!failed && !sawTool) fail("no tool_name")
  if (!failed && badInput) fail("tool_input is not an object")
}
function fail(m) {
  if (failed) return
  if (openRec) { printf "\n"; openRec = 0 }
  printf "E\t%s\n", m
  failed = 1
}
function put(tag, piece) {
  if (!openRec) { printf "%s\t", tag; openRec = 1 }
  gsub(/\n/, " ", piece)
  printf "%s", piece
}
function readstr(mode, tag,    buf, w, win, piece, ch, e, h, code, bad, hx, j) {
  pos++
  buf = ""
  w = 64
  while (pos <= len) {
    win = substr(s, pos, w)
    if (!match(win, /["\\]/)) {
      if (mode == 1) buf = buf win
      else if (mode == 2) put(tag, win)
      pos += length(win)
      if (w < 65536) w = w * 2
      continue
    }
    w = 64
    piece = substr(win, 1, RSTART - 1)
    pos += RSTART - 1
    if (piece != "") {
      if (mode == 1) buf = buf piece
      else if (mode == 2) put(tag, piece)
    }
    ch = substr(s, pos, 1)
    pos++
    if (ch == "\"") {
      if (openRec) { printf "\n"; openRec = 0 }
      return buf
    }
    e = substr(s, pos, 1)
    pos++
    if (e == "u") {
      h = tolower(substr(s, pos, 4))
      pos += 4
      if (mode == 0) continue
      code = 0
      bad = 0
      for (j = 1; j <= 4; j++) {
        hx = index(HEX, substr(h, j, 1))
        if (hx == 0) bad = 1
        code = code * 16 + hx - 1
      }
      if (bad || code < 32) piece = " "
      else if (code < 127) piece = sprintf("%c", code)
      else piece = "?"
      if (mode == 2 && (bad || (code < 32 && code != 10) || code >= 127)) lossyRead = 1
    }
    else if (mode == 0) continue
    else if (e == "n") piece = "\n"
    else if (e == "t" || e == "r") piece = " "
    else if (e == "b" || e == "f") { piece = " "; if (mode == 2) lossyRead = 1 }
    else piece = e
    if (mode == 1) buf = buf piece
    else put(tag, piece)
  }
  fail("unterminated string")
  return ""
}
`;
