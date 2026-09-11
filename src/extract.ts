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
 *   C<TAB>value       a string under a command-shaped key, at any depth of tool_input
 *   P<TAB>value       a string under a path-shaped key, at any depth of tool_input
 *   N<TAB>count       how many keys tool_input has directly
 *   E<TAB>reason      the payload could not be read (records before it still count)
 *
 * A value holding newlines becomes several records with the same tag, so every
 * line of a multi-line command is checked. Array elements are read one by one,
 * nested arrays included. Every copy of a duplicated key is read — a
 * last-value-wins parser would see only the final copy. `\uXXXX` escapes are
 * decoded in keys and values (non-ASCII becomes "?"), so an escaped spelling of
 * a fragment is no way around it. Text that merely looks like JSON inside a
 * string is never taken for structure.
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
      tag = ""
      if (d == 1 && ctype[1] == "o" && curkey[1] == "tool_name") { tag = "T"; sawTool = 1 }
      else if (d >= 2 && inInput[d]) {
        k = (ctype[d] == "o") ? curkey[d] : ckey[d]
        if (k in CK) tag = "C"
        else if (k in PK) tag = "P"
      }
      readstr(tag == "" ? 0 : 2, tag)
      continue
    }
    if (match(substr(s, pos, 64), /^[-+.0-9A-Za-z]+/)) { pos += RLENGTH; continue }
    fail("unexpected character")
  }
  if (!failed && d != 0) fail("truncated payload")
  if (!failed && !sawTool) fail("no tool_name")
}
function fail(m) {
  if (failed) return
  if (openRec) { printf "\n"; openRec = 0 }
  printf "E\t%s\n", m
  failed = 1
}
function put(tag, piece) {
  if (!openRec) { printf "%s\t", tag; openRec = 1 }
  gsub(/\n/, "\n" tag "\t", piece)
  printf "%s", piece
}
function readstr(mode, tag,    buf, w, win, piece, ch, e, h, code, j) {
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
      for (j = 1; j <= 4; j++) code = code * 16 + index(HEX, substr(h, j, 1)) - 1
      if (code >= 32 && code < 127) piece = sprintf("%c", code)
      else if (code < 32) piece = " "
      else piece = "?"
    }
    else if (mode == 0) continue
    else if (e == "n") piece = "\n"
    else if (e == "t" || e == "r" || e == "b" || e == "f") piece = " "
    else piece = e
    if (mode == 1) buf = buf piece
    else put(tag, piece)
  }
  fail("unterminated string")
  return ""
}
`;
