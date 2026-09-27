---
"herkos": patch
---

A command holding a multi-byte character (an em dash, an accented letter, an emoji) no longer turns enforcement off when the character lands on one of the payload reader's window boundaries. The reader scans a string in byte windows; a UTF-8-aware awk (the one macOS ships) given a window that ended inside a character aborted on the half character, and the hook announced "could not read this tool call" and let the call through unchecked, then repeated the notice for the rest of the session. The hook now runs the reader under the C locale, which reads bytes; values pass through unchanged. A test puts 2-, 3- and 4-byte characters across every boundary up to byte 200, with and without an escape shifting the windows. Regenerate with `herkos init` / `herkos project init`.
