---
"herkos": patch
---

`herkos discover` now reports an unreadable policy file on stderr, like every other command. The generated hook's comments are plainer; regenerate with `herkos init` to pick them up (enforcement is unchanged).
