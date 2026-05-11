---
description: Run c-doctor health check on C code under the given path (defaults to the repo)
---

Run `./target/release/c-doctor` (relative to the project root) on `$ARGUMENTS` — or on `.` if no argument was given.

Before running, verify the binary exists. If it doesn't, build it first with:

```
cargo build --release
```

After running, briefly summarize for the user:
- The final score and label (Great / Needs work / Critical)
- The top 3 highest-severity issues (file:line, rule, one-line takeaway)
- Whether any rule fires repeatedly (a hint at a systemic pattern)

Do **not** fix anything as part of this command — the user is asking for a diagnosis, not a remediation. If they want fixes, they'll ask.
