---
description: Revert snapshot trigger
globs: 
alwaysApply: true
---

# REVERT BACK CLAUDE

When the user says exactly **"REVERT BACK CLAUDE"** (in caps), immediately run:

```
git reset --hard 3e336f459a4dba58d9f3a3dd0d912db6a151a55a
```

in `/Users/soghatak/protocol-fuzzer`.

This is the stable snapshot taken on **28 June 2026** at commit `3e336f4` ("Commit on 15:02 PM, 26 June 2026").

This version has the working split-segment memory pressure approach (not the drip-feed) that achieved 60+ second CNT depletion on Snort.
