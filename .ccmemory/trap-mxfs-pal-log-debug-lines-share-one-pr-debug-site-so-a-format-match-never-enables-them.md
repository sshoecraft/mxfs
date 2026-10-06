---
name: trap-mxfs-pal-log-debug-lines-share-one-pr-debug-site-so-a-format-match-never-enables-them
description: TRAP (0.90.64): mxfs_pal_log(MXFS_LOG_DEBUG) prints via ONE pr_debug("%s%pV") in pal/linux/kern.c; dyndbg `format "P-X"` can't enable it. Use mxfs_pr…
metadata:
  type: feedback
tags: [instrumentation, dynamic-debug, trap]
---

An instrument line written as `mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: P-TAUTH-IMPORT-RETAINED ...")` never appeared on the rig although `scripts/drbd_rig.sh`'s narrow dyndbg set enabled `module mxfs format "P-TAUTH-IMPORT-RETAINED" +p`. The run looked like "the retention never fired".

**Why:** `mxfs_pal_vlog` (pal/linux/kern.c) routes every MXFS_LOG_DEBUG call through a single `pr_debug("%s%pV\n", pfx, &vaf)`. Dynamic debug matches the format string of the pr_debug *call site*, which is `"%s%pV\n"` for all of them, so no tag can be enabled on its own; only `+p` on that one kern.c site enables all of them at once (a flood).

**How to apply:** a debug instrument that a harness must switch on by tag is written with `mxfs_probe(...)` / `mxfs_probe_ratelimited(...)` (pal/mxfs_probe.h: a pr_debug at the caller, format ends in `\n`). Use mxfs_pal_log(MXFS_LOG_DEBUG) only for lines nobody will select by tag. If an instrument line is absent, check which macro printed it before concluding the event did not happen. Absence of a debug line is not evidence until the site is known to be enabled.
