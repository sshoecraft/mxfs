---
name: trap-a-test-nodes-journal-since-boot-holds-older-builds-and-older-boots
description: TRAP (0.89.90): measuring a build's kernel log from a rig node's journal: `-b -1` on test2 was a July boot of a months-old module; window by --since…
metadata:
  type: feedback
tags: [logging, measurement, rig, journal]
---

Measuring what one build prints (log-level work, probe counts) from a rig node's persistent journal is only valid over the window that build was loaded.

What bit: to fill in a node that rebooted mid-suite, `journalctl -k -b -1` on test2 was taken as "the previous boot" — it was a boot from **2026-07-01**, three months and hundreds of builds earlier (P68-EVDECIDE 29,600 lines, tags that no longer exist). Counting it would have described a module that no longer exists. Separately, a node's current boot can span several module loads of different builds.

How to apply:
- Window by time, not by boot: `journalctl -k --since "<the build's load time UTC>" -p info` on each node.
- Check `journalctl --list-boots` before using `-b -N`; a node's previous boot can be arbitrarily old.
- `-p info` excludes pr_debug, so on a probes-on rig run it shows exactly what prints by default — except `callbacks suppressed` lines and probe-gated stack dumps, which are artifacts of probes being on.
- A message whose format has no match in the current source (e.g. `P-PRKEY-REGISTERED idx=`) may be a `%s`-built tag (`"P-PRKEY-%s idx="`) — check for that before concluding the line came from an older build.
