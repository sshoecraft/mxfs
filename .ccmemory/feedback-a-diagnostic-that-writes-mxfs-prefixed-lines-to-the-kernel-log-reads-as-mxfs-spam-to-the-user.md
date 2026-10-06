---
name: feedback-a-diagnostic-that-writes-mxfs-prefixed-lines-to-the-kernel-log-reads-as-mxfs-spam-to-the-user
description: USER complained of dmesg spam; pve1's steady 243 lines/h were our mxfs-diag-heat logger (every 15 s), not the module (4/h). Keep diagnostics off host…
metadata:
  type: feedback
tags: [pve, dmesg, diagnostics, user-correction]
---

The user has said kernel-log spam "is gonna piss off a lot of people". On pve1 (physical PVE pair) the kernel log showed a steady ~243 MXFS-looking lines per hour while idle. They were `mxfs-diag-heat:` lines from `tools/pve_crashdiag.sh on` (a temperature logger writing to /dev/kmsg every 15 s, installed to diagnose pve2's crashes); the module itself logged 4 lines in that hour.

**Why:** anything written to the kernel log with an `mxfs` prefix is, to the user, MXFS spamming dmesg, whoever wrote it.

**How to apply:**
- Before judging MXFS's log rate on a host, split the lines by source: `journalctl -k --since -60min -o cat | grep mxfs | sed -E 's/[0-9]+/N/g' | sort | uniq -c` separates module tags from `mxfs-diag-*`.
- Install kmsg-writing diagnostics only on the host under investigation, and turn them off (`systemctl disable --now mxfs-diag-heatlog`, or `tools/pve_crashdiag.sh off <host>`) when it is done. On pve1 the heat log was disabled 2026-10-06; netconsole and the softdog panic were kept for failover tests.
