---
name: feedback-the-physical-pve-pair-is-old-hardware-so-minimize-hard-resets-and-restore-without-one
description: USER 2026-10-07: "pve1 is old hw like pve2 dont break them". A suite sysrq reset left pve1 off 37 min. Restore with pve_power.sh restore (no reset);…
metadata:
  type: feedback
---

**What happened (0.90.92 physical failover suite, 2026-10-07):** the suite reset pve1 (192.168.1.80) by sysrq-b three times in ten minutes (04:55, 05:00, 05:05 CDT). After the third, pve1 never booted: its journal has no boot between 05:05:30 and 05:42:29, so it stopped before the kernel. The suite failed the step after 300 s and stopped, leaving pve2 in its emulated power-off (nft isolation from pve1, DRBD and MXFS units held). pve1 came up at 05:42:29, two minutes after Wake-on-LAN magic packets were sent to its MAC 64:31:50:3a:8e:70 (from clyde and from pve2) — likely the wake, not proven.

**The user, on seeing it:** "wow did you break the other host too with all the reboots???" then "you gotta be careful - pve1 is old hw like pve2 dont break them".

**How to apply:**
- The physical pair (pve1/pve2) are old workstations with no BMC. Every hard reset costs wear and risks a host that does not come back. Never run reset-heavy steps back to back when a non-reset path tests the same thing; space resets out; do debugging and reproduction that needs resets on the nested pair (pve9-1/pve9-2, disposable VMs) instead.
- To end a run that stopped while a host was "off", use `tools/pve_power.sh restore <addr>`: it lifts the isolation in place and starts mxfs-drbd-guard then mxfs-drbd@mxfs, with no reset (measured: pve2 back to Connected Primary/Primary UpToDate in 95 s). `on` resets the host again.
- A host that does not answer after a reset: send `tools/wake_on_lan.py <mac> 192.168.1.255` before declaring it dead.
- Tell the user before starting a reset-heavy campaign on the physical pair.
