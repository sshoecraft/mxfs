---
name: trap-clyde-and-both-pve-hosts-share-unprotected-power-so-a-joint-crash-is-checked-against-clydes-boot-list-first
description: TRAP: pve1+pve2 'crashed' 13 s apart (2026-10-07 06:48); clyde's own boot had ended 06:47 too: shared power, no UPS. Check clyde's boot list first.
metadata:
  type: feedback
tags: [pve, power, clyde, crash-triage]
---

On 2026-10-07 pve1 and pve2 (the physical MXFS-on-DRBD pair) both showed a previous boot ending with no shutdown sequence, 13 s apart (pve2 06:48:07, pve1 06:48:20 by their own clocks), and `last -x` said "crash" for both. That looks like an MXFS double failure (both hosts self-fencing, a split, a shared hang).

It was not: clyde itself (`journalctl --list-boots` on clyde) had a boot ending 06:47:11 with no shutdown, rebooting 06:49:50. Three machines that share nothing but the building's power died together. Clyde has no UPS software (/etc/nut, /etc/apcupsd absent), no pstore entry, no oops. pve clocks run a minute or more off after a reset, so the offsets between the three are not meaningful.

**How to apply:**
- Before attributing a simultaneous pve1+pve2 death to MXFS, run `journalctl --list-boots | tail -3` and `uptime` on clyde. If clyde restarted in the same minute, it was power.
- A clyde restart also kills: the netconsole listeners (tools/pve_netconsole.sh start again; their pidfiles go stale), the nested pair VMs pve9-1/pve9-2 (not autostarted; `virsh -c qemu:///system start`), and any lap driver waiting on them (it aborts at its join budget).
- pve1 does not reliably power itself back on after an AC loss (it came back ~23 min after pve2), so a "down" pve1 after an outage needs Wake-on-LAN (tools/pve_power.sh), not a diagnosis.
- An unplanned outage is still a free power-cut test: check the pair rejoined (Connected, Primary/Primary, UpToDate, mounted) and run a chk_mxfs while it is unmounted.
