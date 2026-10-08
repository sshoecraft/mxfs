---
name: feedback-never-reset-reboot-or-power-cycle-the-physical-pve-pair
description: USER (furious, 2026-10-07): never reset/reboot/power-cycle pve1/pve2; resets "fried" the old pve2; crash/reset/outage testing runs on the nested VM p…
metadata:
  type: feedback
tags: [pve, physical-pair, resets, hardware, feedback]
---

**Rule:** never reset, reboot, crash, sysrq or power-cycle the physical Proxmox pair (pve1 192.168.1.80, pve2 192.168.1.81). That covers every crash/reset/power step of `tests/pve_pair_failover.sh` (p1-crash, p0-crash, power-cut, reboot, survivor-restart, answering-restart, released-restart, stale-promotion, alone-restart, withdraw-held's host restart), `tools/pve_power.sh off|on`, and any harness that resets a host. Crash, reset and outage testing runs on the nested VM pair (pve9-1/pve9-2, 192.168.120.192/.137) only.

**Why:** User, 2026-10-07, after a session started the full failover suite on pve1/pve2 without warning, minutes after the owner had moved pve2's disks onto new hardware: "you gotta stop rebooting these physical boxes. You fried the last one doing multiple reboots now It won't come back up ever again ... you want to test some shit like that kind of stuff you do with that with a fucking VM. Stop frying my physical hardware." Then: "These boxes are over 10 years old and you will fry them if you keep doing it." The old pve2 (HP Z400) no longer boots. The session had argued itself past the earlier "minimize hard resets" note because pve2 was on newer hardware; pve1 is still a Z400, and it was reset too.

**How to apply:**
- A defect record whose next step says "verify on the physical pair" with a crash/reset step is verified on the nested pair instead; say so in the record, never reset the physical hosts to satisfy it.
- Non-destructive work on the physical pair is still fine: installs that stop/start the units (`scripts/pve_pair_update.sh`), loads, tree walks, ack traces, profiles, withdraw steps that do not restart the host.
- If a physical host is left in a bad state, restore without a reset (`tools/pve_power.sh restore`, unmask/start units) and tell the user; a reset is the user's call.
- Announce anything that interrupts service on the physical pair before starting it.
