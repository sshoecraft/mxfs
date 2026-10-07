---
name: trap-a-reset-pve-hosts-journal-runs-minutes-off-until-chrony-slews-so-time-a-boot-in-monotonic-seconds
description: TRAP: after a reset pve1's clock ran 237 s fast (RTC; chrony slews); wall-clock journal times misplaced a boot, and the suite's --since @t0 windows r…
metadata:
  type: feedback
tags: [pve, journal, clock, measurement]
---

On the physical pair (HP Z400s), after a sysrq reset the host's clock starts from the RTC and chrony only slews it afterwards: pve1's boot of 2026-10-06 22:56 logged `chronyd: System clock wrong by -236.665655 seconds` at 24 s, and its wall-clock journal stayed ~3-4 min ahead of clyde for the rest of the night. Reading that boot's milestones in wall-clock time put network-online.target 224 s after the host answered ssh; in `journalctl -o short-monotonic` it was at 15.5 s. A whole defect record was drafted on the wrong numbers before the clock was checked.

The same skew breaks harness windows: tests/pve_pair_failover.sh asks `journalctl --since @$t0` with t0 from clyde's clock, so on a host running 237 s fast the window reaches back ~4 minutes into the previous step. answering-restart then reported "recovered ... 2 s after its reset" (an earlier step's P163-RECOVERY-COMPLETE); a refusal line from an earlier step would equally fail a healthy step.

- Time a boot's milestones with `journalctl -b -o short-monotonic`, and the kernel's lines with `journalctl -k -b -o short-monotonic`.
- Before trusting a log-window verdict on a host, compare `date +%s` there with clyde's; a harness should take t0 from the host it reads (`on HOST "date +%s"`, as promotion-race does), not from clyde.
- Fix the source: `chronyc makestep` then `hwclock --systohc` on the host, so the next reset boots with a correct RTC.
