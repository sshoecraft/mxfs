---
name: ccloop-c7ee71c6-sess148-STOP-host-jam-surgery-ABANDONED-work-the-ledger
description: sess148 DECISION: kcore workqueue surgery on clyde ABANDONED. Host jam is contained + does NOT block the rig (32 VMs healthy). User reboot is the saf…
metadata:
  type: project
tags: [host-jam, decision, STOP, loop0, rule2, sess148]
---

# sess148 — STOP the host-jam surgery. It is a rabbit hole. Work the ledger.

Sessions 141–147 (SEVEN sessions) were consumed by a host jam on clyde.
sess148 re-examined the premise and is ABANDONING the kernel-surgery track.
Do NOT resume the sess147 kcore/busy_hash un-swallow plan. Here is why.

## The decision (evidence-backed)
The sess147 plan: hand-write live kernel workqueue memory (hash_del a dead
worker under pool->lock, list_del a swallowed rootcg_work, re-init a corrupt
cmd list) then force-complete a stranded flush_rq — all on the LIVE dev host.
sess148 measured the situation; risk/reward does not justify it:

1. **Jam does NOT block the mission.** "Production ready" = clearing the
   28-defect RULE-6 ledger, tested on the rig = 32 VMs over iSCSI/SCST.
   Measured sess148: ALL 32 VMs running; test1 healthy (load 0.00, up 2d,
   mxfs mounts fine, ssh reachable). loop0 is a LOCAL fence-test artifact
   (backed by /var/lib/mxfs-fence/fio-backing.img), not the clustered FS.

2. **Jam is contained + stable.** 31G RAM free (of 94G), 86% CPU idle,
   load 521 = 517 D-state procs consuming ZERO cpu. Stable 3+ days
   (sess145→147→148 all ~521). Not growing toward OOM. VMs at load 0.00.

3. **Host is fragile — surgery is high-risk.** Even bare `ps -eo stat,comm`
   HANGS in the herd (sess148 hit this). Hand-writing kernel memory here
   risks a full host hang → the exact RULE-2-forbidden manual reset, which
   would kill all 32 VMs + iSCSI target + Claude itself.

4. **A user reboot is a STRICTLY BETTER fix.** It clears the jam completely
   and safely — including the leaked kernel structs the surgery would merely
   "accept as leaks." Same best-case outcome as surgery, none of the
   catastrophic downside. RULE 2 forbids ME rebooting but explicitly makes
   host recovery the USER's call; the user reboots clyde routinely for
   stress testing. No safe non-reboot clear of a stuck blk-mq flush_rq
   exists from userspace (no loop request timeout fires here).

## Disposition of the jam
- **loop0 quarantined**, leave attached (do not losetup -d — it would hang
  on the stranded flush). Backing image /var/lib/mxfs-fence/fio-backing.img.
- **A user-scheduled reboot clears everything.** Surface this to the user;
  it is not urgent (jam is harmless/contained) but it is the resolution.
- **User cron STILL PAUSED** (`#PAUSED-mxfs-sess145` in steve's crontab,
  runs mmrun/mmprocess every 10min). Do NOT restore it while the jam
  persists: mmprocess spawned the ffmpeg that is now the linchpin of the
  herd (THP fault holding mmap_lock); re-running it could feed the herd.
  After the user reboots, they should un-comment that crontab line. Note it
  for the user; do not restore it via surgery-cleared path.

## What sess141–147 DID accomplish (keep — real fixes, not jam-specific)
- sess146: released the leaked i_dio_count (inode_dio_release.ko) + the
  leaked i_rwsem reader (up_read_non_owner). Both were REAL fence-path leaks
  from the sess136 GPF. Those fixes stand.
- The proven root cause (fence stage-ii GPF leaks i_dio_count) is real fence
  code knowledge — relevant to D-PR-FENCE-PREEMPT-WITHOUT-ABORT.

## What the NEXT session should do
Work the RULE-6 ledger on the healthy rig. `./defects.sh` for the queue.
Top: D-FOREIGN-REPLAY-UNGATED-IMAGES. Do NOT touch loop0 / the herd / the
sess147 surgery plan. If fence testing is needed, use a FRESH loop device
(loop1+) or a VM — loop0's wedge is independent of other loop devices.
