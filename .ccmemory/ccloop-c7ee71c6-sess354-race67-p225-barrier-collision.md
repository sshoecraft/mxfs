---
name: ccloop-c7ee71c6-sess354-race67-p225-barrier-collision
description: sess354: #92 races 6/7 blocked by P225 mount barrier — B's mount classifies suspended A (zero live locks) as stale holder, 62s SETTLE-VERIFY; death t…
metadata:
  type: project
---

# sess354 — race 6/7 vs P225 mount barrier (proven, 2 runs)

## Mechanism (both runs INVALID, window 74s/66s vs <40s cap)
tests/clean_depart_lineage_race.sh suspends A, umount+remounts B, resumes
A after the mount SSH returns. B's kernel-side cycle is FAST (umount +
DLM re-claim ~12s; P163-CLEAN-DEPART-LINEAGE fires on peers instantly —
the #92 lineage arm WORKS). But B's mount(2) does not return: B's 10s
join scan sees suspended A's hb ts frozen → "slot N stale — will purge" →
stale mask includes A → P225-SETTLE-VERIFY 62s mount barrier → script
resumes A at ~66s → A fenced (REAL death threshold = 64s / 31 checks,
NOT the 87s in the test header).

## Two traps discovered
1. PREP_A (fresh umount+remount of A, sess350 advice) is WRONG: a fresh
   mount takes root-ino PR (ino=128, the ONLY live lock cluster-wide on
   an idle fleet) — that live authority made run 1 barrier WORSE.
   Long-idle nodes hold only tombstones. Use long-idle A and B.
2. Even with ZERO live locks held by A (verified caw_slotdump
   --held-only: nonempty=24 live=1(root PR by test2) tomb=23), B's mount
   still computed mask 0x400 = A's slot as "held authority at mount".
   OPEN QUESTION: how P225-STALE-DEFERRED derives holder-ship — likely
   from tombstoned lock records (last_ex_slot / lineage) in v5_mount.c.

## Test fix (next session, NO kernel change)
B's hb slot is re-ACTIVE on disk EARLY in mount (DLM claim, ~12s), long
before the barrier. Launch B's mount DETACHED (nohup), poll slotdump for
B's slot ACTIVE + seq advanced, resume A immediately (~15-20s window),
then wait for mount completion (P225 SETTLE-ALIVE once A resumes; proven
in run 1: "P225-SETTLE-ALIVE slot=4 ... not dead, leaving it alone").
Then run asserts. Also fix header threshold claim 87s→64s.

## Cluster at handoff
test5 fenced 17:44:24Z run 2, recovered+zeroed cleanly; needs
power-cycle + prep_node rejoin (flow in sbclean_fence_idle.sh step 4 or
this session's transcript). Others healthy on 0.13.3.

## Also this session
#94 closed FIXED AND VERIFIED (sbclean_fence_idle 2/2 PASS); #95
SB lost-update ledgered. open=42 of 95 (30 critical).
