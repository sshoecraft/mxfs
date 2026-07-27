---
name: ccloop-c7ee71c6-sess12-E-32caw-ROOT-PROVEN-truncate-agwait-self-deadlock
description: sess12-E ROOT PROVEN from incident journal: 32/caw shutdown = single-node cycle — truncate (setattr_size→bunmapi) holds ILOCK+dirty trans, waits AG-1…
metadata:
  type: project
tags: [32-node, deadlock, agwait, bunmapi, truncate, rule4-proven, rule6, open]
---

# sess12-E: 32/caw spurious-shutdown ROOT — PROVEN (supersedes sess12-C/D theories)

## The cycle (all from test14 journalctl -k -b -2, incident boot, no new repro needed)
1. [562.269] P2G-LOGWHO ino=23068801 comm=bash pid=3393 callers: xfs_setattr_size →
   __xfs_bunmapi → xfs_defer_save_resources — the fence test's `: > file` TRUNCATE
   logged the ino (dirty trans) while holding ILOCK_EXCL.
2. [562.271] P1-AGWAIT ag=11 comm=bash pid=3393 trans_dirty=1 trans_held_ags=[] —
   blocks acquiring AG-11 for the extent-free.
3. [562.299] P12-WORK ag=11 enter holders=0 cached=1 page_ms=132502 — test14 ITSELF
   holds AG-11 cached and is mid-BAST-RELEASE (peer requested it); local acquires
   must wait for the release to complete ("peer-held" from the waiter's view).
4. [570..740+] P67-AG-BAST-STALL ag=11 every 3-8s forever; P67-INSTR names
   stuck_ino=23068801 ilocked=1 in_ail=1 — the release drain cannot flush the ino
   BECAUSE ITS ILOCK IS HELD BY THE WAITER (bash). page_ms 132502→310719.
   CYCLE: bash(ILOCK+dirty)→waits AG-11; AG-11 grant→needs release done;
   release→needs AIL flush of ino→needs ILOCK→bash. Single-node deadlock.
5. Writeback flusher piles behind the inode's locked folio (hung_task 625-776);
   [774] noino release fence hard-wall → designed shutdown (P-NOINO-RELFENCE-WEDGE
   policy: never unlock undrained) → withdraw → zombie.

## Class + coverage of existing mitigations
Design Tension "ILOCK held across CAW poll" — third instance:
- create path: FIXED v0.3.148 (drop dp ILOCK across xfs_dialloc, xfs_inode.c:1948).
- dirty-trans GROW path: P5G-AGLOCK-BOUNDED-BUSY skip-to-next-AG (xfs_mxfs_dlm.c:28718).
- P5D-PREWAIT-DEFERRED-BAST fires deferred inode BASTs pre-block — CLEAN trans only.
- TRUNCATE/extent-free (__xfs_bunmapi + deferred extent-free): NO mitigation — this hole.
N≥2 structural; 32-node BAST churn just raises the hit rate (1 hit / ~10 sequences).

## Fix design (next session; targeted at proven cause)
Preferred: PREACQUIRE the AGs the unmap will touch BEFORE the transaction dirties —
extent list is enumerable under ILOCK pre-logging; extend the existing
mxfs_trans_preacquire_inode_ags pattern (already used by rm-rf paths; grep it) to
xfs_setattr_size/xfs_itruncate_extents. Fallbacks: (b) waiter-vs-release deadlock
detect at AG acquire (fail -EAGAIN, restart trans — restart safety unclear);
(c) teach release-drain to detect the cycle and yield to the local waiter first
(grant-before-release inversion — protocol risk). NOT convert_delalloc (sess12-D's
theory — that path is exposed too in principle but the OBSERVED holder is truncate).

## Repro/verification apparatus (in tree)
tests/repro_32caw_wedge.sh (arm→chain→fail-closed harvest; 8 clean laps baseline,
1 natural hit / ~10 sequences) + tests/stallcap_watch.sh. Verification after fix:
loop until well past the historical hit rate (e.g., 30+ sequences) + P1-AGWAIT
prints must show trans_held_ags pre-populated (or zero AGWAIT-while-dirty).
Original evidence: test14 journal boot with the 11:03-11:24 window (was -b -2 at
save; boot offsets shift with every restart — locate by the 11:11 wall-clock era).
