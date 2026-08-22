---
name: ccloop-c7ee71c6-sess283-dlmfairness-root-agwait-relock-convoy
description: sess283: dlm_fairness NO_TERMINAL_RECORD root = agwait_handoff relock holds ILOCK across 480s cross-node dir-EX wait (violates FIX-L3), ag=6 convoy
metadata:
  type: project
---

# sess283 — dlm_fairness FAIL root-caused (0.11.500, live scene test14)

## Mechanism (evidence-backed, live wedge observed 20:33-20:39Z 2026-08-14)
- mv (rename): xfs_rename → mxfs_trans_preacquire_inode_ags → mxfs_trans_agwait_handoff(ag=10) → relock loop (xfs_mxfs_dlm.c:40918-40925) → blocking xfs_ilock ascending → caw_wait_for_grant on dir ino=41943202 EX, 480s, rc=-110.
  - P139-LOCKTOTAL ino=41943202 req=5 rc=-110 total_ms=480083
  - P-ACQ-STUCK slot=53582 hex=40 → EX held by NODE SLOT 6, w=ffffffbf (31 waiters), el_ms=479311
- While waiting, mv held earlier-relocked inode's ILOCK → P67 AG-AIL-STALL agno=6 stuck_ino=25179842 ilocked=1 → ag=6 drain poisoned → test14's cached ag=6 EX (slot bit31) never released (P12-AGBAST-RX page_ms→480067) → ~30 nodes D-state P1-AGWAIT ag=6 → bdi flusher + sync D-state on test13/test14 → dlm_fairness `sync` never returns → coord_done never runs → NO_TERMINAL_RECORD=32.
- Self-resolves ONLY at the disk-lock liveness cap: "disk lock acquisition timed out after 480078 ms (base 120000, liveness-extended cap 480000)".

## Root
mxfs_trans_agwait_handoff relock loop uses plain blocking xfs_ilock per inode: holds inode[i-1] rwsem+admission across inode[i]'s unbounded cross-node wait. Violates sess16 FIX-L3 invariant (xfs_inode.c:879-901): cross-node DLM waits only with NO rwsems held — Phase A (all DLM grants, ascending ino), Phase B (rwsems nowait). Fix shape: apply Phase A/B in the relock (or reuse xfs_lock_inodes). RULE-5 consult before landing.

## Unverified legs / open
- Node slot 6 host identity + why it held dir 41943202 EX for 480s (likely its own op parked on ag=6 holding the dir admission — phantom-admission family).
- Whether rc=-110 force-shutdown test14's FS afterward (xfs_inode.c:2335 comment implies ilock_begin force-shutdown; node looked alive at 20:45).
- P15-REL-ABORT orph=1 ino=41943202 on test14 at 2322s (release aborted, holder re-acquired) — same ino, same second mv began waiting; role unclear.

## Techniques that worked
- run.sh precheck "sync-wedged" node-fault = live specimen alarm; inspect BEFORE re-prep.
- /proc/PID/stack D-state sweep fleet-wide in parallel; P12-AGBAST-RX cached=1 page_ms climbing identifies the drain-poisoned AG holder; P-ACQ-STUCK gives on-disk holder bits for the stuck inode; scripts/caw_slot_dump.py --ino/--ag/--type for on-disk lock words (run on a node against /dev/mapper/mpatha).
- P131-WAITLONG only logs on grant SUCCESS — absent during a live stall.
- bpftrace on nodes exists; caw_nudge_wait.part.0 entry probe won't re-fire (single call, internal loop); caw_nudge_ring_wants_wake is inlined.
