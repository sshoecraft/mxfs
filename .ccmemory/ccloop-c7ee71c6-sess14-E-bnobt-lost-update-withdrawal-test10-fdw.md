---
name: ccloop-c7ee71c6-sess14-E-bnobt-lost-update-withdrawal-test10-fdw
description: sess14: NEW incident — test10 voluntary withdrawal during fence_during_write: bnobt lost-update double-free (P15 FREE-LEFT overlap; P81 DISK-INODE-OW…
metadata:
  type: project
tags: [bnobt, double-free, withdrawal, fence, replay, 32-node, open, w-replay-agmeta]
---

# sess14-E: bnobt lost-update → test10 withdrawal (fdw lap, 18:27, v0.11.123)

## Incident
Storm+chain lap at .123: fence_during_write FAIL "node10 no fence/shutdown in window
(exp=0 got=1)" — test10 (NOT the fenced victim) hit EFSCORRUPTED in an extent free and
performed the DESIGNED voluntary withdrawal (P-WITHDRAW-QUEUE → P163-WITHDRAW-STAMP
slot=30; peers fence + replay slice). Cluster stayed 31/32 healthy; recovery machinery
worked. But a healthy node shutting down = OPEN defect (RULE 6).

## Forensics chain (all within 2ms, test10 dmesg; full copy at
tests/logs/bnobt_20260726_1827_test10/test10.dmesg — 118k lines)
1. P15-INSTR FREE-AG-EXTENT-FAIL-LEFT agno=30 bno=294 len=2 ltbno=282 ltlen=13
   (282+13=295 > 294 ⇒ LEFT bnobt record OVERLAPS the extent being freed)
   caller=__xfs_free_extent ← xfs_extent_free_finish_item comm=bash.
2. P47-INACT agno=30 bno=294 inact_ino=62914707 disk_di_mode=0100644
   disk_di_gen==incore_gen verdict=DISK-LIVE-same-gen=>A-lost-removal
   (unlink inactivation found the DISK dinode still live).
3. P81-DEXT ino=62914707 disk_claims_freed=1 verdict=DISK-INODE-OWNS-FREED=>
   bnobt-lost-update (the disk inode still OWNS the extent being freed).
4. P28/P33 bnobt snapshot: leaf daddr=0x3be33b8 nr=3 rec0=(40,240) recN=(562,261091).
5. Then defer_finish_noroll dirty-cancel → "Corruption of in-memory data (0x8)" shutdown.

## Interpretation
The free-space btree (or the inode's durable removal) lost a cross-node update — the
AG-metadata sibling of the D3 dir/cluster staleness family. Context: fence_during_write
FENCES a node every lap ⇒ suspect vector = fenced peer's journal-slice REPLAY vs live AG
state (the standing watch item W-replay-agmeta; also sess121 P93 write-side stale-AG-meta
interlock, sess9-A drc Shape-2 family). My sess14 guards (P32E/P32D/P146D) fired ZERO
times on test10 — not fix fallout. First such shutdown in ~18 laps today.

## Next steps
- Reproduce with fdw laps; on hit, correlate: WHICH node freed extent (294,2)/removed ino
  62914707 earlier, was that node the FENCED victim, and did slice replay resurrect the
  pre-free bnobt/dinode state (replay writing stale AG meta over live)?
- The P144-WR bnobt write trace (always-on) + P150-FREE-IBT lines in the harvested dmesg
  give the write provenance; consider extending the P172 ring to bnobt/cntbt bufs
  (currently dir+inode-cluster only) for cross-node merge.
- Cluster required re-prep after (test10 unmounted/withdrawn).
