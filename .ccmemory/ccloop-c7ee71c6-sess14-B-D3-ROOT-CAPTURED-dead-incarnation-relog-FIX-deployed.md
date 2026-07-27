---
name: ccloop-c7ee71c6-sess14-B-D3-ROOT-CAPTURED-dead-incarnation-relog-FIX-deployed
description: sess14: D3 ROOT CAPTURED by P172 ring+stacks (ino167: bailed reload → P146V re-log at NL → iflush_cluster clobber by test28/test6) — FIX v0.11.120 de…
metadata:
  type: project
tags: [d3, root-cause, data-loss, ring-capture, dead-incarnation, fix-deployed, verify-pending, 32-node]
---

# sess14-B: D3 co-resident stale clobber — ROOT CAPTURED, FIX DEPLOYED (v0.11.120)

## The hit (2026-07-26 16:17, lap 12 of the day, v0.11.119, dirwr=0, P172 ring armed)
cache_coherency 32/caw: rv phase — test1's rename node1_before_1→node1_after_1 (ino 167,
cluster daddr=160 slot 7) invisible on 22/32 nodes. LIVE SPLIT captured: test1 serves ino167
= FILE (-rw- size 12, 16:17, gen 149684498); test2 serves ino167 = DIRECTORY (drwx, 16:07,
gen 3554082434) = the wedge_load storm-era dir incarnation. Harvest:
tests/logs/d3ring_20260726_161854/ (all 32 full dmesg + 8192-entry P172 rings + criteria row).
NOTE the aggregate measured said "failed=0" (rank1-derived) — real hits can hide there;
d3_dirring.sh now also parses per-node reasons.

## Ring forensics (tests/d3_ring_analyze.py --daddr 160 --slot 7)
- #4001 16:17:03 test1 xfsaild SETS slot7 (rv create, FILE, dirmask clean) — current truth.
- **#4008 16:17:08.686 test28 kworker/u10:10 pid41150, #4009 +2ms test6 kworker/u12:4
  pid21305: both write daddr160 with dirmask bit7 SET (slot7=DIRECTORY = stale storm image),
  fl=- (no delwri/BLI/DONE)** — the durable clobber writes, named node+path+moment.
- test1's own #4010 (16:17:19) then carries the stale dir bit too (stale platter propagated
  back into its buffer — the P13-SLOTPATCH suspicion confirmed as a propagation vector).

## Full anatomy on test28 (dmesg, all within 14ms; identical on test6)
1. RELOAD-TYPEFLIP-DIRENT-OK ino=167 incore=040755/gen3554082434 disk=0100644/gen149684498 —
   reload validated via PARENT DIRENT that disk is the live incarnation (ground truth).
2. P34J-RELOAD-RACE-BAIL — release drain active → adoption DISCARDED (verdict lost).
3. P146V-UNLANDED — drain's durable stage saw clean-but-mismatched dinode, diagnosed
   "phantom retire", RE-LOGGED the dead dir core (v_behind includes gen-mismatch!).
4. P58-DIRPIN-NONEX — that commit ran at dlm_mode=0 (NL, no authority) + dump_stack:
   xlog_cil_commit ← mxfs_dlm_bast_process+0x4dab (workqueue mxfs-ino-bast).
5. Second stack: bast_process+0xd71 → xfs_iflush_cluster → xfs_iflush wrote the slot
   (P32-IFLUSH-NXSHRINK extent-map revert + P-DIRDW daddr=160+7 INCLUDED-logged) →
   P146-RELDUR wrote=1 → P138-BAST release completed. Platter now stale → 22 nodes adopt it.

## The fix (v0.11.120, srcver 151AB51D362BF70064D5A0A)
New field xfs_inode.h: `i_mxfs_dead_incarn_gen` — set at RELOAD-TYPEFLIP-DIRENT-OK
(disk's di_gen recorded as the live incarnation; we are the corpse), cleared on successful
adoption (post from_disk), on TYPEFLIP-STALE-SKIP (in-core judged live), and at init
(xfs_mxfs_dlm.c:26001 block).  Consumers:
- Arm 1 (xfs_mxfs_dlm.c P146V site ~13977): if marker matches buffer's di_gen (≠ our gen) →
  P146D-DEADINCARN, skip the re-log, flushed=true (nothing of ours to land; i_dlm_stale
  stays set → post-drain access adopts disk).
- Arm 2 (xfs_inode.c xfs_iflush, after P32F fence): same predicate → P32D-DEADINCARN-SKIP,
  XFS_ISTALE_CAW + stale_src=24, error=0 goto flush_out (P32F idiom) — covers dirty-BLI
  paths (xfsaild/reclaim) that bypass P146V.

## Verification protocol (RULE 4 2b — pending)
Recipe laps at .120: a recurrence of the precondition shows RELOAD-TYPEFLIP-DIRENT-OK +
P146D/P32D markers WITH cc PASS (no rename loss) = fix verified at the proven site. The
trigger recurred ~1/12 laps today — grind storm+cc and storm+chain laps. Watch: any NEW
loss shape with markers firing = another path (analyze fresh ring harvest).
D1 fix (sess14-A, cancel_work nowait) also in this build — keep counting its laps too.
