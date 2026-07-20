---
name: AAA-ccloop46ef-sess4-P15H-REAP-STORM-root-and-fixes
description: sess4 ROOT: victims = P15H strand-reap storm (45×/35s ino=135) force-releasing live grants → double-EX dark branch. Fixes in DD94481C: threshold 280,…
metadata:
  type: project
---

# sess4 (ccloop 46efd8b6) — P15H reap storm = the floor=1 victim producer

## Discriminator run 060826Z (build 9C813539, floor=1): cold-iget REFUTED
- P14 iget_age_ms = 10521-25068 (10-25 s) on all victims' holes → the dir inode was long-lived in-core; NOT a cold re-iget adoption. sess3's mechanism-(a) dead.
- Only 2 victims this run (test14, test20; shutdowns via same P14→i!=1→dirty trans_cancel chain at 06:14:58). All 82 test failures derivative of the 2 victims' renames never landing (`node14_after_* got=()` AND `node14_before_20` still present).

## THE DARK BRANCH (RULE-4 data, P-DIRDW global chg chain for ino=135)
- Published chg chain 11→1263 is SINGLE, monotone, healthy — every tenure boundary contiguous (gaps are mid-tenure unpublished batches; successor always continues from predecessor's last PUBLISHED image).
- test14: published 492-511 @06:14:46 (its create batch), then NOTHING until 728-744 @:51. Its P14 @:49 shows in-core iversion=649 nx=19 under dlm_mode=3(PR!)→5. 649 = adopted-589(test32's last publish, nx=15) + ~60 local rename ops → **test14 ran a ~3s parallel EX tenure (dark branch) while test7/test1/test3/test27/test2/test30 held real EX serially (published 590-727)**. Dark ops never published (write gates refused) → its renames LOST (the EIO/shutdown follows from walking mixed state).
- test14 fired P15H-STRANDED-RELEASE ino=135 gen=367 @06:14:47 — right at dark-branch birth. test20 (victim 2) fired P15H gen=399 @:54. **45 P15H reaps on ino=135 in ~35s across 23 nodes** (19 in ONE second @:39).

## WHY floor=1 (the A/B lever): under tenure-floor batching, waiters outlast MXFS_CAW_WAIT_TIMEOUT (poll abandons; ACQUIRE_WAIT retry ≤6s) → granted-but-unconsumed mirrors are LEGITIMATE for seconds; the sess15-H2 strand detector reaped at 4×25ms=100ms → mass false reaps → occasionally a reap wire-CAS races a just-promoted consumer (promote-CAS done, post-CAS check_exclusion/verify_grant_persisted SCSI reads stall 100ms+ under storm, in-core mode not yet EX, state≠ACQUIRING in some flavor — P7B storms show state=4 mode=0) → reap clears the fresh bit AFTER consumer's verify passed → phantom cached EX → dark branch. floor=0: grants consumed in ms, no reaps, no victims.

## Existing guards audited (all hold EXCEPT the razors)
- already-held shortcut stores meta via caw_grant_meta_store_unless_releasing (bumps grant_seq, refuses while `releasing`); wait-loop promote does caw_grant_seq_prebump before CAS (v0.6.4); unlock_gen(expected≠0) aborts -ESTALE on entry/in-loop seq movement (v0.6.2/3); P15-REL-ABORT re-checks holders post-drain; strike gate resets on mode≠NL/state==ACQUIRING/gen-turnover. P-SHORTCUT-RELWAIT=434, P-UNLOCK-REGRANT-ABORT=5, P6G-REL-STALE=2 in the failing run (the lattice IS under fire and mostly holds). DUP-SLOT=0 (dual-slot claim-race refuted), P106-STALE-EX=0, P109-CLR-DIVERG=0.
- HOLE-1 found by code audit: on CAW, p_rel_gen==0 at release decision fell into unlock_gen(expected=0)=LEGACY UNCONDITIONAL (every seq abort is expected!=0-gated) → unanchored wire CAS. (Meta bucket eviction — grant_meta is a no-chain hash table — can zero a live tenure's anchor.)

## Fixes in build DD94481C68301A88DB0E3B5 (v0.10.9, RUN LAUNCHED at session mid)
1. xfs_mxfs_dlm.c strike threshold 4→**280** (~7s at 25ms dwork re-arm) — above every legitimate unconsumed window (6s retry gap); true strands (sess15 netpartition wedge) still heal in ~7s.
2. **P6ZC-REL-NOANCHOR**: CAW + p_rel_gen==0 → skip wire unlock entirely (mirror of TCP P6Z arm); stranded-check via grant_gen-now.
3. P15H forensics: p15h_reap flag → P15H-PRE-UNLOCK (wire ex_popcount+nslots via mxfs_v5_dlm_inode_ex_count, cur meta gen) + P15H-UNLOCK-DONE (rc) around the anchored unlock; P15H print now includes state.
4. P-HOLE-DISK btree branch: unconditional btree_enter print (run 060826Z had fmt=3 headers with ZERO btree output — control-flow-impossible, must settle), read-fail/bad-ptr prints, and DISK_MAPS_WANT verdict for BTREE (was EXTENTS-only — why every fmt=3 failure shipped without the disk-vs-incore verdict).

## Next
- If run passes ×1: re-run for ×2, then trio (crash_consistency@32 needs floor ON), dir_reuse@16/@32, then full ladder 1/2/4/8/16/32 (`./run.sh N caw` each). Marker only on all-green evidence.
- If still failing: read P15H-PRE-UNLOCK/UNLOCK-DONE forensics — they name the exact interleave. Candidate escalation: post-grant wire re-verify on first dir-EX admit after slow grant + strike-window admits (design in sess4 transcript), or consume-fence.
- Windowing rule: ALWAYS filter kernlogs by run start; check `prep OK ... build <srcv>` in run output.
