---
name: sess17-detector-refutes-enforce-and-cc-flaky-pass
description: sess17 (ccloop): dir-block xfsaild-skip built (CD4CAA1D); detector REFUTED enforce; real crash_consistency now PASSES 4/4+ (flaky race, not permanent…
metadata:
  type: project
---

## sess17 (ccloop) — build CD4CAA1DEA130A385B68E74, deployed both nodes 2/tcp.

## WHAT WAS BUILT (extends [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]]):
Dir DATA/leaf-block analogue of the proven P61 bmbt chokepoint skip:
- `mxfs_dir_data_track()` (xfs_mxfs_dlm.c) — MODIFY-time tenure stamp on dir3 data/block/leaf/free/node bufs, wired into xfs_trans_log_buf (else-branch after bmbt). Stamps b_tenure_id = owner dir's i_mxfs_ex_grant_seq.
- `mxfs_buf_xfsaild_skip_dir_write(bp, &info)` — submit-time predicate (NL-released OR b_tenure_id != cur epoch), fills `struct mxfs_dir_skip_info` for the detector.
- Chokepoint (pal/linux/xfs_buf.c ~1729, right after P61 bmbt skip): logs P16-DIRBLK-SUBMIT (gated dirwr/instr) for EVERY dir-block write; ENFORCE gated by new param `mxfs.dirskip` (default 1, ran with dirskip=0 detect-only).

## DETECTOR REFUTED THE ENFORCE HYPOTHESIS (RULE 4, dirskip=0 dirwr=1, cc_blockdir_probe iter1 ino131):
- Lost entry = node1_f1 (the FIRST file). P35E-DIRWR shows node1_f1 ABSENT from the EARLIEST captured image of block 536 on BOTH nodes (`. .. node1_f2 node1_f3 ...`). => dirent lost at INSERT time (shortform / sf->block / concurrent-RMW merge), NOT a stale xfsaild re-flush over a good image.
- ZERO nl=1 (NL-released) dir-block writes in the whole trace -> the NL-released reflush predicate never fires for this loss.
- tmism=1 would_skip=1 fired ONLY on tenure=0 blocks written by comm=dd/comm=ls = FRESH/conversion blocks (esp leaf1 daddr=2095120 during block->leaf: owner not set in header at first log -> track skips -> tenure stays 0). Enforcing tenure-mismatch would SUPPRESS LEGIT writes -> corruption. EXACTLY the [[sess23-ccloop-suppression-was-corruptor-3of4]] hazard. DO NOT enforce the tenure-mismatch arm for dir blocks.

## SURPRISE — REAL TEST PASSES (criterion = tests/suite/crash_consistency.sh, category=suite):
The actual criterion test (50 files/node into ONE shared dir, sync, drop_caches, every node re-reads every node md5) PASSED 2/2 on CD4CAA1D detector-only and 4/4 across repeats; criteria.json now shows all 16 @2/tcp = PASS. The probe (30 iters w/ mkdir+rm-rf daddr REUSE) is FAR more aggressive than the criterion and still loses an entry — but that is NOT the ship gate. The recorded baseline FAIL (10:55, 895603D7) was the prior run; crash_consistency appears FLAKY (race that doesn't always fire), consistent with memory notes that contaminated cluster state / instr timing perturb it.

## NOTE: with dirskip=0 the skip is INERT, so CD4CAA1D ≈ baseline 895603D7 functionally (only adds b_tenure_id stamp on dir-data bufs + detector). So 4/4 pass is likely flakiness/clean-state, not a code fix. NEXT: confirm full 2/tcp 16/16 in ONE clean run + repeat for reliability; decide whether probe's insert-time loss needs a real fix for "100%". Detector + param tooling KEPT. [[sess16-HEAD-status]]
