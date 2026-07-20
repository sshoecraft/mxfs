---
name: sess9run-FIX26-bast-midtrain-upgrade-release-abort
description: sess9 FIX-26 (build 1F9B6D4E, VERIFIED repro-level): bast_process released mid-drain upgrade grant → phantom cached EX → same-aoff concurrent dir add…
metadata:
  type: project
---

# FIX-26 — bast_process releases a mid-drain upgrade grant (dir_reuse one-name loss root)

## Symptom
4/tcp dir_reuse_coherency FAIL: readdir=399/400, ONE .md5 name missing on ALL nodes (drc-CLASS: LOOKUP_ENOENT REREAD_MISS — durable data loss, NOT the leaf/walk-shadow variant). Repro ~1 in 3 standalone runs (run 20260703T141319Z FAILed, victim node4_f27.md5).

## Proven mechanism (realns-anchored, run 20260703T141319Z)
1. t4 held PR; a peer's request queued a BAST → bast_process entered for the PR tenure (P70-BP ENTRY mode=3).
2. Mid-drain, t4's own pending EX create request was granted: **gen=98 EX arrived during the drain** (P37-GRANT-RECV EX gen=98 during bast drain window).
3. P15 holders re-check passed — the woken waiter had NOT yet incremented ex_holders.
4. p_rel_gen was captured POST-drain (line ~10239) → captured 98 (the new grant!) → gen-aware unlock compared 98==98 → **released the just-granted EX** (P51-REL held_mode=3 while P6U-UNLOCK mode=EX gen=98).
5. Waiter resumed, set i_dlm_mode=EX (phantom — no on-disk grant), served creates.
6. Master granted gen=99 EX to t2. **Both nodes streamed adds concurrently: t2 node2_f31@aoff=184 and t4 node4_f27.md5@aoff=184, 1.8ms apart, same block daddr=2095128.** Last writer (t2 lineage) erased t4's dirent.

## Fix (xfs_mxfs_dlm.c bast_process)
- Capture `p_entry_gen = mxfs_v5_dlm_inode_grant_gen(...)` at bast ENTRY (pre-drain, right after P70-BP ENTRY print).
- Extend the P15-REL-ABORT condition: abort release also when `p_rel_gen != 0 && p_rel_gen != p_entry_gen` (tenure advanced under the drain). Print gains gen_moved/entry_gen/now_gen fields.
- TCP-only by construction (grant_gen returns 0 on CAW).
- Composes with the existing post-NL ESTALE guard (11549 unlock_gen): entry-gen covers [entry→10239]; ESTALE covers [10239→unlock].

## Verification
- 4 consecutive standalone PASSes post-fix (was ~1/3 FAIL).
- **P15-REL-ABORT gen_moved=1 fired 49-68× PER NODE PER RUN** (t2=68 t3=62 t4=49 in the first passing run) — the race is constant traffic; every fire was a would-be phantom-EX window.

## Diagnostic ledger added this session (KEEP)
- P9-LFREE at xfs_dir2_data_make_free (xfs_dir2_data.c): logs every byte-range free in storm-dir blocks with the live dirent name at the freed offset. Discriminator: victim name in P9-LFREE ⇒ local free; absent ⇒ image-level divergence. (This failure: only comm=rm frees — image-level.)
- P13-LADD now prints realns for cross-node ordering.

## Session-8 run112 note
The old readdir-tear memory (sess8-part3) attributed run112 to xfsaild dir-block writeback — cross-node dmesg timestamps there were NOT wall-aligned; with realns anchors the run112 shape is consistent with THIS DLM race instead (t3 f31/t4 f19.md5-era concurrent adds). The P3W skip-guard thread is likely moot; do not pull it further unless a new failure shows a genuine out-of-tenure xfsaild write WITH realns proof.

## Residual leads seen but NOT yet chased (lower priority)
- t2 adds continuing (f48-f50.md5) after a kworker release-drain write mid-round with a buffer lineage reset — did not cause this loss; watch for it in future failures.
- A never-logged (lseq=0) leaf1 write by kworker during the verify window on t2 (daddr=6279744).
