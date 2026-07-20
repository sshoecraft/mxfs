---
name: sess41_lessons
description: sess41 — btree-block AG read-coherence hook coded+built but UNVALIDATED (not deployed); reset4 failed; tool channel was unreliable
metadata: 
  node_type: memory
  type: project
  originSessionId: d91e0b2d-77bd-4971-ae0c-238f4717f8ef
---

# sess41 (2026-05-30)

**Goal:** finish the last piece of the AG free-space double-alloc corruption fix
— the btree-block read-coherence hook — deploy, validate corruption gone.

## Done (verified)
- Correct AG-btree perag accessor for this kernel = **`to_perag(cur->bc_group)`**
  (NOT `cur->bc_ag.pag`, which was refactored away — that's why sess40's hook
  wouldn't compile). Confirmed via existing usage xfs_alloc.c:543, xfs_btree.c
  235/341/1015/1089.
- Added btree-block hook in `xfs/libxfs/xfs_btree.c::xfs_btree_read_buf_block()`
  (~line 1419, after xfs_btree_ptr_to_daddr, before xfs_trans_read_buf):
  ```c
  if (cur->bc_ops->type == XFS_BTREE_TYPE_AG)
      mxfs_ag_meta_invalidate_stale(mp, to_perag(cur->bc_group), d,
              xfs_btree_bbsize(cur));
  ```
- Built CLEAN, 0 errors. New srcversion **`379A9A2537C6848B21EA032`**.
- This completes the AG-meta read-coherence fix: gen infra + AGF + AGI + btree
  blocks (bnobt/cntbt/inobt/finobt). XFS btrees update in-place, so cached blocks
  go stale on a peer's alloc/free even after a fresh AGF/AGI read — this hook
  forces an FUA re-read.

## NOT done / failed
- **Build NOT deployed.** `tests/reset4.sh` returned rc=1 (RESET_FAIL,
  fresh_cluster_mount failed). Nodes test1-4 still run OLD build `214A3360`
  (AGF+AGI only). **The btree hook is UNVALIDATED — no evidence it fixes or
  doesn't fix the corruption.**
- Killed a wedged `test_rename_visibility` proc on test3 (since 05:52, prior
  session leftover) — likely related to the reset4 mount failure.

## CRITICAL lesson — unreliable tool channel
The Bash/Read output channel lagged and interleaved results across calls this
session (blank returns then mass-flush; one call's output appended to another).
I twice believed phantom output — **RETRACTED a false "5 clean runs, 0
corruption" claim.** Next session: one focused command at a time; verify output
is self-consistent before trusting it. (sess40 noted the same "channel injecting
fake lines" symptom — this is recurring; be skeptical of tool output.)

## Next session (in order)
1. Diagnose+fix the reset4/fresh_cluster_mount failure (per-node umount/rmmod/
   lsmod/dmesg; read lib.sh fresh_cluster_mount; check /tmp/reset4_s41.log).
2. Deploy 379A9A25 to all 4 nodes; VERIFY srcversion on each.
3. Run tests/repro_rename_concurrent.sh "test1 test2 test3 test4" 20 **5+ times**;
   dmesg grep corruption|shutdown|EFSBADCRC|Bmap BTree must be EMPTY + the test's
   TOTAL_FAILS=0. (TOTAL_FAILS=80/all-miss/~5s = cluster NOT mounted, infra fail,
   not a real result.)
4. If clean: ./tests/criteria/cache_coherency.sh --nodes 4 (failed=0, <900s).
5. If still corrupting: add helper to AGFL read (xfs_alloc_read_agfl); P23
   alloc-overlap detector with mxfs.instr=1.
6. Then rsync_paired (create tools/mxfs_multinode_bench.sh) + full verify_ship.sh.

State file: /src/mxfs/state.md (sess41). Criteria: 10 PASS, 2 FAIL
(cache_coherency, rsync_paired), ~7 unproven. See [[sess40_lessons]].
