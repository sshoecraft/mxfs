---
name: sess21-PROVEN-root-pinned-leaf-staleRMW-and-gpt-rebuild-fix
description: sess21 PROVEN root of dir_reuse_coherency leaf-hash hole + GPT-5.5 rebuild-leaf-from-data fix design. Build 4942DEC9.
metadata:
  type: project
---

## sess21 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp leaf-hash hole: ROOT PROVEN + fix design.

## REFUTED this session (RULE 4): the sess20 "cross-node dir FORMAT divergence / reload self-skip" reframe. Detectors P21-SELFSKIP-DISKAHEAD=0 and P58=0 on both nodes → the dir reload self-skip is NOT the locus. (block↔leaf are BOTH di_format=EXTENTS; only di_nextents differs — verified vs kernel xfs_dir2_block.c/leaf.c.)

## PROVEN ROOT (fresh instrumentation, build 4942DEC9, DRC_ROUNDS=15, NO dirwr — dirwr=1 CHANGES the failure mode, do NOT diagnose with it):
- The shared dir's SINGLE leaf block (daddr 2093296, ino 131) is **perpetually pinned+undestaged** (`P21S-EVICTSKIP-LEAF ino=131 pin=1 undest=1 dirty=0 in_ail=0`, fired 60× test1 / 365× test2). Every create touches the one leaf block → CIL never quiesces it. DATA blocks are NOT perpetually pinned (each dirent → one of several data blocks → they quiesce → evict refreshes them → readdir is COMPLETE=200).
- The acquire/reader evict (mxfs_dir_evict_data_blocks AND mxfs_dir_drain_evict_data_blocks) SKIPS the pinned leaf (can't clear XBF_DONE while pinned → lost uncheckpointed delta = sess64 corruption). So a node acquires EX with a STALE in-core leaf (missing peer's recent hashvals), inserts its own entry, and destages it → durably DROPS the peer's hashvals. readdir lists the names (data coherent) but lookup ENOENTs (leaf missing hashvals) = the durable leaf-hash hole. ALWAYS the peer's (rank2/non-owner) entries.
- The release drain DOES destage the leaf (via xfs_log_force(SYNC)+xfs_ail_push_ag_sync at xfs_mxfs_dlm.c ~4392-4396; P21F-RELFLUSH-LEAF=0 only because the AIL push lands it before mxfs_dir_flush_data_blocks's bwrite). So release is fine; the bug is ACQUIRE keeping a stale pinned leaf.
- Test FAILS round ~15 (lookup_fail of node2_*), then round ~17 test2 SHUTS DOWN (xfs_create→xfs_trans_cancel dirty-cancel corruption, secondary). Cap DRC_ROUNDS=15 to repro the hole WITHOUT the shutdown wedge (faster cycles).

## WHY prior fixes don't work: merge-via-separate-DLM-acquire = TCP DLM timeout shutdown (sess18 dead-end). force-evict-on-release = resurrection (sess96). bounded pin-drain at acquire = storm re-pins faster (sess74/97); unbounded = 5.5× slowdown (sess97). Clearing XBF_DONE on pinned = corruption (sess64).

## GPT-5.5 FIX DESIGN (the leaf is DERIVED metadata; rebuild from coherent DATA inside the modify's OWN tp+grant — NO extra DLM acquire, NO XBF_DONE-clear-on-pinned):
1. **Detect**: acquire-evict, when a LEAF/FREE block is SKIPPED because pinned/undestaged, set inode flag MXFS_DIR_DERIVED_STALE. If a DATA block is skipped, set MXFS_DIR_DATA_UNSAFE. (Cheap: only flags on skip.)
2. **Repair**: at top of xfs_dir_createname/removename/replace (holding dir ILOCK_EXCL + tp + cached EX grant), if DERIVED_STALE: rebuild the leaf hash index (and LEAF1 `bests`/tail, or NODE free blocks) by scanning the coherent in-core DATA blocks (xfs_dir2_hashname + xfs_dir2_db_off_to_dataptr per live dirent, sort by (hashval,address)), OVERWRITE the (possibly pinned) leaf buffer in-core, and `xfs_trans_log_buf(tp, leaf_bp, 0, blksize-1)` — RELOG, do NOT evict. Relogging a pinned buffer is normal XFS (CIL relogs pinned metadata) — this supersedes the stale image safely. Clear the flag.
3. **Lookup fallback**: while DERIVED_STALE, lookup via data-block scan (not the stale leaf) to avoid transient ENOENT + duplicate-create (EEXIST) races.
4. **Reservation**: add log res for one full leaf block (+free block) to clustered dir-modify transactions (create/remove/link/rename) — the repair logs the whole leaf.
5. **Safety**: rebuild ONLY when DATA is proven coherent (MXFS_DIR_DATA_UNSAFE blocks it → small bounded data-block refresh first; DATA quiesces so cheap). Scope to LEAF format first (don't truncate if entries overflow leaf cap → that needs node-format conversion). Clear flags on reclaim/format-change/truncate/shutdown. Deletes/rm-rf safe because rebuild scans CURRENT data (deleted = unused region = omitted), as long as DATA is fresh.

## STATUS: fix NOT yet implemented. Build 4942DEC9 has detectors P21S-EVICTSKIP-LEAF + P21F-RELFLUSH-LEAF (xfs_mxfs_dlm.c) + P21H-LEAFHOLE (xfs_dir2_leaf.c leaf_lookup_int, fired 0× → failing lookups use leafn/other path, not leaf1). Harness fixes this session (KEEP): run.sh asserts per-node srcversion==local .ko (catches stale-build deploy — test2 was silently running an OLD module → INVALID prior results incl. some sess20 conclusions); prep_node.sh umount -f + rmmod retries for shut-down mounts; MXFS_TEST_ENV passthrough; tests/force_reset.sh helper.
