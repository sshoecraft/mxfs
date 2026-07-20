---
name: sess26-leaf-rebuild-and-b5-bnobt-fix-progress
description: sess26: dir_reuse_coherency 2/tcp — FIXED leaf-hash hole (reliable leaf-rebuild) + bnobt double-free (B5 inact-skip on EX-EDEADLK). test1 PASSES; res…
metadata:
  type: project
---

## sess26 (ccloop 8ddb16a2) — TWO root fixes landed for the 2/tcp dir_reuse_coherency blocker. Build 68485F02386AAFFFD6423A4.

### Onion peeled — THREE distinct bugs, two now FIXED:
The criterion = full `./run.sh 2 tcp` (16 pass; sole FAIL = dir_reuse_coherency). At REAL timing the failure had THREE layers, exposed one at a time:

1. **Leaf-hash hole** (was: readdir=200, lookup_fail=97, all node2_f10+ missing from LEAF index but present in DATA blocks; durable both nodes; FS alive). **FIXED** by making the sess21 `mxfs_dir_rebuild_leaf_from_data` fire RELIABLY. Root: the flag-only trigger (`MXFS_IF_DIR_LEAF_STALE` set solely on an evict-SKIP of an undurable leaf, P21S) fired ZERO times in the failing run → rebuild never ran → a node durably destaged a SHORT leaf. **FIX**: arm the flag once per cross-node tenure in `mxfs_dlm_dir_modify_refresh` (xfs/xfs_mxfs_dlm.c ~2422): `if (new_incarn || dp->i_dlm_dir_gen != dp->i_dlm_dir_evicted_gen) xfs_iflags_set(dp, MXFS_IF_DIR_LEAF_STALE);` (computed BEFORE the evict updates evicted_gen/incarn). The rebuild reconstructs the leaf from the (coherent) DATA blocks unioned w/ plain-bio snapshot — only ADDs the peer's missing hashvals. CONFIRMED LEAF1 format (P26-REBUILD-OK nent up to 201, ndb=2, zero BAILs). lookup_fail 97→0.
   - NOTE: firing the rebuild on EVERY multi-node createname (first attempt, xfs_dir2.c gate `|| !single_node`) was REVERTED — 113x/run perturbed timing and tripped bug #2. Once-per-tenure (~82-116x) is the keeper.

2. **bnobt double-free shutdown** (`Corruption of in-memory data (0x8) at xfs_defer_finish_noroll`, xfs_defer.c:721; P47-INACT DISK-FREE + P81-DEXT incore-extent-stale + P28/P33 bnobt LEFT-FAIL). PROVEN ROOT: ino 1956 freed at t=64s, REUSED, then ifree'd AGAIN at t=86s — each ifree preceded by `DLM inode lock failed: ino=1956 mode=5 rc=-35` (EDEADLK). The sess78 TOCTOU fix (xfs_inode.c xfs_inactive ~2773) acquires the per-inode EX grant but on EDEADLK sets mxfs_inact_dlm_locked=FALSE and PROCEEDS to free without it; the unlocked FUA disk read is stale → B1 (disk_mode==0) misses → double-free. **FIX = B5** (xfs_inode.c ~2876, added to B1-B4 skip block): `bool mxfs_b5_nolock = !mxfs_inact_dlm_locked && !mxfs_local_unlink && ip->i_dlm_mode != MXFS_LOCK_EX && !xlog_recovery_needed(mp->m_log);` → skip destructive inactivation. RATIONALE: a node that legitimately unlinked an inode holds it EX (acquire returns 0); EDEADLK means we hold only NL/PR → STALE cached copy we don't own → real owner frees it. Wired into P19-B3DEC detector + skip cond + reason "ex-lock-unavailable-stale-copy". RESULT: NO MORE 0x8 bnobt shutdown; both nodes alive; **test1 now PASSES all rounds** (0 drc-FAIL).

3. **RESIDUAL (current blocker): test2 short readdir** = readdir=100-117/200, lookup_fail=0, FS alive. test1 reads full 200 from the SAME LUN → the LUN HAS 200 → test2's COLD read (drop_caches) is STALE, missing test1's (node1_*) entries. = DATA-block read-coherency divergence under reuse (sess15 "whole-block vanishes" family). Standalone tests/drc_probe2.sh (dir .drcp ino 2869): rounds 1-3 PERFECT (both nodes rd=200 n1=100 n2=100), round 4 test1 hit a *different* `Metadata I/O Error (0x1) at xfs_trans_read_buf_map` (xfs_trans_buf.c:313) shutdown — NOT bnobt (B5 held). The probe is harsher (test1 sole cold-reader + rm-rf + immediate reread).

### NEXT (sess27):
- Root-cause test2 short readdir: why test2's cold (drop_caches) readdir reads a stale/short dir DATA set while test1 reads full 200. Suspect: stale cached dir-inode (ino 131) bmap on test2 not dropped by drop_caches (pinned/referenced) OR FUA-reread of data blocks returns stale (SCST). Instrument the readdir/cold-read path: log dir inode nextents/i_size/data-block-count + per-block b_mxfs_dir_gen vs i_dlm_dir_gen on a multi-node dir read that comes up short.
- Investigate the probe's Metadata I/O Error 0x1 at xfs_trans_read_buf_map:313 (reading a metadata buf that errors — possibly a dir block at a freed/reused daddr). May share root with #3.
- Files changed sess26: xfs/xfs_mxfs_dlm.c (modify_refresh arm), xfs/libxfs/xfs_dir2.c (rebuild trigger comment, reverted to flag-only), xfs/libxfs/xfs_dir2_leaf.c (P26 rebuild diagnostics), xfs/xfs_inode.c (B5). tests/drc_probe2.sh (both-node n1/n2 probe).
- Repro: `bash tests/reboot_cluster.sh 2; timeout 600 ./run.sh 2 tcp dir_reuse_coherency` then grep both nodes dmesg `mxfs-drc-FAIL`. Marker NOT written.
</body>
