---
name: sess16-stale-tenure-keepguard-fix
description: sess16: crash_consistency durable lost-update FIX (build 7187ED60) — stale-tenure (buf_gen != i_dlm_dir_gen) bypasses the in-AIL undestaged keep-guar…
metadata:
  type: project
---

## sess16 FIX for 2/tcp crash_consistency (build 7187ED6031A5F1F3D4958D6, deployed both nodes tcp).

## REPRODUCED + PROVEN (RULE 4, build 17DCD050, instr=0):
cc_blockdir_probe iter 2 lost `node2_f41.md5` — **gone from BOTH nodes (test2 the writer also `N`), does NOT resolve +8s = DURABLE loss, NOT visibility lag.** Confirms [[sess15-HEAD-status]] over [[sess-tcp-cc-ROOT-dir-entry-visibility-lag]]. dmesg: `DIR-STALE-SKIP ino=1961 blk=0 buf_gen=0 inode_gen=4 dirty=0 in_ail=1 pin=0 delwri=0 li_empty=1 has_bli=1 bli_flags=0x2` (ino 1961 reused across iters). instr=1 changes timing → bigger/different loss, NO DIR-STALE-SKIP (artifact; do NOT diagnose under instr=1).

## ROOT (refined): the durable clobber is in the RMW path (owned_ex), via `mxfs_dir_evict_data_blocks` (xfs_mxfs_dlm.c ~2043), NOT the read-hook DIR-STALE-SKIP (that's !owned_ex lookup visibility). The evict's keep-guard `(in_ail && !incarn_aba && undestaged)` SKIPS a previous-tenure leftover buffer → RMW reads stale base → drops peer's dirent. KEY: the evict runs ONCE per tenure at the FIRST modify after EX-acquire, when this node has committed NOTHING to the dir blocks this tenure → any in-AIL undestaged block there is a PRIOR-tenure/owner leftover (peer held EX in between, superseded it on LUN).

## DISCRIMINATOR: current-tenure work carries buf_gen == i_dlm_dir_gen (stamped at read OR at xfs_dir3_data_init); a leftover has buf_gen < i_dlm_dir_gen. sess15 incarn (i_generation) discriminator fired 0× — di_gen doesn't differ on reuse; buf_gen-vs-i_dlm_dir_gen is the right token (already in the proven signature: buf_gen=0 vs inode_gen=4).

## FIX (3 edits):
1. xfs/libxfs/xfs_dir2_data.c xfs_dir3_data_init (~742): `bp->b_mxfs_dir_gen = dp->i_dlm_dir_gen` after get_buf — a freshly-created block (get_buf, no read → buf_gen=0) gets the current tenure so it is NOT mistaken for a leftover and discarded (the freshly-allocated-current-block hazard).
2. xfs/xfs_mxfs_dlm.c mxfs_dir_evict_data_blocks (~2043): `bool stale_tenure = (dbp->b_mxfs_dir_gen != ip->i_dlm_dir_gen);` added to undurable term: `(in_ail && !incarn_aba && !stale_tenure && undestaged)`. Race-safe: evict→read→RMW→relog all under ILOCK_EXCL so xfsaild can't flush the stale BLI mid-window; the relog supersedes it.
3. xfs/libxfs/xfs_da_btree.c read-hook keep-guard (~3210): same `stale_tenure` bypass for !owned_ex lookup/readdir visibility. Same proven op as sess133 P133-INAIL-REFRESH (clear XBF_DONE on in-AIL), just triggered by stale_tenure.
Also: added lseq/wseq/undest to DIR-STALE-SKIP log line (xfs_da_btree.c ~3277).

## RESIDUAL RISK to watch: clearing XBF_DONE on an in-AIL UNdestaged buffer in the read path (Edit 3) leaves a lingering BLI whose logged content differs from the freshly re-read content — only matters on true crash recovery, not drop_caches (the test). If a regression appears (sf rename / cache_coherency), Edit 3 is the suspect; Edit 2 (modify path) is the load-bearing fix and is race-safe.

## NEXT: probe result (40 iters) pending; then FULL `./run.sh 2 tcp` must be 16/16 (esp. crash_consistency + no regression in cache_coherency/strong_consistency/rename), ideally 3×. Fallback build 17DCD050 (15/16). [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] [[sess15-incarn-fix-implemented-but-0-fire]]
