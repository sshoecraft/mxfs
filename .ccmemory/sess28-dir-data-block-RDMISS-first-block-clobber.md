---
name: sess28-dir-data-block-RDMISS-first-block-clobber
description: sess28 DECISIVE: dir_reuse 2/tcp remaining failure = node1's FIRST-wave dirents (node1_f1..f12, data files only, no .md5) clobbered from the dir's fi…
metadata:
  type: project
---

## sess28 — DECISIVE characterization of the dir_reuse 2/tcp remaining failure (after gen fix [[sess28-ROOTFIX-inode-revert-fresh-gen-on-create-reuse]])

### The missing entries (new tests/suite/dir_reuse_coherency.sh RDMISS logging, build 0270D870)
- `drc-RDMISS round=11 missing_from_readdir=[node1_f1 node1_f10 node1_f11 node1_f12 node1_f2 node1_f3 ... node1_f9]` = EXACTLY node1_f1..f12, **DATA files only, NO .md5**. 12 contiguous first-wave entries of NODE1. BOTH ranks agree (durable cross-node loss).
- Some rounds (e.g. 17) lose nearly EVERYTHING (~196) — a worse incarnation/timing variant, both nodes agree.

### Interpretation
The test creates per node: first a `dd` wave (node_fN data files), then a `md5sum` wave (node_fN.md5). node1's FIRST-wave data files (f1..f12) land in the dir's FIRST data block (block 0). Those exact entries are durably lost while their later-created .md5 siblings survive. This is the **"writer's first-dir-block entries clobbered"** pattern already named in xfs/libxfs/xfs_da_btree.c:3055 — a STALE cached first-dir-block (block 0) is read (peer miss) or RMW-clobbered, reverting the early dirents.

### RULED OUT (so the fix is NOT these)
- Inode-revert: P26-IGET-FAIL=0, lookup_fail=0 (gen fix C887AFA3 fixed it).
- di_size WRITE-revert: P133-DIRINO-REVERT=0 on both nodes (enabled under `iwr`).
- So it is purely a dir DATA-block (xfs_dir3_data_buf_ops, block 0) CONTENT lost-update.

### Mechanism hypothesis (RULE 4, for next session)
Concurrent add: the dir is recreated each round (rm-rf+mkdir → new incarnation, i_dlm_dir_gen reset). node1 adds f1..f12 to block 0, then both nodes keep adding (block 0 fills, spills to block 1). A node RMWs block 0 on a STALE base (its cached block 0 predates f1..f12, OR an ABA prior-incarnation block-0 buffer at the reused daddr with the SAME i_dlm_dir_gen=1 so the read-invalidation gen-compare (b_mxfs_dir_gen < i_dlm_dir_gen) does NOT fire), durably dropping f1..f12. The xfs_da_btree.c read-invalidation (3084+) only invalidates CLEAN buffers and keys on the monotonic i_dlm_dir_gen which RESETS per incarnation — likely blind to the ABA reuse (each fresh dir starts gen 0→1, matching a prior incarnation's stamp).

### NEXT (RULE 4)
1. Add a dir-DATA-block content-revert detector under `iwr` (analogue of P133/P56): before a xfs_dir3_data_buf_ops write, plain-read the on-disk block, compare live-dirent count (or xfs_dir2_data_hdr bestfree[0].length — emptier block = fewer entries); flag writing-fewer-over-more. Confirms write-side stale-base RMW vs durability.
2. Likely fix: make the dir block-0 RMW base FRESH across the per-round reuse — incorporate the inode INCARNATION (VFS_I(dp)->i_generation, now fresh per my gen fix) into the dir-block staleness stamp (b_mxfs_dir_gen) so an ABA prior-incarnation block-0 buffer is always invalidated; OR hard-invalidate ALL the dir's cached data-block buffers on a gen-mismatch reload (new incarnation).
3. Then full `./run.sh 2 tcp` ×3 = 100%.

### Build/keep state
- Build 0270D870 = gen fix (KEEP, the major win) + sess28 inode-write skip + `iwr` probes (P28-IWR/FREEWR/CREATE, P133 under iwr) + RDMISS test logging. Criterion NOT met (marker NOT written). Reboot cluster before runs (test2 rmmod-wedge after kills).
</body>
