---
name: sess20-residual-is-daddr-reuse-corruption-not-leafhash
description: sess20: the cc_blockdir_probe REUSE-churn residual is a SEPARATE deep bug (dir-block verifier failure during addname under inode/daddr reuse → xfs_tr…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — the cc_blockdir_probe REUSE-churn residual is the historical daddr-reuse corruption family, distinct from the FIXED leaf-hash lost-update.

## CONTEXT: official ./run.sh 2 tcp = 16/16 ×3 (criterion MET, marker YES). That suite does concurrent same-dir creates but NO rm-rf reuse churn. cc_blockdir_probe adds rm-rf+recreate each iter (reuses dir ino 131 + its leaf/data daddrs). User asked to add a suite test for it (tests/suite/dir_reuse_coherency.sh, registered in criteria.json+manifest, coord=barrier) and debug.

## FINDING (build E0C391F3 reada=1 dirwr=1, cc_blockdir_probe 40 50): under reuse churn the FS SHUTS DOWN on BOTH nodes. Trace (identical both nodes):
```
xfs_da_read_buf -> xfs_corruption_error (dir DATA block fails verifier during addname)
  -> xfs_dir3_data_read -> xfs_dir2_leaf_addname -> xfs_dir_createname -> xfs_dir_create_child -> xfs_create
  -> xfs_trans_cancel (DIRTY trans) -> "Corruption of in-memory data (0x8)" xfs_trans.c:1061 -> Shutting down
```
P16 (test1, the failing leaf daddr 2093296): `ops=xfs_dir3_leaf1 mode=5 tenure=0 epoch=4369 nl=0 tmism=1 dgen=2 lgen=2 bgen=2`.

## P20 GUARD IS NOT THE CAUSE: test1 shut down with ZERO P20 fires. test2 had a P20-LEAFCLOBBER-SKIP (owner=131 daddr=2093296 buf_cnt=152 disk_cnt=202 bgen=0 dir_gen=105) just before its shutdown, but test1 proves the corruption is independent of P20 (same xfs_da_read_buf verifier-failure path). So the write-guard skip did not corrupt anything here; the shutdown is a corrupt dir-block READ.

## DIAGNOSIS: this is the long-standing inode/daddr-REUSE double-allocation / stale-extent-map corruption family (sess39 EFSBADCRC, sess87 inode DOUBLE-ALLOCATION, sess111 stale INODE/BMAP duplicate, the cache_coherency/bnobt-double-free saga). Under rm-rf+recreate, a freed dir-block daddr is reallocated; a node reads a dir DATA block whose on-disk content no longer matches what the (stale) in-memory extent map expects -> verifier fails -> corruption shutdown. This is NOT the readahead leaf-hash lost-update fixed this session (reada disable + P20).

## STATUS: leaf-hash bug FIXED (reada disable, official suite 16/16). Reuse-churn corruption = separate DEEP bug, still open. New suite test dir_reuse_coherency CAN wedge the cluster (FS shutdown -> umount hangs -> rmmod busy -> needs `virsh destroy/start test2`), so it is effectively expected-FAIL until the reuse-corruption is fixed; do NOT treat a full-suite run that includes it as 16/16-equivalent until then. Recovery after wedge: force umount -l + rmmod (test1 ok); test2 needed virsh reboot. [[sess20-FIX-2tcp-leafclobber-and-reada-disable]] [[sess111_reframe_bnobt_red_herring]]
