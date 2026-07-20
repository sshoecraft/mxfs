---
name: sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root
description: sess4(ccloop run6614) UNIFIED: cache_coherency@fb1 AND dir_reuse@fb0 fail with the SAME bug — a dir inode gets a CORRUPT/divergent extent map (block0…
metadata:
  type: project
---

## sess4 (run 6614aa96) — the force_block tension is ONE bug: corrupt dir extent map

### UNIFIED ROOT (both hard tests, same signature; build 0FB8EBA3 probes)
Reading a dir's block0 returns wrong content → `xfs_dir3_block_verify`(struct, err117) or `xfs_dir3_block_read_verify`(CRC, err74) → `xfs_trans_read_buf_map` shutdown. Two sub-faces:
- **struct/owner-mismatch**: block is a VALID dir3 block but OWNER = a DIFFERENT live dir inode (e.g. reader=.cache_coherency 4194432, block owner=child rename_visibility 4194437 at daddr 4186568). = block double-alloc / stale map → another dir's live block.
- **CRC-garbage**: `P-BLKRV-CRC daddr=112/120 blkno=<random> owner=<random>` — block0 maps to a LOW/metadata block (blocks 14-15) with garbage content. Reading inode (P-BLKLK) is fmt=2 nx=1, EX-held, self=1, NOT flagged stale/reused → its single extent points at a WRONG physical block = **corrupt extent map from sf→block conversion**.
Both tests trigger it: cache_coherency@force_block=1 (forced block dirs) AND dir_reuse@force_block=0 (heavy churn sf→block). force_block just picks WHICH test builds the bad block-format dir.

### REFUTED this session (do NOT retry)
- Disabling `dir_release_invalidate=0 dir_relinval_clean=0` does NOT fix cache_coherency@force_block=1 → **0/3 still FAIL**. The invalidate-at-release levers are NOT the trigger; the bad extent map is created at ALLOCATION/conversion, not at release-invalidate.

### CONFIG (settled): run force_block=0 (cache_coherency deterministic-PASS; force_block=1 deterministic-FAIL cache_coherency at 2 AND 4 nodes). 2/tcp@fb0 = 17/17. dir_reuse@fb0 4-node ~25-50% flaky (hits the corrupt-map bug under churn). fb1's only win (dir_reuse reliable) can't justify breaking cache_coherency everywhere.

### NEXT SESSION — attack the corrupt dir extent map at the sf→block source
- Path: xfs_dir2_sf_to_block → xfs_dir2_grow_inode → xfs_bmapi_write allocates dir block0. Under cross-node churn the allocated fsb/extent is WRONG (points at a metadata block or another dir's live block). Instrument the ALLOCATION return in the dir-grow path: log allocated fsb→daddr, the AG acquire kind (fresh/cached), and read-back the block for a foreign/garbage magic BEFORE inserting the extent. Catch the moment a dir gets a bad block0.
- Probes in tree (harmless): P-DIFREE-DBL/CORRUPT (xfs_ialloc.c), P-BLKRV-CRC/STRUCT + P-BLKLK (xfs_dir2_block.c reading-inode state).
- FAST-ish repro: `MXFS_EXTRA_MODARGS='dir_force_block=0' ./run.sh 4 tcp dir_reuse_coherency` (~25-50% fail) OR `./run.sh 2 tcp cache_coherency` at DEFAULT force_block=1 (mostly-fail ~34s).
See [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]] [[sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision]] [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]]
