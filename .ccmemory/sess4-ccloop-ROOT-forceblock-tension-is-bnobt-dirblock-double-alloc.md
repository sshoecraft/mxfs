---
name: sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc
description: sess4(ccloop run6614) DEFINITIVE ROOT: force_block tension = cross-node bnobt DIR-BLOCK DOUBLE-ALLOC. cache_coherency@force_block=1 deterministically…
metadata:
  type: project
---

## sess4 (run 6614aa96) — force_block tension ROOT-CAUSED to bnobt dir-block double-alloc

### THE TENSION (both configs fail, measured this session, build 75F2759C = probes only)
- `force_block=0` (sess3 override): cache_coherency 4/tcp PASS 4/4; dir_reuse flaky (sf→block race, `xfs_dir_create_child -117` / `xfs_ifree -117`).
- `force_block=1` (tree DEFAULT, sess67): dir_reuse 4/tcp reliable (3/3); **cache_coherency deterministically FAILS 0/4** (~47-330s, node shuts down).
- Full 4/tcp: force_block=0 → 14/17 (fails late at dir_reuse#13 + 2 cascades); force_block=1 → ~2/17 (fails early at cache_coherency#2, cascades rest).

### DETERMINISTIC REPRO + DEFINITIVE ROOT (RULE 4, P-BLKRV dump_stack, build 75F2759C)
`./run.sh 4 tcp cache_coherency` at force_block=1 → a node shuts down:
```
Metadata corruption at xfs_dir3_block_verify, block 0x3fe1c8 (=daddr 4186568)
  block dump: magic XDB3 (valid), self-blkno correct, OWNER=4194437, entries [., .., node3_after_7]
Call stack (P-BLKRV-STRUCT owner=4194437):
  mkdir → xfs_dir_lookup_locked → xfs_dir2_block_lookup_int → xfs_dir3_block_read
        → xfs_da_read_buf → read_verify FAIL
```
- The mkdir is creating/looking-up in dir **4194432** (P62-DATAINIT-BLK0/P42-SFCONV ino=4194432, freshly sf→block converted). Its extent map points block0 at daddr 4186568.
- BUT daddr 4186568's durable on-disk content is dir **4194437**'s LIVE block (rename_visibility dir, real entries). → dir 4194432 was allocated a block that is LIVE in 4194437 = **cross-node bnobt DOUBLE-ALLOCATION**.
- The allocating node's AG free-space (bnobt) view was STALE (showed 4186568 free when a peer had allocated it to 4194437). force_block=1 forces dirs to block format → forces the dir-block allocation → exposes the double-alloc. force_block=0 keeps cache_coherency's dirs shortform (no block alloc) → hides it. dir_reuse's heavy churn hits the SAME double-alloc via sf→block ([[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]]).

### WHERE THE COHERENCE GAP IS
Alloc path DOES call `mxfs_ag_dlm_lock` (xfs/libxfs/xfs_alloc.c:3971, 4756) which per its docstring invalidates AG-meta buffers in pag_bcache on a FRESH acquire. So the gap = a **stale bnobt on a CACHED/fast-path AG acquire** (no invalidation) — the allocator reads a stale bnobt and hands out a live block. This is the sess42/43/46/47 AG-free-space-coherence family, still open.

### NEXT (concrete): instrument the dir-block allocation source — when xfs_alloc returns a block, was the AG acquire fresh or cached, and what was pag ag_gen? Catch the moment the allocator returns a block whose disk image already holds a foreign live dir3 block. Then close the cached-acquire bnobt-staleness.

### PROBES ADDED THIS SESSION (harmless logging, in build 75F2759C): P-DIFREE-DBL/P-DIFREE-CORRUPT (xfs_ialloc.c inobt double-free), P-BLKRV-CRC/P-BLKRV-STRUCT (xfs_dir2_block.c read-verify fail + dump_stack + owner).
See [[sess4-ccloop-KEY-bare-defaults-beat-force_block0-dir_reuse-3of3]] [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]] [[sess3-ccloop-UNIFIED-root-divergent-extentmap-and-forceblock-conflict]]
