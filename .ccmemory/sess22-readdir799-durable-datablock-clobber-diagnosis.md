---
name: sess22-readdir799-durable-datablock-clobber-diagnosis
description: sess22(ccloop) dir_reuse readdir=799 residual DIAGNOSED: durable ON-DISK data-block lost-update (REREAD_MISS after drop_caches). Contiguous-run loss…
metadata:
  type: project
---

## sess22 (ccloop) — readdir=799 durable data-block lost-update, decisively classified

### DECISIVE diagnosis (RULE 4, build EFBB9861):
The dir_reuse verify does `sync; echo 3 > drop_caches` BEFORE the readdir (test line 91), so the failing readdir reads COLD from the shared LUN. drc-CLASS shows every missing entry = **LOOKUP_ENOENT REREAD_MISS** → the entry is **DURABLY ABSENT ON DISK**, not a reader stale-cache.
- Round 2: got=787, missing = **node8_f40,f41,...,f47** = a CONTIGUOUS RUN of 8 of node8's entries = ONE WHOLE DATA BLOCK's worth, durably gone.
- Round 6/24: got=799, single entry (node6_f11.md5 / node1_f19.md5).
So: a node durably WROTE or KEPT a STALE data block (missing a peer's recently-added run) over the peer's durable version = durable data-block lost-update / whole-block clobber. The sess11 "committed (rval=0) entry vanishes" family.

### Ruled out this session:
- `dir_evict_prior_tenure=1`: does NOT fix (still readdir=799; PASS then FAIL; once caused a shutdown). The clobber is NOT a stale prior-tenure READ base.
- Acquire-side LOCKED-SKIP / LOCKED-WAIT / P36-EVICT-LOCKED: all fired 0× — not the acquire stale-keep path.

### Existing (incomplete) machinery at the clobber points:
- **sess41 evict-side refresh** (xfs_mxfs_dlm.c ~2883, `mxfs_dirrefresh` default ON): when a DATA block is kept ONLY because in-AIL-undestaged (not dirty/pin/delwri, DONE), coherent plain-reads the daddr and if disk has STRICTLY MORE live dirents, drops XBF_DONE → re-read fresh. Round-2 loss SLIPS THROUGH this → either the block is kept for a different reason (dirty/pin/delwri) OR the clobber is write-side.
- **Release-drain bwrite** (xfs_mxfs_dlm.c:1616 `xfs_bwrite(dbp)`): writes the dir block at release (Inv 1). If dbp is a stale DATA block (in-core fewer entries than disk), this WRITE durably clobbers. P-RELFLUSH logs it (gated behind dirwr/instr). There is a P21F-RELFLUSH-LEAF count detector for LEAF blocks (line 1634) but NO equivalent live-entry-count clobber detector for DATA blocks.

### NEXT (decisive probe to build): at the release-drain bwrite (line 1616), for a DATA block (b_ops==xfs_dir3_data_buf_ops/block), coherent plain-bio read the on-disk block BEFORE the bwrite and count live dirents in-core vs on-disk; log P22-DATA-CLOBBER if in-core < disk (this write is about to durably drop entries). That pins WHETHER the clobber is this release write (in-core<disk here) or an earlier path. If it IS the release write, the fix = refresh/union the block before writing, or SKIP writing a block that has fewer entries than disk (let disk's superset stand). Reuse the live-dirent count loop from xfs_mxfs_dlm.c:2945-2962. See [[sess22-SESSION-SUMMARY-net-progress]] [[sess22-FIX-node-format-datascan-leafhash-heal]].
