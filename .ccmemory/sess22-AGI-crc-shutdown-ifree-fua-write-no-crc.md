---
name: sess22-AGI-crc-shutdown-ifree-fua-write-no-crc
description: sess22(ccloop) NEW gating shutdown: AGI block 0x2 CRC error in xfs_agi_read_verify during xfs_inactive_ifree (rm-rf inode free). Block content VALID…
metadata:
  type: project
---

## sess22 (ccloop) — AGI CRC shutdown is the next gating bug

### Evidence (test1, 2/tcp dir_reuse, build 1FE2C2DA):
```
P126-XFSAILD-SKIP-AGMETA agno=0 daddr=2 ops=agi in_ail=1 dirty=1 pin=0 — staling stale prior-tenure AG-meta
P91-FUA-SKIP-LOGGED daddr=2 ops=xfs_agi pin=0 li_empty=1 has_bli=1 bflags=0x200001 comm=rm — kept in-core authoritative buffer
XFS (sda): Metadata CRC error detected at xfs_agi_read_verify+0xce block 0x2
  First 128 bytes: 58 41 47 49 ... = "XAGI" magic, versionnum=1, length=0x3fe15, count=0x380, root=3, level=1, freecount=0x19, newino=0x83e80, dirino=NULL, unlinked buckets sane
metadata I/O error xfs_read_agi -> xfs_difree -> xfs_inactive_ifree (xfs_inode.c:2653) -> Shutting down filesystem
```
The AGI CONTENT is structurally VALID — only the on-disk CRC is wrong. So an AGI buffer was WRITTEN to disk with a stale/incorrect CRC (mxfs FUA-write / drain path bypassing the xfs_agi_write_verify CRC recompute), then FUA-read-back + verified → CRC fail → shutdown.

### Why it matters / scoping:
- Independent of sess22 dir fixes (reorder remove + leaf holeskip/bail are DIRENT-only; AGI CRC is the inode-btree write path). Pre-existing, FLAKY (sess39/sess45 AG-meta corruption family — "AG free-space double-alloc / AGI iunlink corruption" never fully fixed).
- dir_reuse is the heaviest inode alloc/free churn (rm-rf+recreate 200-800 entries × 24 rounds) → exposes it most. The shutdown EIO-cascades into every test after dir_reuse (fence/fault/soak/tcp_dlm_scaling) → 2/tcp went 17/17(keeper) -> 130/145 this run. 2/tcp historically FLAKY (sess49: 17/17, 16/17, 16/17).

### NEXT: find the AG-meta write path that skips CRC recompute.
Search the drain pipeline (mxfs_dlm_ag_drain_meta_buffers) + mxfs FUA-write helpers for where an AGI/AGF/AGFL buffer is written to the bdev WITHOUT running its write verifier (which computes CRC). Likely a raw submit_bio / FUA write of bp->b_addr that doesn't call bp->b_ops->verify_write or xfs_buf_ensure_ops. Compare to how dir-data blocks are FUA-written. Fix = recompute CRC (run write verifier / xfs_buf_update_cksum) before any out-of-band AG-meta write. See [[sess22-build-1FE2C2DA-reorder-plus-holeskip-144of145-noshutdown]], sess39/sess45 lessons.
