---
name: sess48-readside-refined-scst-per-initiator-readcache
description: sess48 read-side REFINED: P133=0 + dd-fresh-later ⇒ the residual is a stale SCST per-initiator READ cache; even coherent plain-bdev reads see stale d…
metadata:
  type: project
---

## sess48 read-side residual — REFINED root (continues [[sess48-uv-writeside-FIXED-readside-inode-cluster-stale]])

After the write-side fix, the uv residual (outlier sees peer's "deleted" files) is a
**STORAGE-LAYER per-initiator SCST READ-CACHE staleness**, NOT an FS buffer bug:

EVIDENCE (all from the SAME live diverged dir, build 8B767DA4):
- Raw O_DIRECT dd of the dir inode from BOTH initiators = BYTE-IDENTICAL, di_format=01
  (SHORTFORM), 0 files ⇒ the LUN platter is durably correct (write-side fixed).
- The outlier's `mxfs_dlm_reload_inode` read di_format=2 (BLOCK) DURING the test.
- **P133-DINO-READSTALE fired 0×** on both nodes. P133 compares reload's buffer dip vs a
  `mxfs_pal_bdev_read_plain_bdev` coherent read and fires on mismatch. 0× ⇒ at reload time
  the plain-bdev "coherent" read ALSO returned BLOCK — i.e. BOTH the xfs_buf bio AND the
  plain-bdev read saw the stale image. The dd O_DIRECT that saw SHORTFORM ran SECONDS LATER.
- ⇒ The SCST target serves test2 a STALE cached inode-cluster block for a window after
  test1's durable write, then serves fresh (cache invalidation latency / TTL).
- **fua_disable=0 did NOT help (uv 0/3)** — FUA reads do not pierce this cache here (SCST
  may not honor READ FUA over iSCSI/TCP, OR the buf is served DONE-cached so the FUA gate
  at pal/xfs_buf.c:4173 never runs). mxfs_fua_disable default=1 (sess45).
- drop_caches on the outlier → sees 0 (because by then the SCST cache had refreshed).

WHY dirwr=1 made uv PASS: the probe latency widened the window so the SCST read cache
refreshed before the outlier's verify reads. Pure timing artifact (matches the long-standing
"instr hides races" rule). ALWAYS validate uv in production (no dirwr/instr).

NEXT-SESSION DIRECTIONS (read-side):
1. CONFIRM the storage-cache hypothesis directly: from the outlier, in a tight loop right
   after the peer's write, `dd iflag=direct` the inode-cluster LBA and watch di_format flip
   2->1 after N ms — measures the SCST read-cache refresh latency. (vs FS-layer: if dd is
   ALWAYS fresh but xfs_buf is stale, it's the kernel buffer not re-reading.)
2. Does SCST honor READ FUA? Check `mxfs_buf_read_fua` actually issues READ(16) FUA and SCST
   returns platter (caw_verify/fua_verify tools; or scstadmin read-cache settings on the
   target). If SCST ignores read FUA, the FS-level FUA mechanism is moot for reads.
3. If SCST read cache is the wall: configure the target's per-initiator read caching off for
   the shared LUN (storage config, not FS) — OR force the reader to invalidate via a write
   barrier the peer issues. project_test_cluster_scst memory has the target details.
4. Cross-check: does the dir-DATA-block path have the same residual, or only the inode
   cluster? (the block path uses _XBF_FUA_FRESH + consumer_refresh evict.)

KEEP build 8B767DA4 (write-side fixes + reload-on-gen). cache_coherency: write-side proven
correct; read-side flaky (~1/3 prod) pending the SCST read-cache resolution.
