---
name: Sess22 lessons (v0.3.61-v0.3.67)
description: SCSI READ FUA extended from disklock to xfs_buf AG-meta + inode bufs; peer-joined cache invalidation. Failure mode shifted from deterministic iter-1 bnobt to intermittent iter-1..4 mixed bnobt + Mode A. Real progress but bnobt residual.
type: project
originSessionId: c4f837cb-1440-4eab-b2fd-81d91e09dd88
---
## Sess22 changes (2026-05-03)

- **v0.3.61** — P25-INSTR pr_warn at xfs_inode_mark_reclaimable mxfs sync path
  (xfs_icache.c:2465). Confirmed v0.3.60 sync inactive_ifree DOES execute (P25 fired
  4× in r1 on T1).

- **v0.3.62** — SCSI READ(16) FUA passthrough extended from disklock (v0.3.58) to
  xfs_buf reads of AG-meta. New helper `mxfs_pal_scsi_read_fua_bdev` in
  pal/linux/kern.c, declared in xfs/xfs_mxfs_dlm.h. Hook in xfs_buf_submit
  (pal/linux/xfs_buf.c) gates on (XBF_READ && !WRITE && !READ_AHEAD) + multi-node +
  AG-meta predicate. Falls back to bio on -EOPNOTSUPP.

- **v0.3.63** — peer_joined_flush extended to invalidate cached AG-meta in every
  perag (xfs_mxfs_dlm.c:2459). AG-meta read into cache during mount via bio
  (single_node=true at mount-time read), persists with XBF_DONE; FUA hook only
  fires on cache-miss reads. Walk all perags + invalidate_ag_meta.

- **v0.3.66** — stripped P27/extra P26 instrumentation (was perturbing timing,
  caused CAW timeouts).

- **v0.3.67** — FUA hook also covers xfs_inode_buf_ops + xfs_inode_buf_ra_ops
  (inode cluster bufs). Targets cross-node dir/inode coherency for Mode A
  dir_removename ENOENT.

## Failure distribution (sess22)

| Version | Failure | Iter |
|---|---|---|
| v0.3.61 r1 | bnobt LEFT-FAIL T2 | 1 |
| v0.3.62 r1 | T2 RIGHT-FAIL + T1 LEFT-FAIL simultaneously | 1 |
| v0.3.63 r1 | bnobt RIGHT-FAIL T1 | 3 |
| v0.3.64 r1 | DLM inode timeout T2 ino=128 (P27 instrumentation perturbed) | 2 |
| v0.3.66 r1 | Mode A dir_removename ENOENT T2 | 4 |
| v0.3.66 r2 | bnobt RIGHT-FAIL T1 | 1 |
| v0.3.66 r3 | DLM inode timeout T2 ino=128 | 4 |
| v0.3.67 r1 | bnobt LEFT-FAIL T2 | 3 |
| v0.3.67 r2 | bnobt LEFT-FAIL T2 | 1 |

Empirical: FUA fires extensively (best run P26 n=2241+ FUA reads on T2, n=65 on T1).
Failure mode shifts but bnobt LEFT/RIGHT-FAIL still surfaces ~50% of time at iter-1..3.

## Key insights from sess22

1. **Most AG-meta reads hit cache, not the FUA hook.** P26 success counts vary
   wildly between nodes (T1:65 vs T2:2241). T1 (mounted first, single_node=true
   longer) cached AG-meta via bio path; subsequent reads hit cache. T2 (mounted
   second, peer-joined faster) had more cache misses → more FUA reads.

2. **bnobt corruption now happens during exclusive AG hold (intra-node)**, not
   cross-node. v0.3.62 evidence: T2 alloc'd agbno=22456 len=65520 at 179860.910,
   fail at 179864.180 with gtbno=22456 gtlen=239678 = pre-alloc state. T2's own
   alloc disappeared from T2's later free walk. Suspected mechanism: something
   stales T2's bnobt buf during T2's exclusive hold; FUA-read of disk gives
   pre-T2-modifications state, wiping T2's in-memory updates.

3. **invalidate_ag_meta during open trans is dangerous.** Staling a buf with
   active BLI: stale clears XBF_DONE, next read fetches disk, but BLI in
   trans's t_items still points to the buf. Trans commit reads CURRENT buf
   content (post-FUA, pre-modification). Modifications LOST.

4. **Peer-joined invalidation is necessary but not sufficient.** Mount-time
   single_node=true causes bio reads to populate cache. peer_joined_flush
   invalidates BUT only stales bufs IN pag_bcache at moment of invalidate.
   Bufs that aren't yet in cache (haven't been read) aren't affected.

## Sess22 don't-repeat additions

- **Unconditional pr_warn counters in xfs_buf_submit perturb timing dramatically.**
  v0.3.64's P27 every-256-calls submit-total counter caused iter-1 CAW timeout
  on root dir. Sess21's lesson re-confirmed: ANY added pr_warn in hot paths
  can shift timing into different failure modes.

- **Peer-joined invalidation must run AFTER log_force+ail_push+blkdev_flush,
  NOT before.** Otherwise we'd invalidate uncommitted state.

## Sess23 immediate next actions

1. **Limit FUA reads to fresh-acquire window only.** During exclusive AG hold,
   our cached bufs are authoritative; FUA-reading replaces in-memory updates
   with disk content. Hypothesis: the intra-node bnobt corruption is caused by
   FUA firing on cache-miss reads that happen WHILE WE STILL HAVE UNFLUSHED
   modifications. Fix: gate FUA on a per-pag flag set briefly during
   invalidate_ag_meta, cleared after first AG-meta read on that AG.

2. **Verify FUA reads actually bypass LIO target read cache** (sess21
   priority-1, not yet done). Synthetic test: T1 writes pattern X via FUA,
   T2 reads via FUA, verify match. If FUA doesn't bypass cache, this whole
   approach is wrong; need SYNCHRONIZE CACHE 16 instead.

3. **Strip P22 walk-census, P23 alloc-extent, P25 sync-inactive prints** —
   no longer load-bearing; consume log buffer space. Keep MX-INSTR
   agi-recycle as the canonical race-confirmation diagnostic.

4. **Audit xfs_extent_busy cross-node** (sess21 strategy #1, still open).
   Pre-commit busy entries are local-only. Cross-node alloc race not
   addressed by FUA.

5. **Dir block buf cache coherency** — Mode A dir_removename ENOENT surfaces
   when bnobt doesn't fire first. Dir blocks have separate buf ops
   (xfs_dir3_data_buf_ops etc.) — not yet covered by FUA hook.

## Sess22 LATE updates (post-FUA verification)

- **FUA verified working cross-initiator** (`tools/fua_verify.c`).  Both
  WRITE FUA and READ FUA, alternating between T1/T2, see latest content.
  Falsifies "FUA broken on iSCSI/LIO" hypothesis.  v0.3.71/v0.3.78
  architecture (FUA AG-meta reads + peer-joined invalidation) is the
  right foundation.
- **First 15/15 PASS at v0.3.78 run 3.**  v0.3.78 = v0.3.71 + P29-INSTR
  (xfs_bunmapi entry bmap dump) + P30-INSTR (xfs_create end stale-bmap
  check).  Diagnostic prints in hot paths shifted timing such that the
  CAW exhaustion / bnobt races fired less often.  Genuine progress, but
  variance still high (1, 1, 10, 12, 15 across 5 runs).
- **Bnobt corruption is symptom of bmap corruption.**  P29 dumped perf_t2
  bmap at fail showing extents at sb=12536, 105976 that T2 never
  alloc'd (per cross-correlation with P23 log).  Bnobt walk for free
  finds the unalloc'd range as already-free (correctly!) — the bug is
  perf_t2's BMAP claiming ownership of those blocks.
- **Fresh-create inodes are clean** (P30 = 0/0 across 5 runs).  Bmap
  corruption is NOT from xfs_create reading stale dinode.
- **CAW exhaustion (rc=-110) is the dominant remaining failure** (3/5 v0.3.78
  runs).  Need different mechanism than v0.3.46's exponential backoff
  (which caused dd hangs).
