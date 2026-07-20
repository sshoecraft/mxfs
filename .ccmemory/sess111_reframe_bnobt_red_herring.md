---
name: sess111_reframe_bnobt_red_herring
description: sess111 — REFRAME: stop chasing bnobt/AG-meta (Gemini #2 red herring, sess93). Double-free root = stale INODE/BMAP duplicate-free. fua_disable=1 make…
metadata:
  type: project
---

## sess111 (ccloop run 4eef1f39 session 3, 2026-06-06)

### Course correction (overrides sess110's framing)
sess110 (and the start of sess111) were chasing the **bnobt double-free / AG-meta
cold-read** path (clean-cached-skip gap, P110-BIO guard, GPT tenure-local cold-read
pairing). **Gemini consult #2 (sess93) already DEBUNKED this**: the bnobt does
LEGITIMATE forward B-tree math (alloc carves, free re-inserts+merges); the P88/P93/
P70/P90 "clobber" family across sess42-92 mis-read benign async-writeback/SCST-destage
LAG as corruption. DO NOT re-instrument bnobt/AGF/cntbt for "stale clobber."

### Why disk_differs is unreliable here (confirmed by code read)
Cluster runs `fua_disable=1` (mxfs_fua_disable=1 default, xfs_mxfs_dlm.c:6823). Under
fua_disable=1 the **coherent peer-visible store is the SCST write-back cache**; a plain
read hits it (coherent), an **FUA read hits the STALE PLATTER** (lags until destage).
But `mxfs_ag_buf_disk_differs` / `mxfs_ag_buf_disk_bnobt` (xfs_mxfs_dlm.c:4960/4998) read
via `mxfs_pal_scsi_read_fua_bdev` = FUA = platter. So P88 `disk_differs=1` / `disk_nr`
are comparing in-core vs the WRONG store → platter-lag reads as false disk_differs=1.
(A coherent comparison would use plain read; helper `mxfs_pal_bdev_read_plain_bdev`
exists, added sess103. But per Gemini #2 the bnobt isn't the bug, so don't bother.)

### The REAL root (Gemini #2): stale INODE / in-core BMAP issues a DUPLICATE free
An inode's in-core data-fork extent map is stale → unlink/truncate frees blocks already
freed → `xfs_free_ag_extent` ltbno+ltlen>bno EFSCORRUPTED shutdown (xfs_alloc.c:2244).
The bnobt is CORRECT (shows them free); the inode is the culprit. ONE unifying root for
the shutdown AND the visibility failures = cross-node inode-cache staleness.

### Decisive instruments ALREADY LIVE at instr=0 (read THESE, ignore P88 bnobt)
At the shutdown site (xfs/libxfs/xfs_alloc.c:2244-2308):
- **P15-INSTR** FREE-AG-EXTENT-FAIL-LEFT (the shutdown: agno/bno/len/ltbno/ltlen).
- **P47-INACT** verdict: `DISK-FREE=>B-stale/double-free` | `GEN-MISMATCH=>B-stale-inode`
  | `DISK-LIVE-same-gen=>A-lost-removal`.
- **P81-DEXT** `disk_claims_freed`: 1 = on-disk inode extent DOES claim freed block =
  bnobt/tree wrong on disk; **0 = in-core BMAP STALE vs disk = inode-coherency bug**.
Also `INACT-SKIP-STALE` (xfs_inode.c:2281) = the existing DLM-locked double-free guard
(sess47/sess78) firing — count tells how often a stale inactivation was caught.

### Guard already in place (xfs_inode.c:2208-2289)
nlink==0 multi-node inactivation takes per-inode DLM EX (sess78 TOCTOU closure), FUA-reads
disk di_mode/di_gen, SKIPs if di_mode==0 (B1 disk-free) or gen-mismatch+grantless (B2 reused).
sess103 refuted that this guard's FUA inode read is stale-platter (P103-FUA-DIVERGE=0×) —
inodes destage fast, FUA reliable for inodes. So residual double-free is likely
**DISK-LIVE-same-gen = A-lost-removal** (a legitimately-OWNED inode whose in-core BMAP is
stale) OR a non-inactivation free path (truncate/bmap_del). Next: confirm via P47/P81.

### Current build & state
Build `87726318` on all 4 (chokepoint sess108 + publish-on-create + AG-AIL fix sess109
C7393A5A + sf_lookup-EIO + P110-BIO guards). P106-STALE-EX class CLOSED (=0) by chokepoint.
Residuals on cache_coherency: (1) this stale-inode/BMAP double-free shutdown, (2) ~5%
durable lost-write (sess108, all-nodes-agree). Run cc_run3 in progress on CLEAN cluster.
Related: [[sess93_lessons]] [[sess103_lessons]] [[sess108_lessons]] [[sess110_lessons]].
</body>
