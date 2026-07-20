---
name: sess59-drc-CORRECTED-root-durable-dirent-lost-update
description: sess59 CORRECTED root (supersedes size-lag/enumeration theory): dir_reuse 4-node fail = DURABLE dirent LOST-UPDATE under concurrent same-dir create.…
metadata:
  type: project
---

## sess59 CORRECTED diagnosis (RULE 4 — supersedes the size-lag/enumeration theory)

### DECISIVE classification (tests/tcp/drc4_repro.sh, build 39D3BA93, round 4)
Missing `node2_f20` on ALL 4 nodes: **`LOOKUP_ENOENT REREAD_MISS`**.
- NOT lookup-able (stat→ENOENT) → not a readdir-enumeration/visibility miss.
- A SECOND readdir still misses it → persistent, not a transient stale-block read.
- Absent even on **node2, its own creator**.
=> **DURABLE dirent LOST-UPDATE under concurrent same-directory create.**
node2 created+synced node2_f20; a concurrent peer's RMW on a STALE shared dir
block clobbered it on disk; node2's own drop_caches+reload then read the
clobbered block → entry gone everywhere.

### What this OVERTURNS
- [[sess59-drc-readdir-miss-stale-disksize-gen-equal]] (size-lag) and
  [[sess59-drc-root-grantless-readdir-async-evict-latency]] (async-evict
  enumeration miss) were MISREADS. The P62 incore_size=8192/disk=12288 was a
  transient reload snapshot, not the cause; I never verified lookup. The real
  fault is durable loss, not visibility.
- **Approach A (synchronous FUA dir-version check in xfs_dir2_readdir.c) was
  REVERTED** — disproven (P59-RDSYNC ahead=0; node2_f20 is durable loss, size
  matched). File restored to original. drc4_repro.sh KEPT (now classifies
  misses: LOOKUP_OK/ENOENT + REREAD_SHOWS/MISS).

### This IS the CAW ship-blocker family
Durable dir-block lost-update under concurrent same-dir create = exactly the
sess79-92 cache_coherency blocker (sess83/84/88 dir-block durable lost-update,
sess43-58 dir_reuse). Transport-INDEPENDENT → solving on TCP (cheap LIO) directly
unblocks CAW. At 2 nodes the RMW race window was too narrow (sess58 dir_reuse
PASSED at 2/tcp); 4 nodes' higher concurrency exposes it.

### Reliable repro
`bash tests/tcp/drc4_repro.sh 4 50 24` — concurrent reads + on-miss
classification. Failed round 4 (node2_f20) and round 9 (earlier builds). Faithful
`./run.sh 4 tcp dir_reuse_coherency` also fails (node1_f1).

### NEXT (RULE 4): new hypothesis = the dir-block RMW that adds a dirent reads a
STALE cached dir DATA/leaf block (peer's concurrent add not yet visible) and on
commit/writeback clobbers the peer's entry. Review sess79-92 prior fixes
(drain-before-unlock invariant #1, mxfs_dlm_dir_durable_signal, dir-data AG push,
sess83 F08CE615, sess88 73B57CCD) BEFORE attempting — many partial fixes already
landed; find the residual gap at 4-node concurrency. See
[[sess59-4node-tcp-16of17-dir-reuse-coherency-fails]].
