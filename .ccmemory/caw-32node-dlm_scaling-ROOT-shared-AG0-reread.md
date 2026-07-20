---
name: caw-32node-dlm_scaling-ROOT-shared-AG0-reread
description: 32/caw dlm_scaling FAIL root PROVEN: every node re-reads a shared ~400-block AG-0 region ~100+ times/op at load (0 solo) → iSCSI target read-command…
metadata:
  type: project
---

## 32/caw dlm_scaling FAIL — ROOT PROVEN (ccloop 12e0d157, 2026-07-07, build 115CCA8)

Criterion `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 32 caw dlm_scaling`.
Test (tests/suite/dlm_scaling.sh): each node does OPS=2000 `:>f; stat f; rm -f f` in its OWN
private subdir `$MNT/.dlm_scaling/node$R`. FLOOR_OPS=50/s/node, WINDOW=60s. FAIL = `rate>=floor`
on ALL nodes (~41-44/s each; agg=1319, max_single=44). 16/caw PASSES (~82/s = 1319/16). So it's an
**aggregate ceiling ÷ N** effect: agg throughput saturates ~1319/s → 32 nodes get 41/s (<50).

### PROVEN chain (RULE 4, instrumented)
1. **Read-bound, not write.** SCST target (`/home/steve/disk.img`, vdisk_fileio) served ~2.7 GB
   READS vs ~289 MB WRITES per run (~9:1). Host stat: `read_io_count_kb`/`write_io_count_kb` under
   `/sys/kernel/scst_tgt/targets/iscsi/iqn.2026-05.local.mxfs:shared/`.
2. **NVMe backing store is NOT the bottleneck.** iostat nvme0n1 during op-loop: r/s≈24000, r_await
   **0.04ms** (served from clyde RAM cache), %util 46%. Bottleneck = the iSCSI/SCST **command
   round-trip** under a huge aggregate read-command rate, not disk bandwidth (matches handoff).
3. **Reads are PEER-INDUCED.** node1 alone (peers idle), 200 ops in its subdir → **0** block reads
   (`/proc/diskstats` delta). At 32-node load → ~100+ reads/op. So concurrency, not the op path.
4. **All re-reads land in AG 0.** ftrace block_rq_issue (reads) on test1 AND test16 during a live
   32-node run: ~31000-41000 read events/3-4s, **≥99.9% in AG 0**, same ~400-block region
   (fsblk ≈ 18300-18700), 0 AG-header (off 0-3) reads, each block read ~twice. Helper:
   `tests/trace_reads.sh <secs> <agblocks=261653>` (agblocks=ceil(dblocks 13082614/agcount 50)).
5. **Inode ALLOCATION affinity WORKS (not the bug).** P90-PICK (gated on dirwr, which the criterion
   sets) shows per-node spread: test1/slot0→agno0, test16/slot10→agno10, test32/slot23→agno23; overall
   picks spread across AGs 0-31. So each node's files/subdir go to its OWN AG (node_slot % m_maxagi,
   m_maxagi≈50). xfs_ialloc.c:2106-2164 affinity is correct.
6. **DLM locks are cached** (99% hit, `ag: acq=1 rel=0` = AG held, nested cache-hits). Not per-op
   disk locks. dir_priv_ex_skip WORKS (fua dir=6, was thousands). fua ino≈30 agm≈290 (low).

### INFERRED culprit (NOT yet block-mapped): the SHARED PARENT PATH
Allocations spread, but every node's per-op PATH RESOLUTION of `/mnt/shared/.dlm_scaling/node$R`
reads root(ino128,AG0) + `.dlm_scaling`(AG0, created by slot0 in its AG0). Those AG-0 dir/inode
buffers are dcache/buf-cache-cacheable and untouched during the op-loop (nobody modifies
`.dlm_scaling`), yet re-read from the shared LUN every op at 32-node concurrency. ~100 reads/op is
FAR more than 2-3 path buffers, so it may be a full-dir or inode-btree SCAN / coherency reload of the
shared parent — NOT yet proven which. Next: probe the dir-read path to log the inode# of cold
non-FUA dir reads during the op-loop (P15-DIRFUA/dir_perf_probe only catches FUA reads; these are
NON-FUA cache-missed bio reads, uncounted).

### FIX MANDATE (RULE 0: can't widen floor)
To pass, must cut per-op AG-0 reads. Target: stop re-reading the shared, unmodified parent path
across ops (cache it at PR / suppress the coherency re-read when the parent dir is held cached and
not BAST'd — analogous to dir_priv_ex_skip but for the shared-read/lookup side). Verify it doesn't
regress the coherency tests that share dirs.

### A/B confounder note
`fua_disable=1` gave 15/32 but EXPLODED FUA-COUNT (ino=5022 dir=1851) — it switches to cached bio
reads AND changes coherency behavior; NOT a clean "fewer reads" lever. Do not use as the fix path.

### Infra lessons this session
- `/tmp/.mxfs_pass` missing after host /tmp wipe → restore `cp /home/steve/.mxfs/pass /tmp/.mxfs_pass`.
- 0 VMs at session start; boot all 32 `virsh -c qemu:///system start testN`, then
  `scripts/caw_preflight.sh 32` (assembles mpatha, mounts /src, verifies READY).
- DON'T run heavy shell-fork fan-out probes (ds_probe on all 32) — leftover runaway loops wedge
  mounts → run.sh power-cycles ALL nodes sequentially → 560s timeout. Use run.sh's own workload +
  host-side/single-node tracing instead.
See [[caw-16node-dlm_scaling-FIX-private-ex-fua-skip]] [[caw-multipath-16node-instability-diagnosis-sess1]].
</body>
