---
name: sess13run-BREAKTHROUGH-FUA-removes-corruption-readdir-divergence-remains
description: sess13(ccloop) BREAKTHROUGH: fua_disable=0 fua_always=1 ELIMINATES the DABUF_MAP_HOLE corruption/shutdown in dir_reuse 4/tcp (165→0); readdir diverge…
metadata:
  type: project
---

## sess13 (ccloop 4cb2d0a2) — FUA removes the dir_reuse corruption; readdir loss remains

### Baseline (build 40AC2A0C, default params incl fua_disable=1)
`./run.sh 4 tcp dir_reuse_coherency` standalone = FAIL 0/4. Two symptoms:
1. **DABUF_MAP_HOLE shutdown** — `!(flags & XFS_DABUF_MAP_HOLE_OK) at line 2817 xfs_da_btree.c`, caller xfs_dabuf_map, comm=dd. ~150+ per node on test2/3/4. (dir extent-map hole / stale-base RMW corruption.)
2. readdir loss: rank1(owner)=0/400, peers=306/400.

### DECISIVE EXPERIMENT (this session): force coherent reads
`MXFS_EXTRA_MODARGS="fua_disable=0 fua_always=1" ./run.sh 4 tcp dir_reuse_coherency`:
- **DABUF_MAP_HOLE shutdowns = 0** on ALL nodes. NO `Internal error` at all. → the CORRUPTION/shutdown is caused by STALE-BASE reads (LIO per-initiator read cache served stale dir blocks under fua_disable=1); FUA SCSI READ(16) piercing the cache ELIMINATES it.
- BUT readdir divergence PERSISTS: rank1=0/400 (every round), peers=306/400, lookup_fail=0, **same dirino=131 on all nodes** (NOT an inode-incarnation mismatch). So it is an intra-inode dir-content divergence that coherent reads alone do not fix.

### REFUTED / CONFIRMED
- REFUTED: "LIO stale read cache is the SOLE root" — FUA fixes corruption but readdir still wrong.
- CONFIRMED: the DABUF_MAP_HOLE corruption IS read-coherency (stale-base RMW). fua_disable=1 on LIO is unsafe for 4-node dir contention.
- CONFIRMED present-but-gated: grant_gen(sess61)/handoff-bit(sess63)/dir_epoch(sess64) machinery is FULLY BUILT in dlm.c (mxfs_dlm_grant_gen@2263, grant_was_handoff@2299, grant_dir_epoch@2339) + v5_mount.c wrappers + xfs_inode.h fields (i_dlm_cached_grant_gen, i_dlm_handoff_acted_gen, i_dlm_dir_valid_epoch) + xfs_mxfs_dlm.c (P65-EPOCH-ADOPT@7758, P63-HANDOFF@7774). GATED OFF: dir_epoch_adopt=0, dir_epoch_convert_gate=0 (default). dmesg shows P65-EPOCH-ADOPT firing with `adopt=0` (gated) and P63-HANDOFF firing — handoff IS detected, adopt is suppressed.

### rank1=0 evidence (test1, FUA on)
inode 131 fmt=2 nextents=3 disk_size=12288, but `P21S-EVICTSKIP-LEAF ino=131 daddr=1912 leaf_count=402 dirty=0` — the LEAF block (402 hash entries = ~400 files PRESENT on disk) coherent re-read is SKIPPED (EVICTSKIP). So the data IS durable on disk but rank1's readdir enumerates 0 → leaf/data block coherent re-read not happening on the owner that free+recreates the dir each round. `P-DE-ENTER ino=131 fmt=2 nd=4 gen=8` shows nd=4 dir blocks but nextents=3 (extent-map vs block-count mismatch — the latent DABUF_MAP_HOLE source).

### NEXT (testable, RULE 4): FUA(coherent reads) + epoch_adopt(reliable handoff) TOGETHER.
The epoch machinery was likely gated off because WITHOUT FUA reads were stale anyway. Test `fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1` on dir_reuse 4/tcp. Then audit P21S-EVICTSKIP-LEAF (why the leaf evict/re-read is skipped on the reuse owner). RULE-0: fua_always ~16s/round (slow) — if correctness converges, scope FUA to dir-meta-on-handoff only.
Cluster: test1-4 reset via virsh -c qemu:///system destroy+start. Repro: `./run.sh 4 tcp dir_reuse_coherency` (tool timeout ≥480000ms). Criterion NOT met.</body>
</invoke>
