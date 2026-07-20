---
name: caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm
description: 16/caw dlm_scaling ROOT PROVEN (ccloop 0d6e174d, build D8BEF5A5): rate-floor fail = ~5000 coherency-UNNECESSARY SCSI FUA reads of each node's OWN pri…
metadata:
  type: project
---

## 16/caw dlm_scaling — ROOT CAUSE PROVEN (ccloop 0d6e174d, 2026-07-06, build D8BEF5A5)

RULE-4 proven by instrumentation (P15-DIRFUA / FUA-COUNT / DLM-cache counters), NOT inferred.
Supersedes the sess2/sess3 "shared-LUN FUA saturation (inferred, unmeasured)" handoff
([[caw-16node-sess3-fua-saturation-hypothesis-and-lever-map]]).

### The failure
`dlm_scaling` 16/caw = FAIL 0/16, all nodes fail `rate>=floor` (FLOOR_OPS=50/sec, WINDOW=60s).
Each node does 2000× (create+stat+unlink) in its OWN PRIVATE subdir `.dlm_scaling/nodeR`
(disjoint resources). Measured ~33-50 ops/sec (~20-30ms/op) vs native XFS µs.
PASSES at 1/2/4/8; fails at 16 (shared LUN IOPS split N ways drops per-node rate under floor).

### ROOT (measured, test1/5/8 identical)
FUA-COUNT: `total=5888 ino=20 dir=5860 agm=8 scsi=5887 p91skip=0 oskip=0`.
**99.5% of FUA reads are DIR-block reads: ~5860/node = ~2.9 per op.** Each is a synchronous
SCSI READ(16) FUA to the ONE shared LUN. DLM-cache `hit=25057 miss=9 (99%) ag: acq=1 rel=0`
= lock caching PERFECT, dir/AG locks held continuously, NO churn. `bast imm=3 def=9` = ~zero
contention (private dir, as designed). So NOT lock/AG contention, NOT membership.

P15-DIRFUA probe (dir_perf_probe=1): **5143 reads ALL of daddr=72** (the subdir's single
block), ALL `fresh_after=1`, ALL `ops=xfs_dir3_block`, **P19-DIRINVAL=0** (the xfs_da_read_buf
gen/aba invalidate NEVER fires). So the same private block is re-FUA'd 5000+×.

### Why the amortization is defeated (two coherency hooks, both fire per-op on a PRIVATE dir)
1. **xfs_buf FUA gate** (pal/linux/xfs_buf.c:6645): with `fua_always=1` (DEFAULT — the
   modinfo desc strings are STALE; real C initializers are `mxfs_fua_always=1`,
   `mxfs_fua_disable=0` at xfs_mxfs_dlm.c:24305/24361) EVERY dir read = FUA, ignoring
   `_XBF_FUA_FRESH`. **A/B: fua_always=0 did NOT help (still 5860 dir FUA)** because the
   flag is cleared before each read.
2. **addname/removename FUA-platter-compare** (xfs/libxfs/xfs_dir2_data.c ~2143-2202): on a
   CLEAN dir block it does `mxfs_pal_scsi_read_fua_bdev` of the block + memcmp vs in-core,
   invalidating (`&= ~(XBF_DONE|_XBF_FUA_FRESH)`, line 2193) if differ. Comment 2092-2098
   claims a "RULE-0 throttle: fires only on FIRST add per tenure because the block becomes
   dirty." **dlm_scaling DEFEATS this**: create→dirty→commit+DESTAGE→CLEAN again→unlink→
   CLEAN→fires again. The immediate create-then-unlink returns the block to clean every op.

### The epoch/tenure levers are OFF by default (ruled out)
`mxfs_dir_tenure_evict`, `mxfs_dir_evict_prior_tenure`, `mxfs_force_coherent`,
`mxfs_dir_zombie_retire` all default 0 → epoch_stale=tenure_stale=false. The only active
da_read_buf invalidate arms are gen-mismatch (self-heals, stamps gen at da_btree.c:3847) +
owner/incarn ABA (private dir → no ABA). Confirmed P19-DIRINVAL=0.

### THE FIX DIRECTION (not yet built)
For a PROVABLY-PRIVATE dir (this node holds EX AND no peer has ever BAST'd it), ALL the
cross-node dir coherency FUA machinery is unnecessary. Existing `owned_ex` fast-path
(xfs_da_btree.c:3090) already skips it but is gated on `dp->i_dlm_unpublished` (too narrow —
the subdir publishes almost immediately). BROADEN to `i_dlm_unpublished || (i_dlm_mode==EX &&
never-BAST'd-this-tenure)` and apply the SAME gate to the xfs_dir2_data.c addname-platter-check.
The comment at da_btree.c:3081-3088 warns `i_dlm_mode==EX` ALONE is unsafe (a shared EX dir
can hold stale blocks after release-on-BAST + peer-modify + re-acquire) — hence the EXTRA
"never BAST'd this tenure" condition (a never-contended lock never had a stale window).
Need: a per-inode "BAST received since EX acquire" flag (reset on acquire, set on bast).
DLM-cache showed ~zero BASTs on the private subdir so the signal will be clean.

### Infra / how to reproduce
`scripts/caw_preflight.sh 16` then `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1
dirland=1 dir_perf_probe=1" ./run.sh 16 caw dlm_scaling`. Grep node dmesg: `FUA-COUNT`,
`P15-DIRFUA` (daddr repeat), `P19-DIRINVAL`. Other 16/caw blocker = dir_reuse_coherency (EIO).
</body>
