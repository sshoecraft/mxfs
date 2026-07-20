---
name: compiled-caw-16node-dlm-scaling-fua-storm
description: 16-node caw dlm_scaling rate-floor fail = private-dir FUA storm; fixed (valid_epoch-gated dir_priv_ex_skip, build 8B203AA4) → 15/16.
metadata:
  type: project
tags: [compiled, dlm_scaling, caw, 16node, fua, dir-coherency, cache_coherency]
---

## 16-node caw `dlm_scaling` — private-dir FUA storm: root, fix, residual

Single ccloop `0d6e174d` (2026-07-06/07). Compiles five raw memories on the 16/caw
`dlm_scaling` rate-floor failure and its fix. Marker NOT written. Build progression:
**D8BEF5A5** (base) → **98D240B3** (v1 `!contended`, REGRESSED cache_coherency) →
**8B203AA4** (v2 +`valid_epoch==0`, SAFE, CURRENT/FINAL) → 787CCEE8 (v2+probes) →
787CCEE8/B5FED995 (margin experiments, reverted → back to 8B203AA4).

### The failure (ROOT PROVEN, RULE-4, base D8BEF5A5)
`dlm_scaling` 16/caw = **FAIL 0/16**, every node fails `rate>=floor` (FLOOR_OPS=50/s,
WINDOW=60s). Each node runs 2000× (create+stat+unlink) in its OWN PRIVATE subdir
`.dlm_scaling/nodeR` (disjoint resources). Measured ~33-50 ops/s (~20-30ms/op) vs native
XFS µs. PASSES at 1/2/4/8; fails at 16. See [[caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm]].

Instrumented root (test1/5/8 identical, via P15-DIRFUA / FUA-COUNT / DLM-cache counters):
`FUA-COUNT total=5888 ino=20 dir=5860 agm=8 scsi=5887`. **99.5% of FUA reads are DIR-block
reads (~5860/node, ~2.9 per op)** — each a synchronous SCSI READ(16) FUA to the ONE shared
LUN. DLM-cache `hit=25057 miss=9 (99%) ag acq=1 rel=0` = lock caching PERFECT, no churn;
`bast imm=3 def=9` = ~zero contention. So NOT lock/AG contention, NOT membership. P15-DIRFUA:
5143 reads ALL of `daddr=72` (the subdir's single block), all `fresh_after=1`, all
`ops=xfs_dir3_block`, `P19-DIRINVAL=0` (the xfs_da_read_buf gen/aba invalidate NEVER fires) —
the same private block re-FUA'd 5000+×. These reads are **coherency-UNNECESSARY**: no peer
ever touches the private subdir.

Two per-op coherency hooks defeat amortization on a PRIVATE dir:
1. **xfs_buf FUA gate** (`pal/linux/xfs_buf.c:6645`): with `fua_always=1` (the REAL default —
   modinfo desc strings are STALE; actual C initializers `mxfs_fua_always=1`,
   `mxfs_fua_disable=0` at `xfs_mxfs_dlm.c:24305/24361`) EVERY dir read = FUA, ignoring
   `_XBF_FUA_FRESH`. A/B `fua_always=0` did NOT help (flag cleared before each read).
2. **addname/removename FUA-platter-compare** (`xfs/libxfs/xfs_dir2_data.c ~2143-2202`): on a
   CLEAN dir block, `mxfs_pal_scsi_read_fua_bdev` + memcmp vs in-core, invalidating if differ.
   Its "fires only on FIRST add per tenure" throttle assumes the block stays dirty;
   `dlm_scaling` DEFEATS it — create→dirty→commit+DESTAGE→CLEAN→unlink→CLEAN returns the block
   to clean every op, re-arming the compare.
Epoch/tenure levers (`mxfs_dir_tenure_evict`, `dir_evict_prior_tenure`, `force_coherent`,
`dir_zombie_retire`) all default 0 → ruled out. Environment is NOT the bottleneck: shared LUN
= `/home/steve/disk.img` (50GB) via SCST vdisk_fileio on `/dev/nvme0n1p2` (Samsung 990 EVO
Plus 2TB, rotational=0, 12% util), clyde 94GB RAM. 16-node failure = FUA round-trip latency
(~3-5ms/read) + DLM handoff, not disk bandwidth. Reducing redundant FUA is the right lever.

### The fix — `dir_priv_ex_skip` (param, default 1)
See [[caw-16node-dlm_scaling-FIX-private-ex-fua-skip]] (v1) and
[[caw-16node-dlm_scaling-FIX-validepoch-safe-but-marginal]] (v2). For a provably-private dir
(this node holds EX AND no peer ever BAST'd it), all cross-node dir-FUA machinery is
unnecessary. MXFS caches the inode DLM lock: a dir EX releases to NL ONLY on a peer BAST
(sets sticky `i_dlm_dir_contended`, `xfs_mxfs_dlm.c:13142`) or on eviction. So
`EX && !contended` ⟹ held continuously since a fresh acquire ⟹ cached image authoritative —
strictly stronger than bare `i_dlm_mode==EX` (which `xfs_da_btree.c:3081-3088` rejects because
a shared EX dir can hold stale blocks after release-on-BAST + peer-modify + re-acquire; that
case sets `i_dlm_dir_contended`, so it's excluded).

Applied at BOTH dir-FUA sources with the SAME gate:
1. `xfs_da_read_buf` owned_ex (`xfs/libxfs/xfs_da_btree.c ~3090`): broadened from
   `i_dlm_unpublished` to `unpublished || (priv_ex_skip && gate)`. owned_ex gates the
   invalidate block at :3473 → buffer stays DONE → cache hit → no cold re-read → no FUA.
   Required `#include "../dlm/v5_mount.h"` for `enum mxfs_lock_mode` (MXFS_LOCK_EX);
   da_btree.c lacked it (dir2_data.c had it).
2. `mxfs_dir_addname_coherent_refresh` (`xfs/libxfs/xfs_dir2_data.c ~2087`): early `return 0`
   for the private-EX case — skips the per-addname FUA-platter compare (2nd, uncounted source).
Param declared in `xfs/xfs_mxfs_dlm.c` after `dir_unpub_skip` (~9710):
`int mxfs_dir_priv_ex_skip = 1;`.

**Gate evolution:**
- **v1 (98D240B3): `EX && !i_dlm_dir_contended`** → dlm_scaling PASS 16/16 (test5 FUA-COUNT
  `total=256 dir=1`, i.e. dir FUA 5859→1). But **REGRESSED cache_coherency** (clean A/B: skip=1
  FAIL 0/16 empty-content, skip=0 PASS 16/16). Hole: cache_coherency subtest1 is a SINGLE shared
  dir with concurrent mkdir+create from all 16 — a dir is briefly `EX && !contended` BEFORE the
  first peer BAST → skip fired → stale-base addname RMW clobbered dirents. `!contended` catches
  in-flight BASTs but misses COMPLETED handoffs during an earlier NL window.
- **v2 (8B203AA4): `EX && !contended && i_dlm_dir_valid_epoch==0`** → SAFE. `valid_epoch` bumps
  >0 on first cross-node handoff, maintained on CAW at `xfs_mxfs_dlm.c:15593-15597`, so shared
  dirs are disqualified. cache_coherency PASSED 16/16 WITH the fix (×2 good runs, e.g. run
  014522Z). P-PRIVSKIP probes (since removed) showed 0 engagement on shared dirs, full
  engagement on the private subdir (ino=131/ino=20, valid_epoch=0, dir_gen=0, contended=0,
  mode=5=EX). **RESULT: dlm_scaling 15/16** (was 0/16).
- REFUTED margin idea: relaxing the gate to drop `mode==EX` cut FUA 7189→<256 but did NOT fix
  15/16 (reverted). Probes (P-PRIVSKIP-ADD / P-PRIVSKIP-RD) were removed for the FINAL build.

### Why 15/16 not 16/16 (CONFIRMED, next fix) — the CAW cross-mkfs epoch bug
ONE rotating node's private subdir spuriously gets `valid_epoch>0` (measured test4:
valid_epoch=1,3; FUA-COUNT dir=5972 = skip disengaged) → full FUA storm → dips under the 50/s
floor while still completing all 2000 ops. Passing nodes: <256 FUA total. ROOT: CAW `dir_epoch`
lives in the on-disk CAW LOCK slot table (`mxfs_caw_lock_slot`, in the MXFS envelope).
`mkfs_mxfs.c` does NOT zero/init that region → a prior FS's tombstone survives mkfs; a fresh
subdir reusing that inode number matches by resource (`caw_claim_inherit_epoch`,
`dlm_caw.c:717`, same-resource tombstone) → inherits stale `last_ex_slot` → `caw_advance_epoch`
sees a false cross-node handoff → `dir_epoch++` → grant carries it → `i_dlm_dir_valid_epoch>0`.
Fix options (delicate, validate with multiple runs): (a) mkfs_mxfs zero the CAW lock-slot-table
region; (b) include FS UUID/gen in `mxfs_resource_id` so prior-FS tombstones don't match;
(c) clear slot table at cluster-format/mount. See [[caw-16node-session-state-dlm_scaling-fixed-coherency-variance]]
and [[caw-16node-SESSION-SUMMARY-dlm_scaling-fixed-next-caw-epoch-and-coherency-variance]].

### The systemic blocker (PRE-EXISTING, orthogonal to this fix): 16-node coherency VARIANCE
cache_coherency / strong_consistency / posix_multi at 16 are ~50% flaky standalone: PASS 16/16
vs FAIL 0/16 on identical fresh clusters (cache_coherency: PASS run 014522Z vs FAIL runs
012756Z, 014825Z). Failure = rotating victim node, content empty (writes don't land before
barrier) = SESS50-STARVE EX-writer starvation + durability drain race on the concurrent
same-dir create (cross_visibility: 16 nodes hammer ONE shared dir). CONTAMINATION: running
dlm_scaling then cache_coherency → cache_coherency test#2 FAILs 0/16 (prior test leaves
3 shutdowns + SESS50-STARVE). Proven lever = `MXFS_SETTLE_MS` (run.sh inter-test sync+drain;
settle=8000 → 11/12) but not enough (strong_consistency 8/16, posix_multi 0/16 still fail as
tests #2/#3). criteria.json shows all three PASSED 16/16 on base D8BEF5A5 (18:08) — they CAN
pass; variance-gated. This is the deep ~90-session problem and the REAL criteria blocker; the
dlm_scaling fix is orthogonal.

### Cluster hygiene (learned hard)
- ALWAYS `scripts/caw_preflight.sh 16` before a run.
- NEVER kill run.sh mid-test → leaves mxfs mounted → next prep power-cycles 7-10 nodes → 5min
  slow prep → false timeout.
- `virsh -c qemu:///system destroy+start` reboot ALL 16 after heavy runs (SESS50-STARVE +
  shutdowns accumulate; nodes won't rmmod; coherency tests wedge nodes).
- run.sh `TEST_TIMEOUT=300s`; cache_coherency budget=300s (TIMEOUT_BUDGETS.md). External timeout
  >= preflight + ~40s formation + 300s (use 460s).
- Reproduce: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 [dir_perf_probe=1 |
  dir_priv_ex_skip=0 to A/B]" ./run.sh 16 caw <tests>`. No test args = full suite. Grep node
  dmesg for `FUA-COUNT`, `P15-DIRFUA`, `P19-DIRINVAL`.

### Remaining for criteria (1/2/4/8/16/32 caw all 100%)
1. dlm_scaling 16/16: the CAW cross-mkfs epoch fix (above).
2. 16-node coherency variance (systemic deep blocker).
3. dir_reuse_coherency 16/caw: SEPARATE root (EIO node3/4, "no-result readdir 0/1600"),
   was failing before this fix, unaddressed.
4. 32/caw: never run.
5. Re-verify 1/2/4/8 caw on final build 8B203AA4, then write marker.
