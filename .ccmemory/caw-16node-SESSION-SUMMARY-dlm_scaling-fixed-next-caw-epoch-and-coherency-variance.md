---
name: caw-16node-SESSION-SUMMARY-dlm_scaling-fixed-next-caw-epoch-and-coherency-variance
description: SESSION SUMMARY ccloop 0d6e174d: dlm_scaling ROOT proven + SAFE fix shipped (build 8B203AA4, dir_priv_ex_skip). Now 15/16 (last node=CAW cross-mkfs s…
metadata:
  type: project
---

## SESSION SUMMARY — ccloop 0d6e174d (2026-07-06/07). Marker NOT written.

Entry point for next session. Detail memories: [[caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm]]
[[caw-16node-dlm_scaling-FIX-private-ex-fua-skip]] [[caw-16node-session-state-dlm_scaling-fixed-coherency-variance]].

### SHIPPED (build 8B203AA4A99375F9B774F79 — CURRENT deployed, validated safe)
**dlm_scaling private-dir FUA-skip.** Param `dir_priv_ex_skip=1`. Gate `i_dlm_mode==MXFS_LOCK_EX &&
!i_dlm_dir_contended && i_dlm_dir_valid_epoch==0` at xfs_da_btree.c owned_ex (~3095) + xfs_dir2_data.c
mxfs_dir_addname_coherent_refresh (~2088). Skips the private-subdir dir-FUA storm.
- ROOT PROVEN (RULE-4): dlm_scaling FAIL 0/16 = each node ~5860 coherency-UNNECESSARY SCSI-FUA reads
  of its OWN private dir block (P15-DIRFUA daddr=72, fua_always=1 real default). NOT disk-bound.
- SAFE: cache_coherency PASSED 16/16 WITH the fix (×2 good runs); P-PRIVSKIP probes showed 0 engagement
  on shared dirs (valid_epoch>0 disqualifies them). Earlier `!contended`-only (build 98D240B3) REGRESSED
  cache_coherency (concurrent-mkdir/create window); adding valid_epoch==0 closed it. `#include
  "../dlm/v5_mount.h"` added to xfs_da_btree.c for MXFS_LOCK_EX.
- RESULT: dlm_scaling **15/16** (was 0/16). Big win, not complete.

### WHY dlm_scaling is 15/16 not 16/16 (CONFIRMED, next fix)
ONE rotating node's private subdir spuriously gets `valid_epoch>0` (measured test4: valid_epoch=1,3;
FUA-COUNT dir=5972 = skip disengaged) → full FUA storm → dips under 50/s floor. Passing nodes: <256
FUA total (skip engaged, valid_epoch=0). ROOT: CAW `dir_epoch` lives in the on-disk CAW LOCK slot table
(mxfs_caw_lock_slot, in the MXFS envelope). `mkfs_mxfs.c` does NOT zero/init it → a prior FS's tombstone
survives mkfs; a fresh subdir reusing that inode number matches by resource (caw_claim_inherit_epoch,
dlm_caw.c:717, same-resource tombstone) → inherits stale last_ex_slot → caw_advance_epoch sees a false
cross-node handoff → dir_epoch++ → grant carries it → i_dlm_dir_valid_epoch>0. FIX OPTIONS (delicate,
validate w/ multiple runs): (a) mkfs_mxfs zero the CAW lock-slot-table region; (b) include FS UUID/gen in
mxfs_resource_id so prior-FS tombstones don't match; (c) clear slot table at cluster-format/mount.
REFUTED margin idea: relaxing gate to drop mode==EX cut FUA 7189→<256 but did NOT fix 15/16 (reverted).

### THE SYSTEMIC BLOCKER (pre-existing, NOT my fix): 16-node coherency VARIANCE
cache_coherency/strong_consistency/posix_multi at 16 are ~50% flaky standalone (PASS 16/16 vs FAIL
0/16 on identical fresh clusters) — rotating victim node, content empty (writes don't land before
barrier = SESS50-STARVE EX-writer starvation + durability drain race on concurrent same-dir create).
MXFS_SETTLE_MS=8000 helps contamination (cache_coherency passed) but NOT enough (strong_consistency
8/16, posix_multi 0/16 still failed as tests #2/#3). criteria.json shows these PASSED at 16 on base
D8BEF5A5 — variance-gated. This is the deep 90-session problem; the REAL criteria blocker.

### ENVIRONMENT (characterized — NOT the bottleneck)
Shared LUN = /home/steve/disk.img (50GB) via SCST vdisk_fileio on /dev/nvme0n1p2 (Samsung 990 EVO Plus
2TB SSD, rotational=0, 12% util). clyde 94GB RAM. 16-node failures = FUA round-trip latency (~3-5ms/read)
+ DLM handoff coordination, NOT disk bandwidth. Reducing redundant FUA is the right lever.

### CLUSTER HYGIENE (critical)
ALWAYS `scripts/caw_preflight.sh 16` before a run. NEVER kill run.sh mid-test (leaves mxfs mounted →
next prep power-cycles 7-10 nodes → 5min slow prep → false timeout). `virsh -c qemu:///system
destroy+start` reboot all 16 after heavy runs (SESS50-STARVE + shutdowns accumulate, nodes won't rmmod;
coherency tests wedge nodes). run.sh TEST_TIMEOUT=300s; cache_coherency budget=300s. External timeout
>= preflight + ~40s formation + 300s (use 460s). Run: `MXFS_DEV=/dev/mapper/mpatha
MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 16 caw <tests>`. No test args = full suite.

### REMAINING FOR CRITERIA (1/2/4/8/16/32 caw all 100%)
1. dlm_scaling 16/16: CAW cross-mkfs epoch fix (above).
2. 16-node coherency variance (systemic): the deep blocker.
3. dir_reuse_coherency 16/caw: separate root (EIO node3/4), unaddressed.
4. 32/caw: never run.
5. Re-verify 1/2/4/8 caw on final build.
Builds: D8BEF5A5(base)→98D240B3(v1 REGRESSED)→8B203AA4(v2 SAFE, CURRENT)→[787CCEE8/B5FED995 experiments, reverted].
</body>
