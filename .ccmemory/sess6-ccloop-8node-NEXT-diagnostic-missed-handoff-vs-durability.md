---
name: sess6-ccloop-8node-NEXT-diagnostic-missed-handoff-vs-durability
description: sess6(run6614) N=8 dir_reuse NEXT precise diagnostic: fastret_stale=0 rules out 'gen>loaded stale serve' + demoter_bypass, but NOT missed-handoff (gr…
metadata:
  type: project
---

## sess6 (run 6614) — N=8 dir_reuse: precise next diagnostic (amends the DECISIVE memo)

### NUANCE on the P6-DIRPATH finding (fastret_stale=0):
gen==loaded at every dir-EX serve rules OUT "a gen>loaded stale base is served" and rules OUT the demoter-bypass. BUT it does NOT rule out a **MISSED HANDOFF**: if grant_gen does NOT change on a real cross-node handoff, gg_refresh never arms, gen is never bumped, so gen==loaded (fastret_stale=0) yet the cached/cold base is stale vs the peer. So TWO live candidates remain, both consistent with fastret_stale=0:
  A. **Missed handoff**: the grant_gen signal (hgg) fails to change on some real N=8 handoff → gg_refresh skipped → base never refreshed. (Would also mean the base is content-stale.)
  B. **Release-durability gap**: handoff detected + cold-read done, but the peer's committed dir block isn't durable on the LUN (disk behind gen).

### NEXT SESSION — decisive counters to split A vs B (build on 97E09EE8's P6 counter infra):
1. In the dir-EX fast-path serve, when we read hgg (grant token) at ~14815: count (a) serves where hgg != cached_grant_gen (handoff detected → gg armed) vs (b) serves where hgg == cached_grant_gen (no handoff seen). If a real handoff happened but hgg==cached (missed), that's candidate A. Cross-check: also record whether mxfs_v5_dlm_inode_grant_gen ever returns 0/stale at N=8 (the query used for hgg) — an unreliable grant_gen query = candidate A root, fix the query/store (like the sess5 dir_epoch max-across-mirrors fix but for grant_gen).
2. For candidate B: add a per-dir-block "cold-read content vs expected" check, OR simply TEST loosening durable_signal (xfs_mxfs_dlm.c:18593, currently gated gen>0 && fmt EXTENTS/BTREE) to always-flush for peer-reachable (!self_created) multinode dirs — if N=8 improves, B confirmed. (durable_signal already synchronous bwrite+blkdev_flush; the gate is the only obvious hole, though gen>0 is usually true for the storm dir by the .md5 wave.)

### STATE: shippable = 9AA569A0 (gg_refresh+leaf_flush; 1/2/4 tcp=100%, 8/tcp=16/17). Measurement build on nodes = 97E09EE8 (adds harmless P6-DIRPATH/DIRPHANTOM counters + dump param dirphantom_dump). rsyslog masked all 8 nodes (keep it — else disks refill, see [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]]).
See [[sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap]]</body>
