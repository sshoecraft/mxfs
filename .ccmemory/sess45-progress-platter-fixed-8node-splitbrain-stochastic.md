---
name: sess45-progress-platter-fixed-8node-splitbrain-stochastic
description: sess45 HEAD: platter-lag FIXED (dir_release_fua_write=1 default → 4/tcp 3/3). 8/tcp blocker = STOCHASTIC membership split-brain (formation+flap). Add…
metadata:
  type: project
---

## sess45 HEAD — read first. Builds (all on disk at /src/mxfs/mxfs.ko sequentially):
- 1DD4B2F3 = dir_release_fua_write=1 default (platter-lag writer-side fix). KEEP.
- 8371542 = +membership beacon (dlm.c update_active_nodes pr_warn "MXFS-MEMBERSHIP
  local=%u active_count=%d") + run.sh convergence gate (prep waits all N nodes
  report active_count==N stable before workload).
- C074A836 = +SELF-FENCE (dlm/v5_mount.c: stamp ctx->dlm->last_memb_change_ms on
  BOTH peer disconnect (suspect) AND reconnect → engages the memb_settle EX-freeze
  locally so a starved-but-alive node stops granting EX while peers may be evicting
  it). CURRENTLY TESTING.

## PROVEN this session:
1. **Platter-lag root** (the 135-session core bug) FIXED: dir_release_fua_write=1
   (explicit SCSI WRITE16+FUA of released dir blocks at release-drain, LIO
   write-cache bypass) → **4/tcp dir_reuse 3/3 clean** (was ~2/24-fail). Both
   writer-side (dir_release_fua_write) and reader-side (dir_modify_target_flush,
   SYNCHRONIZE CACHE) independently passed 8/8 single runs in prior sess36.
2. **8/tcp residual = MEMBERSHIP SPLIT-BRAIN, stochastic.** Distribution batches
   (tests/drc_batch8.sh, classifies PASS/FLAP/SINGLE/MASS):
   - default 1DD4B2F3: 0/5 (3 SINGLE, 2 MASS)
   - +memb_settle_ms=20000: 0/4 (3 SINGLE, 1 MASS) — reduces MASS
   - +dir_modify_target_flush=1 (combo): 2/4 (2 SINGLE, 0 MASS) — eliminates MASS!
   - +convergence gate (8371542): 0/6 (4 SINGLE, 2 MASS) — high VARIANCE, gate
     alone didn't help mid-run.
   The SINGLE losses survive ALL platter+flush fixes → they are transient
   split-brain (1-dirent), NOT platter-lag. MASS = sustained split-brain (e.g.
   node7_f22-f50 whole-block, a starved node kept writing after eviction).

## ROOT of 8-node split-brain (sess39 + sess45):
master = active_nodes[hash%count]. During formation ramp (beacon shows 5→6→7→8)
AND mid-run flaps (8-VM host CPU starvation → TCP socket stalls >grace), nodes hold
DIVERGENT views → two masters → two EX holders → divergent RMW → loss. The
memb_settle gate (EX-freeze while local view changing) is insufficient: a starved
node declared-dead by PEERS sees NO change in its OWN view (deferred death) → never
freezes → writes as stale master. P-STALEMASTER-GRANT (dlm.c:2649) DETECTS this but
only LOGS — it PROCEEDS to grant.

## NEXT (RULE 4):
- If self-fence (C074A836) converges 8/tcp: make memb_settle_ms=20000 +
  dir_modify_target_flush=1 DEFAULTS, rebuild, full 1/2/4/8 tcp validation.
- If not: (a) make P-STALEMASTER-GRANT BAIL (return retry, don't grant as
  non-master) — dlm.c dg_grant_ex ~2643; (b) watch RULE-0 slowness (self-fence +
  20s freeze per flap may slow/timeout the 480s test); consider lower memb_settle.
- Possible deeper root: the 8-VM-on-one-host environment is CPU-oversubscribed;
  FUA-write adds I/O load aggravating starvation. Could try reader-side flush ONLY
  (lighter) to reduce load.
Harnesses: tests/drc_batch8.sh (dist), drc_cap8.sh (detailed fail capture),
drc_cap4.sh. See [[sess45-RESURRECTED-platter-lag-fix-dir-release-fua-write-default-on]]
[[sess45-8node-residual-is-membership-splitbrain-not-platterlag]]
[[sess39-ROOTFIX-membership-splitbrain-formation-and-flap]].
