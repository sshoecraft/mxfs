---
name: ccloop-c7ee71c6-sess311-relgate-fault-sites-are-iclus-only-knob-off
description: sess311: relgate fault stages UNREACHABLE under production config — all 8 sites are ICLUS(class=2)-only and icluster_dlm=0 default; driver written
metadata:
  type: project
---

# sess311 — fault-inject leg blocked: stages are ICLUS-only, ICLUS is off

## What was built
- Fleet re-prepped to knob=1 (144s, 0.11.511 sv EB44E6A843CF082A799AF9D x32).
- `tests/relgate_fault_inject.sh` WRITTEN (defer + wedge modes, RULE 3).
  Churn v1 (per-node private create/rm) produced ONLY class=1 certs, 0 fault
  hits. Churn v2 (all nodes append to the SAME 64-file set in one shared dir
  → cross-node same-inode EX ping-pong): still class=1 only, fault_hits=0,
  but 18 defer_oblig + 19 tripwire_retries fired naturally and ALL resolved;
  cas_noproof_v2=0, wedges=0 throughout. Runs: tests/logs/relgate_defer_
  20260815_064850 and _065327 (test2 target, test3-5 peers).

## Root cause of fault_hits=0 (PROVEN by code reading + counters)
- ALL 8 mxfs_relgate_fault() sites live in the ICLUS release path
  (xfs_mxfs_dlm.c 47521-48062), emitted class=2 certs only.
- ICLUS routing requires `mxfs_icluster_dlm=1` (mxfs_iclus_routed, 27872) —
  and the knob DEFAULTS 0, load-time-only (0444). Fleet runs 0.
- Comment at 46910: "MUST STAY 0 until (1) BAST fan-out invalidating covered
  cached inodes before on-disk release and (2) call-site routing in
  ilock_begin/bast_process/inactive land — with the knob off this layer is
  inert scaffolding." NOTE: mxfs_iclus_fan_out EXISTS (48163) and routing
  exists (mxfs_dlm_inode_lock_routed 27896) — the comment may be STALE;
  verify before trusting either way.

## Consequences
- The sess309 step-6 ICLUS machinery (per-cluster worker, wedge, stages
  7/9/10) has NEVER executed on any board — boards run icluster_dlm=0.
- sess310's "5 natural defers" were INODE-class (mxfs_inode_relcert_defer
  15040, call sites 18860/19016), same class as this session's 18.
- INODE-class enforcement DOES hold under targeted contention: defers
  resolve via retry, tripwire bounces, cas_noproof_v2=0.

## Next (RULE-5 consult recommended first)
Ask GPT: (a) is fault-inject verification of the INODE-class defer path
sufficient for step-6 F1 given icluster_dlm=0 is the production config
(are there fault hooks in the INODE path? none found — stages are ICLUS
symbols), (b) should an icluster_dlm=1 rig config be stood up to exercise
the ICLUS machinery (check the 46910 comment's two prerequisites first),
or (c) treat the ICLUS layer as dormant scaffolding whose verification
belongs to the future icluster enablement, and close the fault leg on
INODE-class evidence + admission-closure checks.
Driver fixes if ICLUS config is chosen: expect class=2 certs, and the
churn (shared-file appends) should then BAST ICLUS resources directly.
