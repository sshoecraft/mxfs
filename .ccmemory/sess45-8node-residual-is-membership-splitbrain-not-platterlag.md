---
name: sess45-8node-residual-is-membership-splitbrain-not-platterlag
description: sess45: platter-lag fix (dir_release_fua_write=1) VALIDATED at 4/tcp 3/3. 8/tcp residual = MEMBERSHIP SPLIT-BRAIN (formation ramp + TCP flap), domina…
metadata:
  type: project
---

## sess45 — 8-node residual is membership split-brain, NOT platter-lag

### Validated this session (build 1DD4B2F3 = dir_release_fua_write=1 default):
- **4/tcp dir_reuse: 3/3 PASS** (was baseline ~2/24-fail). The platter-lag fix
  (writer-side SCSI WRITE16+FUA at release-drain) is correct + reliable at 4 nodes.
  KEEP IT — it is the mode-A (single-dirent platter-lag) fix.
- **2/tcp**: per resume already passes (re-confirm).

### 8/tcp failure-mode distribution (build 1DD4B2F3):
- run1: iter1 PASS 8/8; iter2 FAIL — TCP FLAP ("peer did not reconnect within
  15000ms — declaring dead") → P-STALEMASTER-GRANT split-brain → MASS loss (11
  .md5 files).
- grace45 run (tcp_death_grace_ms=45000): iter1 FAIL — single-dirent node5_f1 at
  round 2, NO flap (formation-ramp split-brain or residual mode-A).
- batch8 default: iter1 FAIL/MASS(17) — node3+node7 files, NO flap detected =
  formation-ramp split-brain.
=> DOMINANT 8-node fail = MEMBERSHIP SPLIT-BRAIN (mostly MASS loss, early rounds
1-3), NOT the platter-lag (now fixed; shows only as the rarer single-dirent case).

### ROOT (sess39, re-confirmed): inconsistent active_nodes across nodes →
master=nodes[hash%count] diverges → two nodes grant EX for the same dir →
divergent RMW → mass loss. Two triggers: (1) FORMATION ramp 1→8 (workload starts
before convergence — run.sh prep verifies mount+build but does NOT wait for
N-member convergence); (2) mid-run TCP FLAP under host CPU starvation (8 VMs on
clyde) → false death → rejoin with stale grants.

### WHY memb_settle_ms=6000 (sess39 gate) is insufficient: it freezes EX for 6s
after the LOCAL last-membership-change, but a node's view goes "stable" before it
learns of a late-joining peer (lease UDP propagation lag) → it proceeds with a
stale count. Fix candidates (RULE 4, test one at a time):
  1. Increase memb_settle_ms (6000→20000): longer freeze after last join lets all
     nodes converge before EX work. Runtime param — test FIRST (no rebuild).
  2. Harness convergence gate: run.sh prep waits until all N nodes report N active
     members before the barrier workload (needs a per-node active-count readback;
     /proc/fs/mxfs exists in pal/linux/xfs_stats.c — could add /proc/fs/mxfs/members).
  3. Increase tcp_death_grace_ms (15000→45000) for the flap (grace45 test was
     inconclusive — that iter failed via formation not flap).

### NEXT: test memb_settle_ms=20000 at 8/tcp (batch). Harnesses:
tests/drc_batch8.sh <iters> [modargs] (non-breaking, classifies
PASS/FLAP/SINGLE/MASS), tests/drc_cap4.sh, tests/drc_cap8.sh. Build 1DD4B2F3.
Criterion = full 1/2/4/8 tcp 100%. See
[[sess45-RESURRECTED-platter-lag-fix-dir-release-fua-write-default-on]]
[[sess39-ROOTFIX-membership-splitbrain-formation-and-flap]].
