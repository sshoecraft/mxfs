---
name: caw-session-STATE-2026-07-07-build-115CCA8C-16of17-and-32-progress
description: ccloop 0d6e174d sess2 STATE (build 115CCA8C): dedup+bast_wq now DEFAULT-ON (fixes 32 coherency, validated). 16/caw=16/17. 32/caw: 5 PASS. Holdouts: d…
metadata:
  type: project
---

## ccloop 0d6e174d sess2 — authoritative STATE (2026-07-07). Marker NOT written.

Read FIRST: [[caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone]]
[[caw-16node-MILESTONE-16of17-pass-dir_reuse-perf-sole-holdout]].

### CURRENT BUILD = 115CCA8CAE1BE39F04E86FD (built + deployed + validated at 32)
CHANGE vs 8B203AA4: made two wedge-preventer params DEFAULT-ON in xfs/xfs_mxfs_dlm.c:
- `mxfs_noino_bast_dedup = 1` (was 0) — line ~12819. Comment always said "ship default should be 1".
- `mxfs_bast_wq_max_active = 32` (was 0/unbounded) — line ~9768.
- WHY: 32-node coherency (posix_multi/strong_consistency) FAIL with ship-0 (EIO+starve, test20 shutdown,
  test1 load 9.5) but PASS 32/32 with these two set. PROVEN: same 2 tests FAIL ship-0 @32 → PASS with
  `MXFS_EXTRA_MODARGS="bast_wq_max_active=32 noino_bast_dedup=1"` → PASS with defaults baked into 115CCA8C
  (ship config, no modargs). Also fixes dir_reuse@16 EIO wedge.
- Version NOT bumped (set via Makefile -D flags; CLAUDE.md forbids editing Makefile). srcversion is identity.
- **NOT YET regression-checked at 16** — MUST run 16 coherency family on 115CCA8C ship config to confirm no
  regression (dedup drops duplicate no-inode BASTs — "safe, peer re-BASTs"; bast_wq=32 non-binding at N<=16).

### 16/caw = 16 of 17 PASS (on 8B203AA4; re-confirm on 115CCA8C)
All PASS except dir_reuse_coherency (PENDING). Every test passes on FRESH-PREP single/small-group runs.

### 32/caw progress (build 115CCA8C, ship config, fresh-prep):
- PASS 32/32: strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness.
- FAIL: **dlm_scaling** 0/32 (ALONE too — not contamination). Root PROVEN: private subdirs get
  `valid_epoch>0` (test1 dmesg: valid_epoch=8,5,32) → disengages dir_priv_ex_skip gate
  (`i_dlm_dir_valid_epoch==0`) → private-dir FUA storm → rate<50/s floor. load=0.51 = coordination-bound,
  NOT local IOPS saturation. This is the CAW CROSS-MKFS STALE-EPOCH false-positive (prev session's
  diagnosis, now pervasive at 32). FIX (bounded, delicate): mkfs_mxfs zero the CAW lock-slot-table region
  in the envelope, OR include FS UUID/gen in the resource so prior-FS tombstones don't match
  (caw_claim_inherit_epoch dlm_caw.c ~717). Membership at 32 converges fine (32/32 stable ~50s).
- UNTESTED at 32: precond_readiness, cache_coherency (SLOW — 32MB cross_write_read, timed out a 3-batch;
  run ALONE with >=480s), scaling_curve, rsync_paired, crash_consistency, fence_during_write,
  fault_netpartition, soak, dlm_lock_correctness, dir_reuse_coherency.

### THE TWO HARD HOLDOUTS (block the criteria):
1. **dir_reuse_coherency PERF** (16 AND 32). Correct with dedup+bast_wq (0 EIO) but ~250-280s/round @16
   (verify ~79s, rm ~60s, create ~50-80s) = ~6000s vs 2240s budget (140*N). SUPER-LINEAR (O(N^2)
   coordination on hot shared dir + 16 nodes cold-verify FUA-storm). fair_handoff=1 is correct but WORSE
   (~300s/round). Needs real perf work (fair+fast anti-starvation, e.g. aging/longest-waiter-first in
   caw_wait_for_grant per sess3; and/or cheaper cold-verify). RULE-0 tension: no native clustered
   equivalent, so "2x native" ceiling undefined; budget doc says "record healthy PASS wall and tighten".
2. **dlm_scaling@32 epoch false-positive** (above) — more bounded; mkfs slot-table-zero is the lead.

### METHOD / HYGIENE
- Clean: `virsh -c qemu:///system destroy+start` test1-16 (and 17-32 for 32). `scripts/caw_preflight.sh N`
  before EVERY run (power-cycles wedged; heavy 32 runs leave ~20 nodes dirty). test17-32 were SHUT OFF at
  session start; started + preflighted them; 32-node infra WORKS (mpath 2-path to all 32).
- Run: `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw <tests>`. Each invocation = fresh prep (re-mkfs+mount).
  To switch 32→16 cleanly, TEAR DOWN mxfs on test17-32 first (else 16's mkfs runs under their mounts).
- External timeout = preflight + formation + test. 32-node formation ~50-60s. cache_coherency@32 is slow.

### REMAINING for criteria (1/2/4/8/16/32 caw 100%):
1. 16 regression check on 115CCA8C. 2. dir_reuse perf (16&32). 3. dlm_scaling@32 epoch fix. 4. finish 32
untested tests. 5. re-verify 1/2/4/8 on 115CCA8C. Marker NOT written.
