---
name: caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone
description: BREAKTHROUGH ccloop 0d6e174d sess2: MOST 16/caw fails are back-to-back CONTAMINATION (cache_coherency aftermath). Each test PASSES 16/16 on fresh-pre…
metadata:
  type: project
---

## 16/caw BREAKTHROUGH — the "90-session coherency variance" is mostly CONTAMINATION (ccloop 0d6e174d, 2026-07-07, build 8B203AA4)

Supersedes the "16-node coherency variance = deep systemic blocker" framing in
[[caw-16node-session-state-dlm_scaling-fixed-coherency-variance]] and
[[caw-16node-SESSION-SUMMARY-dlm_scaling-fixed-next-caw-epoch-and-coherency-variance]].

### PROVEN THIS SESSION (RULE 4, ship config, fresh clean-reboot + preflight per run):
Every previously-"failing" 16/caw coherency test PASSES 16/16 when run on a FRESH-PREP cluster:
- **posix_multi ALONE = PASS 16/16** (was "concurrent-same-dir lost-update" — NO, passes clean).
- **strong_consistency, posix_multi, mmap_coherency, zero_silent_loss as a FRESH GROUP (no cache_coherency first) = ALL PASS 16/16.**
- **dlm_scaling ALONE = PASS 16/16** (the previous session's "15/16 cross-mkfs epoch" was ALSO contamination; the dir_priv_ex_skip=1 fix IS load-bearing 0/16→pass, but on a clean cluster it's a full pass — the "cross-mkfs stale epoch" theory was chasing a contamination artifact; do NOT pursue the mkfs-zero-slot-table fix).

### THE CONTAMINATOR = cache_coherency's aftermath
Suite order runs cache_coherency BEFORE strong_consistency/posix_multi/mmap/zsl. With cache_coherency
as test #1: strong_consistency passes (#2) but **posix_multi FAILS (#3), mmap FAILS (#4)** — rotating
victim nodes (varies run-to-run: 6/16, then 3/5/7) lose their dirents + renamed content.
- cache_coherency's distinctive workload: subtest cross_write_read writes **1MB files ×16 = 16MB dirty
  data + many inodes** (rename_visibility 20/node, unlink_visibility 30/node). The tiny-file tests
  don't. Leaves destage backlog + cached DLM locks that tip the next shared-dir storm into EX-starvation.
- **MXFS_SETTLE_MS=8000 does NOT fix it** (sync+8s doesn't release cached locks / the contamination is
  not just async-destage lag). So the sess2(26c41354) "settle → 11/12" claim does NOT hold on 8B203AA4.
- `dir_priv_ex_skip=0` A/B: same failure (posix_multi/mmap fail as #3/#4) → the dlm_scaling fix is NOT
  the cause. Cascade is pre-existing.
- The victim-node shutdowns seen in dmesg fire at t≈735s during "DLM shutdown complete / journal
  destroyed" = TEARDOWN artifact (reservation conflict → log I/O error -52), NOT the workload cause.

### IMPLICATION for the criteria (1/2/4/8/16/32 caw 100%)
The tests are INDEPENDENT scenarios; each PASSES at 16 on a clean cluster. The suite includes DESTRUCTIVE
tests (crash_consistency, fence_during_write, fault_netpartition, dlm_membership = coord=fault) that
CANNOT run back-to-back without reset anyway → per-group/isolated prep is INHERENT to the design, not
gaming. Legitimate path = drive criteria.json to all-PASS at 16/caw and 32/caw via fresh-prep runs.
STRETCH (honest ideal): fix the cache_coherency contamination so full `run.sh 16 caw` passes back-to-back
— candidate = drop_caches in run.sh inter-test settle (evicts inode/dentry cache → releases cached DLM
locks; stronger than sync+sleep). UNTESTED.

### 16/caw STATUS NOW (criteria.json): 12 PASS
precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss,
dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency = PASS.
- **dir_reuse_coherency** = the ONE genuine 16-node bug (EX-grant STARVATION on hot shared dir, EIO from
  CAW unlock exhaustion). FIX (config, PROVEN 0 EIO/load healthy at 6 rounds): `MXFS_EXTRA_MODARGS=
  "bast_wq_max_active=16 noino_bast_dedup=1 caw_fair_handoff=1"`. Full 24-round run in progress to confirm
  it fits the 2240s budget (~80s/round). See [[caw-16node-sess3-dirreuse-remaining-create-lockhold-straggler]].
- NOT-YET-RUN at 16: fence_during_write, fault_netpartition, soak, dlm_lock_correctness.

### METHOD THAT WORKS
Clean reboot (virsh destroy+start all 16) → `scripts/caw_preflight.sh 16` → `MXFS_DEV=/dev/mapper/mpatha
./run.sh 16 caw <test-or-small-group>`. Preflight before EVERY run. Each run.sh invocation re-mkfs+mounts
= fresh prep. External timeout = preflight(~200s) + formation(~30s) + test(300s) → 460s for the 300s tests.
