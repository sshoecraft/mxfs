---
name: sess51-multi16-state-cwr-fixed-dirstress-discovery-blockers
description: sess51 (run14d): posix_semantics_multi16 — cross_write_read now PASSES (torn-dir-444 gone). New blockers: test_dir_stress (19/80 assertions) + test_d…
metadata:
  type: project
---

## sess51 (ccloop 14d31183) — multi16 cluster-phase state shifted

After recovering the SCST wedge ([[sess51-scst-caw-read-wedge-full-recovery-proven]]) and running the 16-node cluster phase clean (build **5D6E7445** = sess50 phantom-EX fix [[sess50-phantom-ex-waiter-recompute-rootfix]] + new P-WRBUF-DIRTORN write-side probe in pal/linux/xfs_buf.c ~2574), the per-test results:

### PASS (6): concurrent_mkdir(22s) concurrent_touch(30s) concurrent_write(14s) cross_visibility(13s) **cross_write_read(9s)** cv_disc(3s) large_file_integrity(7s)
**cross_write_read NOW PASSES** — the sess50 torn-dir-444 EUCLEAN/shutdown blocker is GONE on clean infra + the phantom-EX fix. The P-WRBUF-DIRTORN / P-IFLUSH-DIRTORN probes did NOT fire (no torn dinode produced). So the torn-dir theory is moot for now; cross_write_read is solved. The probes are harmless (dirwr-gated) — leave them as regression gates or remove later.

### FAIL — new blockers (in priority order)
1. **test_dir_stress** — `19 failure(s) in 80 assertions [30.773s]`. NOT slow (30s) → real CORRECTNESS failures under 16-node dir stress. This is the next target. Find tests/cluster/test_dir_stress.sh, identify which 19 assertions fail + per-node dmesg.
2. **test_discovery** — `1 failure in 2-3 assertions`, but **~125s PER NODE** (16× ~125s, all finish ~338s). 125s ≈ 2× lease_timeout (62s default). discover_peers timing PASSES (avg 3036ms); the failing assertion is the slow one — likely waiting for a departed node to be detected as gone (lease expiry) and either timing out or the detection never completes. RULE 0: 125s is itself a fail. Read tests/cluster/test_discovery.sh.
3. **test_rename_vis_dbg** — phase appeared to stall here >200s (status unknown at relay; may be wedged or just slow). Check next run.

### Ops / repro
- Cluster up: 16 nodes, build 5D6E7445, disk1 freshly recreated (clean PR). After this session the phase was still running (rename_vis_dbg); nodes may be left mounted/dirty — `scripts/cluster_reset_n.sh 16` (power-cycle+prep) then re-run. Prep SEQUENTIALLY if cluster_reset's parallel prep reports NOT_LOADED.
- Run cluster phase: `INSMOD_OPTS="dirwr=1" POSIX_PHASE=cluster bash tests/criteria/posix_phase_timing.sh --nodes 16` (self-mounts, ~80s mount + tests). fua_disable defaults to 1 (correct), instr=0.
- The criterion `posix_semantics_multi16` runs run_tests.sh --phase all --nodes 16; it timed out >600s before because the OLD blocker wedged early. Now it progresses through ~13 tests; failures are dir_stress + discovery (+maybe rename_vis_dbg).
- Build chain: 5D6E7445 added `#include "xfs_bmap_btree.h"` + P-WRBUF-DIRTORN block to pal/linux/xfs_buf.c (decode first dir-EXTENTS extent, log+stack if !xfs_verify_fsbext). xfs/xfs_inode.c has P-IFLUSH-DIRTORN at iflush copy-in (~4265).
