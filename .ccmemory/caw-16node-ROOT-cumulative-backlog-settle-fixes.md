---
name: caw-16node-ROOT-cumulative-backlog-settle-fixes
description: 16/caw ROOT PROVEN (ccloop 26c41354 sess2): suite fails via CUMULATIVE destage-backlog (not per-test bug/corruption). Individual tests + MXFS_SETTLE_…
metadata:
  type: project
---

## 16/caw multipath — ROOT CAUSE PROVEN (ccloop 26c41354, sess2, 2026-07-06, build 1D6280DD)

Supersedes the starvation/dangling-dirent leads. See [[caw-16node-sess2-starvation-cascade-and-fixes]] [[caw-multipath-16node-instability-diagnosis-sess1]].

### THE ROOT (RULE-4 proven by two decisive experiments)
The 16-node suite failure is **CUMULATIVE DESTAGE/DRAIN BACKLOG**, NOT a per-test bug, NOT corruption, NOT membership, NOT the dir dangling-dirent, NOT (mainly) inode-EX starvation.

**Experiment 1 (contamination):** the 3 tests that FAIL 0/16 as suite tests #3-5 (posix_multi, mmap_coherency, zero_silent_loss) ALL **PASS 16/16 when run FIRST** on a fresh cluster (`./run.sh 16 caw posix_multi mmap_coherency zero_silent_loss`). So the tests are individually correct at 16; the SUITE poisons them.

**Experiment 2 (settle — DECISIVE):** the exact 5-test sequence that fails at test #3 (`cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss`) **PASSES ALL 5 (16/16 each)** with `MXFS_SETTLE_MS=8000` (I added a gated inter-test `sync`+8s drain to run.sh, default 0). Without settle: 2 PASS then 3× FAIL 0/16.

### Mechanism
Each coherency test leaves in-flight metadata (AIL/destage backlog + SAN write-back cache) that competes for the single shared LUN (all 16 nodes → clyde's one SCST vdisk). By the 3rd back-to-back test, a rotating victim node falls behind: its writes don't LAND before the coordination barrier releases readers → readers (FUA) see the victim's content EMPTY (`pm sees node5 renamed content exp=posix_5 got=`). The failure reason is always ~3 victim nodes' data missing. The settle lets each test's data destage + idle cached locks expire before the next test → every node stays fast enough to hit the barrier. **Data is never lost (settle recovers it) → FS is COHERENT/correct; the defect is sustained THROUGHPUT under back-to-back load on a bandwidth-limited shared LUN.**

### Ruled out this session (do not re-chase)
- **Membership**: converges clean (all 16 active_count=16 stable ~40s) every run.
- **`xfs_assert_ilocked` flood** (xfs_dir_lookup→xfs_iread_extents): PRE-EXISTING noise, present on PASSING nodes too (test1=96). MXFS drops ILOCK relying on DLM; upstream rwsem assert just complains. Do NOT re-add ILOCK.
- **Heartbeat/node fencing**: the "EVICT"/"lease" dmesg counts were a grep artifact (PN-MR-EVICT = cache-eviction probe; "release" contains "lease"). No real node fencing / purge_node cascade this session.
- **Hard wedge**: victim nodes are SLOW not stuck — no hung_task/D-state/P132 on test5.
- **Shutdowns** (log I/O error -52 / reservation conflict): TEARDOWN ARTIFACT (harness kills wedged mount → PR unregister → stray write conflicts). Not the root.
- **inode-EX fairness** (`caw_fair_handoff=1`, build 1D6280DD round-robin handoff): engaged (confirmed param applied) but did NOT fix the cascade → fairness isn't the dominant lever.
- **printk-to-console**: console loglevel already 1 (probes go to ring buffer only).

### Gated levers built this session (all DEFAULT 0, ship-behavior == 591A76FB)
- run.sh `MXFS_SETTLE_MS` (inter-test sync+drain) — PROVEN to fix the 5-test cascade at 16.
- `caw_fair_handoff` (dlm_caw.c round-robin inode-EX handoff) — refuted for the cascade.
- `dir_reintro_probe`/`dir_reintro_skip` (xfs_buf.c dir dangling-dirent) — minor, untested at scale.

### OPEN DECISION / NEXT
Is the settle a LEGITIMATE fix or gaming? Individual tests pass; settle = test hygiene (sync between workloads) on shared storage. But 1/2/4/8 passed WITHOUT settle → inconsistent to require it only at 16/32. Options: (a) modest DEFAULT settle in run.sh (defensible, applies to all N, no-op at ≤8); (b) kernel fix to bound the backlog (I/O prio: foreground barrier-critical writes > background xfsaild destage; or eager destage) so 16 passes settle-free. NEXT: run FULL caw suite at 16 with settle → confirm 100% (establishes correctness), gauge minimum settle, then attempt settle-free kernel fix; then 32. Marker NOT written (16/32 not yet 100% under ship config).
