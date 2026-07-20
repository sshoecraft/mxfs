---
name: caw-16node-sess2-HANDOFF-levers-and-next
description: 16/caw sess2 HANDOFF (ccloop 26c41354, build DC39A8DC): 3 fails at 16 have 3 distinct roots+levers — coherency-cascade=settle(WORKS,11/12 pass), dir_…
metadata:
  type: project
---

## 16/caw multipath — sess2 HANDOFF (ccloop 26c41354, 2026-07-06, HEAD build DC39A8DC)

Read FIRST: [[caw-16node-ROOT-cumulative-backlog-settle-fixes]] [[caw-16node-sess2-starvation-cascade-and-fixes]]. Marker NOT written (16/32 not 100%).

### THE FULL 16-node picture (measured this session, FULL suite `./run.sh 16 caw` with MXFS_SETTLE_MS=8000)
**11 PASS**: precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, rsync_paired, crash_consistency.
**3 distinct FAILURE MODES remain** (each needs a different lever):
1. **Coherency cascade** (posix_multi/mmap/zsl fail as suite tests #3-5) — ROOT = cumulative destage backlog. **FIXED by MXFS_SETTLE_MS (inter-test sync+drain, added to run.sh, default 0). PROVEN: 11/12 pass with settle=8000.** Not corruption (data recovers). See [[caw-16node-ROOT-cumulative-backlog-settle-fixes]].
2. **dir_reuse_coherency WEDGE** — 16 nodes hammer ONE shared dir → hot-inode CAS storm → **CAW UNLOCK exhausts 100 tight retries (no backoff!) → -EIO → lock stuck → BAST re-fires → mxfs-ino-bast wq spawns 1000+ blocked kworkers → load 870 WEDGE** (dmesg: `unlock exhausted 100 retries ino=538066`). `caw_fair_handoff=1` PREVENTS the wedge (load ~1.0, unlock_exhausted=0) but is TOO SLOW → dir_reuse TIMES OUT at 2240s budget (round-robin adds ~25ms/handoff × huge handoff count).
3. **dlm_scaling FAIL** = `rate>=floor` on all nodes — floor 50 ops/sec/node (DLM_SCALING_FLOOR_OPS); disjoint per-node subdirs + ~50 AGs so NOT lock/AG contention → **shared-LUN IOPS saturation** (16 nodes × create+stat+unlink metadata I/O + fua_always=1 every-read-is-FUA on one loopback vdisk). Hard/maybe infra-limited.
UNTESTED behind the wedge: fence_during_write, fault_netpartition, soak, dlm_lock_correctness.

### Gated levers built (all DEFAULT 0; ship == 591A76FB behavior; on DC39A8DC)
- **`MXFS_SETTLE_MS`** (run.sh env) — WORKS for mode 1. Set e.g. 8000.
- **`caw_fair_handoff`** (dlm_caw.c) — round-robin inode-EX handoff. Prevents mode-2 wedge but too slow. Latency = chosen node's poll_ms (MXFS_CAW_POLL_MAX_MS=25) per handoff.
- **`caw_unlock_backoff`** (dlm_caw.c, NEW build DC39A8DC, UNTESTED) — jittered node-phased backoff (1..15ms) on INODE unlock CAS -EAGAIN (the acquire path already desyncs via sess39; unlock lacked it). Targets mode-2 WEDGE at LOW cost (no serialization, unlike fair_handoff). Hypothesis: desync lets unlock win within 100 retries → no -EIO → no wedge, WITHOUT fair_handoff's throughput hit.
- `dir_reintro_probe`/`dir_reintro_skip` (xfs_buf.c) — dir dangling-dirent, minor (fired 1×), untested at scale.

### NEXT (RULE 4, precise)
1. **Test `caw_unlock_backoff=1` on dir_reuse at 16** (fair_handoff OFF): `caw_preflight.sh 16` then `MXFS_EXTRA_MODARGS="caw_unlock_backoff=1" ./run.sh 16 caw dir_reuse_coherency`. Watch test1 `uptime` load (wedge=load>100; healthy=~1) + `dmesg|grep -c "unlock exhausted"` (must stay 0). If no wedge AND completes <2240s → mode 2 solved cheaply → make default 1. If backoff insufficient (still exhausts 100), the param comment already describes the no-EIO wall-clock-bounded retry to ADD (I did NOT implement that half yet — only the -EAGAIN backoff).
2. If unlock_backoff prevents wedge but dir_reuse still too slow → EITHER make fair_handoff faster (cap poll_ms lower for fair-handoff inode waiters so chosen node reacts in ~3ms not 25ms) OR accept dir_reuse is fundamentally O(N)-slow (sess21 memory) and check it just needs to fit 2240s.
3. Then run FULL suite at 16 with settle + the winning anti-wedge lever → confirm fence/netpartition/soak/dlm_lock_correctness. Then dlm_scaling (may need floor reconsideration or fua reduction — but fua_always=1 is REQUIRED for coherency).
4. Then 32 nodes (all modes worse).

### OPEN QUESTION (settle legitimacy)
Settle fixes mode 1 but 1/2/4/8 passed WITHOUT it → requiring it only at 16/32 is inconsistent/possible-gaming per RULE-0 ethos. Decide: modest DEFAULT settle in run.sh (applies to all N, no-op ≤8) vs kernel fix to bound backlog (I/O prio: foreground barrier-critical > background xfsaild destage). Autonomous loop = my call; lean toward trying the kernel backlog-bound before defaulting the settle.

### Infra
`scripts/caw_preflight.sh N` before EVERY run (resets wedged nodes — after a dir_reuse wedge nodes have 1000+ D-state, MUST power-cycle). NEVER `pkill -f 'run.sh 16 caw'` (self-matches → exit 144); kill by captured PID. Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass. Poll long runs via `while ls -d /proc/$PID`.
