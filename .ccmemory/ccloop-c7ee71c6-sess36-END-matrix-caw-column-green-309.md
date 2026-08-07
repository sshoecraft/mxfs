---
name: ccloop-c7ee71c6-sess36-END-matrix-caw-column-green-309
description: sess36 END: caw matrix column green 1-16, 32=20/21; 309 = PROBE-A transient guard; 4 defects closed today; 10 OPEN; next = pace family or authority p…
metadata:
  type: project
---

# sess36 END state (builds 305-309, srcversion 309=086FA2DC deployed)

## Session scorecard
- CLOSED (FIXED AND VERIFIED, GPT-ruled): D-CRASH-COLDREAD-STALE-SPLIT, D-SILENT-MKDIR-LOSS, D-CAW-YIELD-STARVATION-SHUTDOWN, D-UNMOUNT-BUSY-INODES (root = bast_notify queue-false ref leak, fixed 307, injector-proven 308).
- OPENED (honest splits): D-DIRVIEW-NONCONVERGE-SESS25 (high), D-DWORK-TEARDOWN-LASTREF-LEAK (medium).
- Net: 12 -> 10 OPEN.
- Boards: 306 = 20/21, 308 = 20/21 (only FAIL = dir_reuse pace at 32).
- MATRIX caw column COMPLETE on current builds: 1/2/4/8/16 fully green, 32 = 20/21. dirent_publish_integrity green at every count (was red everywhere on 237). tcp/cawd/cawp columns remain rig-blocked (per-condition XML disks; sda held by mpatha dm-1).

## Key fixes this session
1. 306: removed i_dlm_stale exemption from terminal release gate (dss census: 459/459 = src5, the release's OWN mark; gate self-disarmed). P244 defers now fire (~300/board), P241 blind discharges = 0 everywhere since.
2. 307: bast_notify queue_work-false paths (4 sites) now xfs_irele the extra ref — the 5-session unmount-leak root. Kernel kprobe ref-trace method in tests/refleak_trace.sh + tests/refleak_analyze.py.
3. 308: TEST-ONLY mxfs.bast_qfalse_inject (branch-coverage injector; 126 collisions, 0 leaks).
4. 309: PROBE-A re-reads authority before dump_stack (self-refuting transient tripped soak@4).

## 4/caw transients dispositioned (matrix history)
- soak FAIL = PROBE-A dump_stack noise (fixed 309, soak untouched).
- ag_strand_repair FAIL test1 strands=0 = harness injection-arming window missed the release at low N; PASS on re-run; repair path exercised at 2/4/8/16/32 (repaired=1-2 each).

## The 10 OPEN, grouped for attack
- PACE family (needs reader-state/writer-gate redesign — protocol IO per release, TRAP-1 ceiling): D-DIR-REUSE-COHERENCY-32-FLAKY (only board FAIL; 4-7 rounds vs >=8; su decomposition in 302 showed sx=12-54ms wire-unlock under storm), D-32NODE-SHARED-DIR-CREATE-PACE (42x), D-READDIR-PEER-CACHED-DIR-PACE (1.2s/dir).
- AUTHORITY family (needs per-slot authority-token protocol): D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (P219 contained: 64 masked all landed, 55 EX-restaged, 0 unlanded, 0 fatal on 306 board), D-RELEASE-BARRIER-OPEN (umbrella; terminal instance closed 306; ISTALE/ifree slots still mode-based), D-FOREIGN-REPLAY-UNGATED-IMAGES (containment shipped 273-274; next = mount-time adopted-slice suppression via disklock prior-slot state, then full protocol).
- MEASUREMENT: D-MOUNT-DEGRADES-WITH-USE (today's aged-mount cc laps ran FAST (24-31s) — counter-evidence; entry needs its specific workload re-tested), D-MATRIX-UNMEASURED (only rig-blocked columns left).
- NARROW: D-DIRVIEW-NONCONVERGE-SESS25 (needs repro pressure), D-DWORK-TEARDOWN-LASTREF-LEAK (fix direction: flush bast wq before pag teardown; repro via shutdown injection).

## Rig state at handoff
Cluster prepped 1/caw on 309 (last matrix column). Marker=1/caw. For 32-node work: MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster first. kprobe traces DISARMED. dmesg rings dirty (matrix runs) — clear before censuses. Host load 14-22 typical this week; >25 slows VMs (pace tests noisy).

## Criteria: NOT production ready — 10 OPEN defects against the RULE 6 zero-defect bar.
