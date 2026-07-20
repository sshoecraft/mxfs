---
name: sess3-MID2-run17-no-shutdowns-starvation-next
description: sess3(a16ec5f2) MID2: build 780517DA = SFTORN fix + LKTIMEOUT holder dumps. run17: 0 shutdowns, 19 rounds, fails=r1(600/800 cold-start)+r9(1 dangling…
metadata:
  type: project
---

# sess3 run17 state (build 780517DA, all deployed via run.sh)

## Where things stand after the SFTORN root fix
- run16 (49A0E80D): 15 rounds/480s, no cluster shutdown; test6 solo shutdown = AG2 -110 ABBA (test3 stuck 60s on dir-131 INODE EX while holding AG2 cached; test6 held dir-131 EX waiting AG2 → dirty trans_cancel).
- run17 (780517DA, fresh-boot all 8): **ZERO shutdowns, zero -110 escalations, 19 rounds in ~480s**. Fail rounds: r=1 readdir=600/800 on all nodes (200 files = 2 creators' worth missing at cold start — creates too slow/failed; RDMISS lines absent/rotated), r=9 lookup_fail=1 node7_f23 (dangling dirent: in readdir, stat ENOENT — P26-IGET face). 17/19 rounds CLEAN.
- P-DBLALLOC warnings 12-25/node/run remain — most likely benign freed-dir-leftover content (marker can't distinguish mapped-vs-free; enhance with a map-check if it matters).
- P-LKTIMEOUT-HOLDER dump (dlm.c, local-master path, fires per 1s pending_wait expiry): shows dir-131 queue depth: 3+ PR WAITING/BLOCKED + EX GRANTED held ~300ms (long tenures = release fence). P-LKTIMEOUT-REMOTE names master. hstate enum: 1=WAITING 2=GRANTED 3=CONVERTING 4=BLOCKED. Master of ino131 lock in run17 = node 3760276581; that node ALSO self-starved (519 expiry logs) → master grant queue fairness suspect (sess50 CAW had defer_for_waiter fix; TCP path may lack equivalent).

## Current blockers to 8/tcp 100% (in order)
1. **Cold-start r=1 create slowness/loss** (200 files missing round 1 — likely 2 nodes' dd creates failed/slow during initial lock-master churn; verify via harness stream logs /root/drc_stream_rankK.log dd errors + P34-ACQ-SLOW).
2. **Dir-EX starvation/fairness under 8-way storm** (test7 self-starved as master; 60s acquire budget can still expire → -110 → dirty cancel shutdown (run16's test6). Fix directions: FIFO/aging in master grant queue (promote_waiters order), defer_for_waiter equivalent for TCP, or a bounded holder-tenure cap; ALSO the ABBA: dir-EX holder waiting on AG must trigger AG-yield on the AG-holder waiting for THAT dir (holder dump now names them).)
3. Dangling dirent face (r=9 node7_f23, rare): dirent present, ino stat fails.
4. Pace: ~25s/round vs 20s needed for 24r/480s. Probe overhead contributes (PW spam, P26-DSCAN per negative lookup over holey dirs + MAP_HOLE internal-error reports). After correctness: strip/gate probes, re-measure; consider dscan skip for create-intent negative lookups (careful: leaf-hash-hole → duplicate-name risk).

## Loop for verification (unchanged)
`timeout 260 scripts/ccloop_reset.sh 8; MXFS_EXTRA_MODARGS="watch_daddr=131 watch_ino=131" ./run.sh 8 tcp dir_reuse_coherency` (~9 min). Harvest: dmesg from all 8 to scratchpad runNN/, window per node by LAST `DRCph r=1 rank=. PHASE=create-start` (fresh-boot the VMs to avoid multi-run rings: virsh -c qemu:///system destroy/start all 8, sleep 55).
Then: ≥5 consecutive clean 8/tcp, 4/2/1 regression, full ./run.sh N tcp suites ×{1,2,4,8} before writing YES to /src/mxfs/.ccloop/runs/a16ec5f2-e661-430d-b60e-1535d93bf93a/criteria-met.

Links: [[sess3-ROOT-FIX-sftorn-skip-consumed-ili-fields]]
