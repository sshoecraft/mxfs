---
name: sess15run-FIX-P58-rel-abort-VERIFIED-tcpdlm-now-slowness-only
description: sess15(ccloop) VERIFIED FIX (build 48C6A95E, KEEP): bast_process P15-REL-ABORT — abort dir release if holder re-acquired during drain. Eliminates tcp…
metadata:
  type: project
---

## sess15(ccloop) — VERIFIED FIX: P58-DIRPIN-NONEX resurrection (tcp_dlm_scaling 8/tcp)

### The fix (build 48C6A95E, KEEP — correctness win)
`xfs/xfs_mxfs_dlm.c` `mxfs_dlm_bast_process`, right before `i_dlm_mode = MXFS_LOCK_NL` (~line 6375): re-check holders under `i_dlm_lock`. If `i_dlm_ex_holders>0 || i_dlm_pr_holders>0` (a fast-path acquire raced in DURING the async drain), **ABORT the release**: clear `MXFS_IF_DLM_RELFLUSH`, set `i_dlm_state=MXFS_DLM_ISTATE_BAST` (re-arm), `wake_up_all(&i_dlm_wait)`, and RETURN — keep the grant, do NOT set NL, do NOT unlock. The holder's `mxfs_dlm_ilock_end` re-fires the BAST once `ex_holders` drops to 0 (established deferred-BAST pattern, P-NONE-HELD-DEFER). Logs `P15-REL-ABORT` (always-on, ratelimited). Safe: `bast_work_fn` sets/clears `i_dlm_demoter` and ireles around the call, so early return leaks nothing.

### PROVEN (RULE 4)
Probe `P15-NL-WHILE-HOLDER` fired: `ino=14680192 mode=EX ex=1 state=DEMOTING` on the `mxfs-ino-bast` kworker in `mxfs_dlm_bast_process` — bast_process was queued when ex_holders==0 (bast_notify guards that) but a fast-path acquire re-incremented ex_holders during the drain, and the OLD code released to NL anyway → holder commits dir at NL → `P58-DIRPIN-NONEX` at `xfs_inode_item_pin` → durable dirent RESURRECTION.

### RESULT after fix (clean reboot, ./run.sh 8 tcp tcp_dlm_scaling)
- **P58=0, no `__xfs_trans_commit` corruption, no shutdown, no hung task on all 8 nodes** (was: 5 nodes trans_commit corruption). Resurrection ELIMINATED.
- Test STILL FAILs 1/8 — but now PURELY on SLOWNESS: tcp_dlm_scaling (`tests/tcp/tcp_dlm_scaling.sh`) PASS criterion is `ck "tds node within window" elapsed <= WINDOW(=60s)` per node. All 8 completed 150 rounds CLEAN but elapsed 73-119s (only test8=24s ≤60 → 1/8). So it's a PERFORMANCE test and the same DLM-acquire-starvation slowness as dir_reuse.

### NET: both remaining 8/tcp blockers are now ONE root — DLM acquire slowness
1/2/4 tcp PASS. 8/tcp = full-suite 16/17 (dir_reuse passes at 900s; tcp_dlm_scaling fails the 60s window). BOTH dir_reuse (slow rounds) and tcp_dlm_scaling (elapsed>60s) are the TCP-DLM `P36-RETRY` acquire churn / queue-vs-grant race. NEXT: fix that (see [[sess15run-FIXPLAN-8tcp-dlm-queue-vs-grant-race-and-acquire-churn]], [[sess15run-UNIFYING-both-8tcp-blockers-are-tcp-dlm-acquire-starvation]]). NOTE INFRA: 8-node load occasionally triggers iSCSI `conn error (1020)` → a node's test script wedges D-state → needs virsh reset. Use `setsid bash -c '... ./run.sh ...' </dev/null & disown` so the harness isn't orphaned by shell teardown.
