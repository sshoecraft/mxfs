---
name: sess-tcp-heartbeat-reduction-insufficient
description: Heartbeat-interval reduction (DIR_MODIFY latency) is NOT the fix: 500ms WEDGES, 1000ms is stable but only ~1/3 clean (no real improvement). Reverted…
metadata:
  type: project
---

## Tried reducing MXFS_DISKLOCK_HB_INTERVAL_MS to shrink the DIR_MODIFY notification
latency (the residual shared-dir readdir-staleness root, see
[[sess-tcp-STATE-two-fixes-landed-residual-dir-drain]]). BOTH variants scaled DEAD/LIVE
thresholds to hold the 62s/4s wall windows.

- **500ms (4x), build 4886CEC9**: WEDGED — run1 posix_multi 0/2 then mkfs_mxfs failed
  runs 2-5 (cluster stuck, virsh destroy+start to recover). The 4x FUA-write + 4x
  eviction-dispatch load under posix_multi's heavy churn tips into a stall→barrier-desync
  →wedge. DO NOT use.
- **1000ms (2x), build BEA13E27**: STABLE (no wedge) but clean rate ~1/3 (iter1 fail
  crash_consistency, iter2 CLEAN, iter3 fail crash_consistency+tcp_dlm_scaling) — NO real
  improvement over 2000ms's 1/4. Faster polling does not close the race because cc sleeps
  ~1s and the drain checks read immediately after a barrier; a 1s window still races.

=> REVERTED to **404BC55C** (2000ms, both real fixes only). Heartbeat tuning is a dead end.

## CONCLUSION for next session: the residual is the dir-data-block coherency decoupling
from the inode DLM lock. Holding the dir inode PR does NOT refresh the separately-cached dir
DATA blocks (b_mxfs_dir_gen vs i_dlm_dir_gen). The gen advances only on (a) slow-path inode
reacquire (xfs_mxfs_dlm.c:6925) or (b) the 2s heartbeat DIR_MODIFY notify. Reasoning hits a
contradiction (a PR-holding reader "should" be coherent yet readdir is stale) — so RULE 4
INSTRUMENT FIRST: add an always-on (or mxfs.rddiag-gated) probe in xfs_file_readdir /
xfs_dir2_readdir capturing {i_dlm_mode, i_dlm_dir_gen, loaded_gen, evicted_gen, nentries,
whether consumer_refresh evicted, whether a BAST was pending} on the stale `ls`, then compare
to a fresh one. Likely findings to test: fast-path inode-PR-hold leaving stale data blocks
(gen not advanced); or a pending-but-unprocessed BAST at read time. Fix is read-only-safe
(readdir is read-only, no writer lost-update constraint) — force the dir DATA-block coherence
on the read path WITHOUT the broad cost (do NOT force-evict on every lookup component — the
root dir / parents are hit constantly; scope it). Build/repro: `./run.sh 2 tcp` (~5min);
crash_consistency / tcp_dlm_scaling-drain / dlm_fairness-drain reproduce the stale readdir at
~50-75% over a few runs.
