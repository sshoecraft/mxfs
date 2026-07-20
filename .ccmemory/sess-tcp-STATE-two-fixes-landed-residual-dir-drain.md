---
name: sess-tcp-STATE-two-fixes-landed-residual-dir-drain
description: STATE (build 404BC55C): TWO real fixes landed (cc dir-evict + DLM double-grant gen-token). Residual = intermittent shared-dir readdir staleness (`dra…
metadata:
  type: project
---

## CURRENT BEST BUILD = `404BC55CA1AF4A73317C3DA` (KEEP). Two landed fixes:
1. cc dir-evict in-AIL discriminator ([[sess-tcp-cc-FIXED-dir-evict-inail-discriminator]]).
2. DLM double-grant gen-token ([[sess-tcp-DLM-double-grant-FIXED-gen-token]]).
Both VERIFIED: tcp_dlm_scaling no longer fails on double-grant (durable-wrong-content GONE);
crash_consistency reliable in-suite failure GONE. Achieved MULTIPLE clean 16/16 `./run.sh 2 tcp`
runs (2 consecutive in one batch).

## RESIDUAL (the ONLY thing between here and reliable 16/16): intermittent SHARED-DIR READDIR
STALENESS. Failing check on ~33-50% of runs (1-2 tests): **`<t> shared dir drained exp=0 got=1`**
(tcp_dlm_scaling, dlm_fairness) and cache_coherency cross_visibility. PROVEN reader-stale: after a
barrier (all nodes finished create+rename+rm in a shared dir), rank1's `ls`/readdir shows 1 leftover
dirent that is already removed on disk. Resolves on its own seconds later.

### ROOT: `i_dlm_dir_gen` (the dir-data-block coherency epoch) is advanced ONLY by
(a) a PEER's commit notify via the disklock EVICTION-RING, consumed by the heartbeat thread once
per `MXFS_DISKLOCK_HB_INTERVAL_MS` = **2000ms** (dlm/disklock.c hb loop), OR
(b) the reader's OWN slow-path DLM reacquire (xfs_mxfs_dlm.c:6925 `i_dlm_dir_gen++` on post-release
reacquire of a dir).
The stale window: the reader HOLDS the dir lock cached (fast-path, no reacquire → no gen bump) AND a
peer modified the dir AND the 2s heartbeat hasn't yet delivered the DIR_MODIFY → consumer_refresh
(xfs_lookup / xfs_file_readdir) sees gen unchanged → does NOT evict the stale dir data blocks →
readdir returns the stale dirent. Narrow timing race against the 2s heartbeat.

### TRIED + REVERTED: reducing MXFS_DISKLOCK_HB_INTERVAL_MS 2000→500 (+scale DEAD 31→124, LIVE
2→8 to hold the 62s/4s wall windows). Build 4886CEC9. **WEDGED THE CLUSTER**: run1 posix_multi 0/2
then mkfs_mxfs failed on runs 2-5 (FS/device stuck; had to virsh destroy+start test1/test2). The 4x
heartbeat I/O / timing change destabilized it (wedged EARLIER than the un-changed 5-run would). DO
NOT naively re-reduce the interval. A milder 2x, or DECOUPLING eviction-ring consumption from the
HB write+dead-detection cadence (read peers' rings every ~250ms but write HB + dead-count every 2s,
scaling the dead threshold for the faster read cadence), is the safer direction — UNTESTED.

### SAFER FIX IDEA (read-only, no lost-update risk): the sess36/58 reason the gen is NOT advanced
on fast-path is WRITER lost-update (RMW from stale base erases peer dirents). A READDIR is READ-ONLY
→ advancing its coherency / forcing a fresh dir-block fetch cannot lose data. So: on a MULTI-NODE
readdir where the node holds the dir lock cached (fast-path), force a coherent dir-data-block refresh
(e.g. set i_dlm_stale + reload, or bump local gen + evict) so readdir reflects the peer's latest —
WITHOUT touching the writer paths. CAUTION (RULE 0): do NOT force it on EVERY readdir (rsync_paired
does many — could slow + barrier-desync); scope to the cheap case. INSTRUMENT FIRST (RULE 4): catch
the stale `ls` (ungate P-EVICT-SKIP / P104-CONSUMER-REFRESH / P-DIR-SEQ in xfs_file_readdir +
xfs_mxfs_dlm.c) to confirm fast-path-hold-no-evict is the firing mechanism before patching.

## TEST METHOD: `./run.sh 2 tcp` (full suite ~5min, reliable). Per-run clean rate ~50-66% on
404BC55C. Back-to-back runs eventually WEDGE (deep stale-inode, separate issue) — virsh
destroy+start test1/test2 to recover; one run per fresh cluster is cleanest. criteria.json +
`./showstat.sh 2 tcp` = the third-party-verifiable record.
Fallbacks: 404BC55C (both fixes), 1ED7A5FD (cc only), 30D3C28E (neither).
