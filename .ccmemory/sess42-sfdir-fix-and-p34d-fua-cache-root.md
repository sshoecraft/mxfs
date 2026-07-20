---
name: sess42-sfdir-fix-and-p34d-fua-cache-root
description: sess42: shortform-readdir fix VERIFIED (56453207); P34D FUA-vs-SCST-cache lost-update root PROVEN, fix built 863173A4 UNVERIFIED; cluster needs SCST-…
metadata:
  type: project
---

# sess42 (ccloop 14d31183) — two fixes for posix_semantics_multi16 (last gate FAIL)

Gate: 18/19 PASS; only `posix_semantics_multi16` FAILs (`elapsed>600s`). Continues [[sess41-shortform-dir-evict-gap-root]].

## FIX 1 — shortform-dir readdir coherency (build `564532078173F7EB568677F`, VERIFIED, KEEP)
Implemented sess41's design:
- `xfs/xfs_inode.h`: new `MXFS_IF_DIR_RELOAD (1U<<20)`, added to `XFS_IRECLAIM_RESET_FLAGS`.
- `xfs/xfs_mxfs_dlm.c` `mxfs_dlm_evict_inode_cb` DIR_MODIFY branch: drops the `i_dlm_dir_gen!=0` gate; for live dirs bumps gen (if armed) AND sets `MXFS_IF_DIR_RELOAD` when `if_format==LOCAL` (spinlock-only). Log now `EVICT-RING-DIRMOD ... sf_reload=`.
- `xfs/xfs_dir2_readdir.c` `xfs_readdir`: before the format check, if multi-node + flag set → `i_dlm_stale=true; mxfs_dlm_reload_inode(dp, FT_UNKNOWN)`; re-arms flag if reload BAILed (i_dlm_stale still set). Event-driven, no polling. Needs `#include "xfs_mxfs_dlm.h"` + `"../dlm/v5_mount.h"`.
VERIFIED: standalone test_concurrent_touch 5/5 PASS, all 16 nodes 50-54s, zero barrier timeouts, `sf_reload=1` firing in dmesg. cross_visibility 38s PASS; dir_stress all nodes ~33s PASS.
GOTCHA: `make clean` removes tools/ binaries → `make tools` too, else reset4 mkfs silently fails (sess18 lesson re-hit).

## FIX 2 — P34D platter-adopt lost-update (build `863173A494A37C7D093F817`, built+deployed, **NOT yet verified**)
In-suite, the remaining 600s blowout = almost every test's first barrier loses EXACTLY ONE node's signal **durably**: victim's `touch` rc=0, own readdir=1 immediately after (instrumented), 120s later own_lookup=0 own_readdir=0 and the file never exists on disk for anyone. Same dir_ino on victim+peers (mkdir-race REFUTED). P-SFDIR-REVERT=0 (count-revert refuted). Smoking gun: victim node had `P91-RELOAD-PROTECT`=13 + `P34D-RELOAD-FRESHSRC`=13.
**ROOT (proven)**: with `fua_disable=1` (running default) the cluster's coherence point is the SCST target write CACHE; completed buffer writes are plain-read-visible but NOT yet on the platter. `mxfs_dlm_reload_inode`'s kept_protected branch (P34D, xfs_mxfs_dlm.c ~4102) FUA-read the PLATTER and adopted ANY valid image unconditionally → adopted an image OLDER than the victim's own last flush → in-core fork reverted, own dirent dropped, next RMW made loss durable cluster-wide.
**FIX**: P34D fresh-source read now uses `mxfs_pal_bdev_read_plain_bdev` when `mxfs_fua_disable` (else FUA as before). Log says `src=plain|fua`.
NOTE: other `mxfs_pal_scsi_read_fua_bdev` callers (d_revalidate gen check, s91_dmode lookup reads, P95 paths) have the same FUA-vs-cache hazard — NOT yet touched (RULE 4 scope); revisit if one-node staleness verdicts persist.

## Diagnostics added (KEEP, in tree)
- `tests/lib/cluster.sh` barrier_signal/barrier_wait: log `dir_ino lookup= readdir=` at signal + at timeout (discriminates incarnation-split vs lost-update in one run).
- `tests/criteria/bail_storm_watch.sh`: host-side watcher; on "DLM reload BAIL" storm dumps D-state stacks. Finding: storms had NO D-state holder (hot i_lock from DLM ping-pong, not a wedge).
- `tests/criteria/posix_phase_timing.sh` (sess41) is the per-test timing probe: `POSIX_PHASE=cluster timeout 580 bash tests/criteria/posix_phase_timing.sh --nodes 16`.

## CLUSTER STATE AT HANDOFF (must recover first!)
Stale SCSI PR (WE-RO holder 0x4aa3fe4b, all VMs share one IQN, distinguished by ISID) wedged the LUN: mkfs/dd got EBADE "Invalid exchange"; sg_persist preempt/clear/release ALL returned rc=24 from a freshly registered node — SCST PR state desynced. Recovery in progress at relay: all 16 VMs `virsh destroy`ed, `systemctl restart scst` on clyde was MID-RESTART (state "deactivating"). NEXT SESSION: (1) verify `systemctl is-active scst` + `ls /sys/kernel/scst_tgt/devices/` shows disk1; (2) `bash scripts/cluster_reset_n.sh 16` (boots VMs + prep; PREP_FAIL on insmod right after boot can happen — NFS race; reset4 fixes it); (3) `bash tests/reset4.sh 16`; (4) confirm srcversion `863173A494A37C7D093F817` on all nodes.

## VERIFY plan for FIX 2
`POSIX_PHASE=cluster timeout 580 bash tests/criteria/posix_phase_timing.sh --nodes 16` → expect concurrent_mkdir/touch/write deltas ~45-60s (no 120s timeouts), no `barrier_signal ... readdir=0` warns, P34D log shows src=plain. Then full `bash tests/criteria/posix_semantics.sh --nodes 16` under 600s.
## Budget watch even with zero timeouts
Suite = 14 cluster tests with ~12s inter-test harness gaps + ~80s mount + 16s single phase. Healthy estimate ≈ 450-550s — borderline vs 600. If still over: the ~12s/test gap (result collection/cleanup) is the next target, NOT widening the timeout (RULE 0).
