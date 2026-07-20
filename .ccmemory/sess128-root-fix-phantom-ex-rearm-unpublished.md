---
name: sess128-root-fix-phantom-ex-rearm-unpublished
description: sess128 ROOT FIX (build CA701441): cache_coherency 4/4 PASS. Phantom-EX on reused-inode create — rearm deferred-publish at cache-hit IGET_CREATE.
metadata:
  type: project
---

# sess128 — cache_coherency GREEN (4/4) — phantom-EX root fix (build `CA7014410F4710CF9D54D6E`)

## The proven chain (RULE 4, one probe build `0391EDE5`)
`test_cross_write_read` failed because readers saw a just-created md5 file as EMPTY.

**Root**: a local CREATE satisfied from the inode CACHE (recycle of an IRECLAIMABLE freed incarnation / `mxfs_dlm_reset_inode_for_create` / freed mode==0 hit) keeps the PRIOR incarnation's DLM fields: `i_dlm_mode=EX`, `i_dlm_unpublished=false`. But `xfs_inactive` released the prior incarnation's ON-DISK slot (`mxfs_v5_dlm_inode_unlock` at its `out:` label) without touching in-core state. So `mxfs_dlm_publish_inode` (xfs_create:1509) fast-bails on the clear unpub flag → the creator runs on a **PHANTOM in-core EX with NO on-disk slot** → a peer's acquire of the reused number grants CLEAN (empty slot, NO BAST) → creator never flushes the new dinode → peer's reload adopts the reused incarnation at its not-yet-durable `disk_size=0` (P103-RELOAD-REUSE-ADOPT) → cat returns empty.

**Decisive probes** (kept in tree):
- `P128-PUBLISH-BAIL` (xfs_mxfs_dlm.c, publish_inode fast-bail) — fired on writer node1 for ino 138/139 with dlm_mode=5(EX), correlating exactly with readers' P103 size=0 adopts of the same inos.
- `P128-INACT-EXREL` (xfs_inode.c, xfs_inactive out:) — shows the slot release that creates the phantom.

## THE FIX
`mxfs_dlm_rearm_unpublished(ip)` (xfs_mxfs_dlm.c, near grant_local_new; decl in xfs_mxfs_dlm.h): restores the brand-new-inode invariant (creator-exclusive local EX, fresh EX epoch, linked on unpub list) WITHOUT touching holder counts. Called from `xfs_iget` (xfs_icache.c) on every **cache-hit `XFS_IGET_CREATE`** (multi-node). xfs_create's publish-on-create then acquires the real slot; peers' acquires BAST the creator whose release path flushes the new dinode durable. Probe `P128-REARM-UNPUB` (fired 11× on node1; PUBLISH-BAIL count dropped to 0).

## Result
`cache_coherency.sh --nodes 4`: **PASS 4/4** (cross_visibility, rename_visibility, unlink_visibility, cross_write_read). Was the last failing entry in `.criteria_results.json`'s 12 recorded criteria.

## Remaining for the marker (ship gate)
Full `verify_ship.sh` end-to-end single run. NOTE: `.criteria_results.json` has NO entries for posix_semantics (1+16 nodes), strong_consistency, zero_silent_loss, crash_consistency, fence_during_write, scaling_curve (16 nodes) — these have never been recorded and must run. 16-node criteria need test1–test16 (lib.sh DEFAULT_NODES = test1-16). Deploy build `CA701441` everywhere first.

Related: [[sess127-root-fix-durable-before-visible-new-inode-iget-coord]] [[sess44_lessons]] [[criteria-ship-gate]]
