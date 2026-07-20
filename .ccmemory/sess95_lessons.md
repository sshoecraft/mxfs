---
name: sess95_lessons
description: sess95 — cache_coherency 1/4→3/4. P95 same-type reload (rename PASS) + P95 typeflip reload (uv_delete PASS). Last blocker: uv_verify typeflip thrash…
metadata:
  type: project
---

# sess95 (2026-06-05, ccloop run 29df431e)

## WINS this session (cache_coherency passed=1 → passed=3 of 4)
Two in-place-reload fixes for REFERENCED inodes that EVICTION can't fix
(xfs_irele won't reclaim a referenced inode; retry_iget cache-HITs the same
stale inode — proven `P-EVICT-RESULT inew=0 tries=5`). Eviction → in-place
`mxfs_dlm_reload_inode` (invalidates cluster buffer + dir DATA blocks; works on
referenced inodes; trylock+bail, no deadlock).

1. **P95-SAMETYPE-RELOAD** (xfs/xfs_inode.c, xfs_lookup ISTALE_CAW disk-DIFFERS
   branch): same-type (dir→dir) gen-stale reused inode. FIXED rename_visibility
   (node3 had stale rename dir ino, saw none of peers' entries). VERIFIED:
   build 6B77CE94 → rename PASS, cwr PASS, passed=3/4.
2. **P95-TYPEFLIP-RELOAD** (xfs/xfs_inode.c, after the ftype-mismatch
   INODE-REUSE-EVICT block): type-flip reuse (file→dir) where eviction failed
   because referenced. FIXED the uv_delete barrier (ino 136 reused file→dir;
   node2/3/4 kept stale FILE → couldn't signal → barrier 0/4 → 146s timeout).
   Build 66A40A3D (CURRENT, builds clean, both probes present).

Gemini consult (RULE 5) confirmed approach + the KEY catch: reloading the dinode
alone is insufficient — OLD dir DATA blocks must also be XBF_DONE-cleared under
fua_disable=1 (mxfs_dlm_reload_inode already does this, sess34 H18 walk).

## LAST BLOCKER (unlink_visibility): uv_verify typeflip RELOAD THRASH — NOT YET FIXED
P95-TYPEFLIP-RELOAD fired 125× on test1 for ino=14680194 (uv_verify barrier dir),
incore_ftype=1(file) dirent_ftype=2(dir), tries=6, ~1/sec = barrier_wait poll.
The reload is CALLED but does NOT stick. Root, PROVEN:
`RELOAD-TYPEFLIP-STALE-SKIP ino=14680194 incore_mode=0100644 disk_mode=040755
incore_gen=3551188422 disk_gen=1573697881 — keeping authoritative in-core inode
(type-flip w/o newer gen = stale/corrupt disk)`.
The sess90 typeflip-stale guard (xfs/xfs_mxfs_dlm.c ~line 2013) rejects the flip
because `disk_gen(1.57e9) <= incore_gen(3.55e9)`. BUT XFS generations are RANDOM
(not monotonic), so disk_gen<incore_gen is NOT a reliable "stale" signal. Here the
DIRENT (ftype=2 DIR, just read from the parent block) AGREES with the disk inode
(mode 040755 DIR) — that is GROUND TRUTH that a genuine type-flip happened. The
guard wrongly treats it as a torn read → node1 keeps stale FILE → "touch
uv_verify/node1: Not a directory" → uv_verify barrier 0/4 → 120s timeout → FAIL.

### NEXT STEP (implement, was mid-edit at relay boundary — header not yet touched)
Thread the authoritative `dirent_ftype` into mxfs_dlm_reload_inode so the typeflip
guard is BYPASSED when the disk inode's type matches the dirent ftype (disk+dirent
agree = genuine flip; only reject when they DISAGREE = the sess90 torn/stale-cluster
case which has SAME gen and the dirent still shows the OLD type).
Plan:
1. xfs/xfs_mxfs_dlm.h:130 — change `void mxfs_dlm_reload_inode(struct xfs_inode *ip)`
   to add `uint8_t expect_ftype` param (XFS_DIR3_FT_UNKNOWN=0 = normal).
2. xfs/xfs_mxfs_dlm.c:1861 def — add param; in the typeflip-stale-skip guard
   (~2013) add `&& !(expect_ftype != XFS_DIR3_FT_UNKNOWN && xfs_mode_to_ftype(
   be16_to_cpu(dip->di_mode)) == expect_ftype)` so it does NOT skip when disk type
   matches the dirent.
3. Update ALL callers to pass XFS_DIR3_FT_UNKNOWN: xfs_icache.c:866,876,930,943;
   xfs_mxfs_dlm.c:3028; xfs_inode.c P95-SAMETYPE site (can pass dirent_ftype).
   The xfs_inode.c P95-TYPEFLIP site passes `dirent_ftype`.
4. `make clean && make modules` (spans .c+.h). Verify xfs_mode_to_ftype available
   in xfs_mxfs_dlm.c (it's a libxfs helper — should be).
5. Redeploy (clean reboot all 4 + reset4) + run cache_coherency; expect uv_verify
   thrash gone → unlink_visibility PASS → passed=4/4 → then run full verify_ship.sh.

ALSO watch: the SAME guard may reject the SAME-TYPE case too? No — same-type goes
through a different branch (no typeflip guard). And re-confirm rename/cwr stay PASS.

## Build IDs
- 6B77CE94 = +P95 same-type reload (rename/cwr PASS). 
- 66A40A3D = +P95 typeflip reload (uv_delete PASS; uv_verify thrashes). CURRENT.
- Earlier: 3CD1C5F9 = dialloc P-DIAG instrumentation (7 probes, dialloc EFSCORRUPTED
  is INTERMITTENT, did not fire in sess95 runs).

## Note on EXIT=137
Last run got SIGKILLed (137) with empty log + an orphaned run_tests left running —
a harness/timeout artifact, NOT an FS crash (all 4 nodes stayed mounted, 0
shutdowns). Re-run cleanly. Kill orphans: `pkill -9 -f run_tests`.

## Infra (verified): clean reboot all4 (virsh destroy+start, 65s), `bash
tests/reset4.sh 4`, verify srcversion on test1, run cache_coherency to /tmp + grep
EXIT=. Detail log path in RESULT reason=. Per-node asserts in
/home/steve/.mxfs/results/<ts>/test_<name>/nodeN.log. Nodes NFS-mount /src; built
mxfs.ko used directly. fua_disable=1 is module default (KEEP).
