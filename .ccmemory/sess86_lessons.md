---
name: sess86_lessons
description: sess86 (ccloop) — FIXED rename_visibility ENOTDIR via d_revalidate reused-inode gen-check; cache_coherency passed=1→2; unlink blocked by deep AG/defer corruption shutdown
metadata: 
  node_type: memory
  type: project
  originSessionId: 954c0e4d-a7da-4e35-b24d-6c1f445b930c
---

# sess86 (2026-06-04, ccloop run 29df431e)

## MAJOR WIN: rename_visibility FIXED (cache_coherency passed=1 → passed=2)

**ROOT (PROVEN, RULE-4, NOT a dir-block lost-update — prior sessions mis-framed this):**
The cache_coherency criterion runs each sub-test as a SEPARATE `run_tests.sh --test`
invocation in a loop. Each invocation ends with `rm -rf .mxfs_test` and the next
starts by recreating `.mxfs_test/<subdir>` from node1. So cross_visibility runs FRESH
(cold cache → PASS) but rename/unlink/cwr each run on a WARM cache after node1
rm-rf'd + recreated the dir tree → **inode-number REUSE** (confirmed: dir CT got
inode 402900 before rm and 402900 again after mkdir; dir→dir, SAME number+type, only
generation/contents differ).

node3 & node4 (higher ids) got 20 `ENOTDIR` errors EACH at FILE-CREATE time
(`echo > .../rename_visibility/node3_before_1` → "Not a directory") because their
cached resolution of the recreated parent dir was a STALE prior incarnation. The
files were NEVER created → all their renames `mv: cannot stat` → verify sees node3/4's
whole set missing from ALL nodes. **NOT a write-side dir-block clobber.** Durable
(survives remount). Deterministic: RUN1-after-mount PASSES, RUN2+ FAIL identically.

**Why all prior defenses were BLIND:** the reuse is dir→dir (no ftype mismatch), so
the ftype-mismatch evictions (xfs_lookup INODE-REUSE-EVICT, d_revalidate
P-DREVAL-TYPEMISS) never fire. The INODE_FREE evict-ring fired 0× (delivery/timing
gap). d_revalidate only compared inode NUMBERS (same after reuse → returned valid) and
never consulted XFS_ISTALE_CAW / i_dlm_stale. So the stale dentry was served from
dcache and xfs_lookup's eviction never ran. (manual repro of stat on a reused dir
inode also WEDGED the node — D-state — confirming reload-path fragility.)

**FIX (Gemini RULE-5 design A+C), build `5D6A63D2`, in `pal/linux/xfs_super.c`
`mxfs_drevalidate`:**
- Part A: for a positive dentry, if `ip->i_dlm_stale || XFS_ISTALE_CAW` → return 0
  (INVALID) BEFORE the own-AG fast-path → forces xfs_lookup → its ISTALE-CAW evict
  (d_prune_aliases+irele+retry_iget→gen-gated recycle re-read). detector P-DREVAL-STALEFLAG.
- Part C: for a peer-AG positive DIRECTORY whose name still resolves to the SAME ino
  (ret would be 1), do a LOCKLESS FUA read of just on-disk di_gen via the EXISTING
  helper `mxfs_inode_disk_di_size(ip, NULL, &disk_gen)` (SCSI READ(16) FUA, di_gen at
  dinode off 0x5c; NO ILOCK/DLM → no deadlock). If `disk_gen != incore i_generation`
  → set i_dlm_stale + XFS_ISTALE_CAW, return 0. detector P-DREVAL-GENMISS.
- Gated to peer-AG DIRS only (own-AG dirs take affine fast-path; reg files excluded —
  sess51 FUA-on-every-empty-reg-lookup brought back 120s barrier stall).

**PROVEN:** rename_visibility RUN2 went 81/240-fail → **PASS 240/240 ~11s**; detectors
P-DREVAL-GENMISS(1×)+P-DREVAL-STALEFLAG(2-16×)+ISTALE-CAW-EVICT(10×) all fired. In the
full criterion: cross_visibility PASS + rename_visibility PASS. No D-state hang on a
CLEAN cluster (earlier hangs were reboot-orphan contamination, NOT the fix).

## REMAINING BLOCKER: unlink_visibility + cross_write_read (passed=2 failed=2)

unlink_visibility FAILs with FS SHUTDOWN (deep AG/defer corruption, the long-standing
stochastic bug — sess79-82 bnobt double-free family):
- test4: `xfs_trans_cancel` line 1060 ← `xfs_create+0x487` → "Corruption of in-memory
  data (0x8)" → shutdown (matches sess82 signature).
- test1: `xfs_corruption_error` ← `xfs_defer_finish_noroll` xfs_defer.c:721 → shutdown.
- Shutdown → EIO on barrier touch → all 4 barriers time out 120s (~490s total) →
  cross_write_read then can't run ("Not all nodes ready").
- When NOT shutdown (stochastic), unlink shows phantom-deletion (files remain after
  delete = stale readdir) — separate dir-block reader-staleness.

**OPEN QUESTION for next session:** is the d_revalidate evict churn EXPOSING/worsening
the create-path corruption, or is it the pre-existing stochastic bug? Was about to run
unlink_visibility ALONE on a fresh mount (Part C won't fire without rm-rf-recreate) to
isolate — if it still shuts down alone, my fix is innocent (deep bug). reset4 kept
FAILING after corruption shutdowns (nodes wedged) → had to `virsh destroy+start` all 4.

## INFRA (recurring, cost cycles this session)
- `/mnt/mxfs-src` NFS (192.168.120.1:/src/mxfs) drops off any node after a virsh
  reboot → node1 `mxfs_test.sh: No such file` → FALSE test result. RE-MOUNT on ALL
  nodes after EVERY virsh reboot: `mount -t nfs 192.168.120.1:/src/mxfs /mnt/mxfs-src`.
  Also `/src` (192.168.1.4:/src) for the .ko.
- The `.ko` is loaded over NFS from THIS host's /src/mxfs — `make modules` here is
  immediately visible to nodes; reset4 insmods it. But if old module is stuck
  "in use"/D-state, reset4 fails with "insmod: File exists" → `virsh destroy+start`.
- VMs under `LIBVIRT_DEFAULT_URI=qemu:///system` on this host. destroy+start to clear
  D-state/wedge. After corruption shutdown, nodes often need full virsh reboot.
- Deterministic rename repro: reset4 → `run_tests.sh --nodes 4 --test
  test_rename_visibility` TWICE; RUN2 is the reliable failure (was).
