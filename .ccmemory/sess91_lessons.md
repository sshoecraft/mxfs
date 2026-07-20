---
name: sess91_lessons
description: sess91 — landed inode-cluster FUA-clobber guard (P91) AND found the stuck-XFS_ISTALE_CAW revalidation-thrash root of the remaining barrier-timeout failures
metadata: 
  node_type: memory
  type: project
  originSessionId: c6e57496-a565-405a-b1c1-acf5e69effa4
---

# sess91 (2026-06-05, ccloop)

## TWO fixes this session

### FIX 1 — inode-cluster FUA-over-logged clobber guard (sess90 confirmed root)
Build `BD2A94BA`. Helper `mxfs_buf_has_uncheckpointed_mods(bp)` (xfs_mxfs_dlm.c,
decl in xfs_mxfs_dlm.h): true if pinned / non-empty b_li_list / has BLI / DIRTY /
IN_AIL / delwri. Guards 3 sites that previously cleared XBF_DONE / FUA-re-read
unconditionally and clobbered this node's logged-but-uncheckpointed mods:
1. `xfs_iget_cache_miss` cluster-invalidate (xfs_icache.c ~L1159) — the PROVEN
   daddr=128 clobber site (sess90 P90 FIRED 7×). Now skips stale when in-core
   authoritative → P91-CLUSTER-PROTECT.
2. `xfs_iget_recycle` cluster-invalidate (xfs_icache.c ~L411).
3. `mxfs_buf_read_fua` backstop (pal/linux/xfs_buf.c ~L1536): if pinned/logged,
   SKIP the SCSI read, keep in-core, xfs_buf_ioend+return 0 → P91-FUA-SKIP-LOGGED.
VERIFIED working: P91-FUA-SKIP-LOGGED 12×, P91-CLUSTER-PROTECT 1×, ZERO
P90-FUA-OVER-LOGGED, no shutdowns/corruption. rename_visibility now PASS. KEEP.
NOTE: inode alloc is node-affine per AG, so a peer never allocates into a cluster
we have logged changes in → skipping the invalidate when in-core-authoritative is
safe (won't reintroduce sess38 peer-create-invisible).

### FIX 2 — stuck XFS_ISTALE_CAW → revalidation thrash (the barrier-timeout ROOT)
Build `EDA54DB1` (built, NOT yet deployed/verified at relay). cache_coherency
still passed=2 failed=2 after FIX1: unlink_visibility (node4 30 fails, 138s) +
cross_write_read (empty content + "Is a directory" + lost dirent, 124s). BOTH are
~120s = BARRIER TIMEOUTS, not the inode-cluster clobber.

DECISIVE PROBE `P91-STALEFLAG-DISK` (FUA disk di_mode/di_gen at d_revalidate
stale-flag branch, pal/linux/xfs_super.c ~L1885) showed on node4, 291×:
`ino=8388757 incore_mode=040755 incore_gen=20912466 disk_mode=040755
disk_gen=20912466 istale_caw=1 dlm_stale=1 name=.mxfs_barriers` — the inode is a
PERFECTLY VALID directory, disk and in-core AGREE EXACTLY (mode AND gen), YET
flagged stale → d_revalidate returns INVALID(0) on EVERY call → path-walk into the
live shared barrier dir thrashes → 120s timeouts.

ROOT: eviction-ring INODE_FREE handler (`mxfs_dlm_evict_inode_cb`,
xfs_mxfs_dlm.c:4490) sets `XFS_ISTALE_CAW | i_dlm_stale` when a peer frees an inode
number, but **XFS_ISTALE_CAW has NO clear site anywhere in the tree** (grep
confirmed 0 `xfs_iflags_clear(...ISTALE_CAW)`). After the number is legitimately
reallocated to the current incarnation (e.g. .mxfs_barriers recreated across the
criterion's per-subtest `rm -rf .mxfs_test`), the flag persists FOREVER. i_dlm_stale
IS cleared in many spots but the d_revalidate branch is `i_dlm_stale || ISTALE_CAW`
so the stuck CAW flag alone keeps it failing. (DIR_MODIFY ring path correctly bumps
i_dlm_dir_gen only, does NOT set CAW — not the culprit.)

FIX (xfs_super.c stale-flag branch): FUA-read disk di_mode/di_gen (lockless, no
ILOCK/DLM). If disk MATCHES incore (same di_mode AND di_gen → genuinely current,
not a stale reuse): CLEAR i_dlm_stale + xfs_iflags_clear(ISTALE_CAW), return VALID(1)
— the missing clear site that breaks the loop. If disk DIFFERS (real free/realloc):
keep flags, return INVALID(0) → evict + re-iget (original intent). Safe: gen is
bumped per-alloc so same-gen == same incarnation.

## FIX2 v1 (EDA54DB1) REGRESSED rename — REPLACED by v2 (ECDE1FC5, NOT yet verified)
EDA54DB1 cleared the stuck flag IN d_revalidate (return VALID on gen-match). This
REGRESSED rename_visibility 0→40 fails: clearing i_dlm_stale + returning 1 removed
the dir-CONTENT re-read trigger (a dir's inode gen is UNCHANGED across a rename; only
its dir BLOCKS change) → peer's rename invisible ("New name exists: file not found",
actual=''). VERIFIED firing correctly though: P91-STALEFLAG-DISK ret=1 15× / ret=0 3×,
no shutdown — the flag-clear logic is sound, just in the WRONG PLACE.

ROOT of why flag never clears on the LIVE barrier dir: xfs_lookup ISTALE-CAW eviction
(xfs_inode.c ~L690) does d_prune_aliases+irele+retry but a heavily-referenced LIVE
shared dir (.mxfs_barriers) can't be reclaimed → re-iget cache-HITS same inode, flag
persists → 4 tries → falls through still-flagged. Comment claims "cleared on recycle
XFS_IRECLAIM_RESET_FLAGS" but recycle never runs for the live inode + grep shows NO
xfs_iflags_clear(ISTALE_CAW) anywhere.

FIX2 v2 (build `ECDE1FC5`, built NOT deployed): revert d_revalidate to original
(return 0 when flagged — preserves sess86 rename/unlink). Move the clear to xfs_lookup
ISTALE-CAW block (xfs_inode.c ~L690): FUA-read disk di_mode/di_gen FIRST; if MATCHES
incore (current incarnation = false positive) → clear i_dlm_stale + xfs_iflags_clear
(ISTALE_CAW) + KEEP inode (dir lookup already gave fresh dirent so rename/unlink stays
visible); if DIFFERS → evict+re-iget as before. This is the correct place: AFTER the
fresh dir-block read, so dir-content coherency is preserved.

## NEXT (deploy + verify FIX2 v2)
1. `bash tests/reset4.sh 4` → confirm srcversion `ECDE1FC5` on all 4.
2. `./tests/criteria/cache_coherency.sh --nodes 4` → rename_visibility must stay PASS
   AND unlink/cross_write_read stop timing out. grep node `P91-CAW-FALSEPOS-CLEAR`
   (false-pos clears) vs `ISTALE-CAW-EVICT` (genuine reuse).
3. CAVEAT: a separate SLOWNESS exists — CAW EX-handoff latency on concurrent same-dir
   create (SESS50-STARVE fired; rename creation crawled 38/80 in 5min in one run).
   May be cluster-state CONTAMINATION from killed runs → do a CLEAN full reboot (virsh
   destroy+start ALL 4, not just one) before trusting a slow result. sess38 rule:
   reboot to clean slate before a criterion run.
4. If unlink/cwr STILL time out after v2 + clean reboot, the barrier-dir thrash was NOT
   the dominant cause — re-instrument the actual 120s stall (CAW EX starvation vs dir
   visibility) per sess49/sess50.

## INFRA gotchas (sess91)
- test2 module wedged refcnt=2 after reset (rmmod ERROR in use) → `sudo virsh -c
  qemu:///system destroy test2 && start test2` (VMs are LOCAL under system URI;
  default/session URI shows them shut-off = WRONG).
- After a node reboot, NFS /mnt/mxfs-src is GONE. Re-export on HOST then mount:
  host had a fsid=42 COLLISION between /src and /src/mxfs (NFSv4 → new mounts fail
  "No such file or directory"); fixed by `sudo exportfs -o ...,fsid=43 ... :/src`.
  Then on node: `mount -t nfs4 192.168.120.1:/src/mxfs /mnt/mxfs-src`.
- reset4.sh / cache_coherency auto-background under the 10-min foreground cap; they
  buffer stdout until completion (log empty mid-run). Use a `until [ -f done ]`
  background waiter. Mount point is /mnt/shared, dev /dev/sda. Slots t1=0 t2=3
  t3=1 t4=2; ~20 AGs.
