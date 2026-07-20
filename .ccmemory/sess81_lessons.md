---
name: sess81_lessons
description: "sess81 (ccloop, 2026-06-04) — cache_coherency still passed=2 failed=2; FULLY TRACED the bnobt double-free SHUTDOWN (the ship blocker). AG3 touched by ONLY 2 nodes, CAW-DUP-SLOT=0 (concurrent-EX refuted again). disk_differs=0 = DURABLE on-disk corruption: a live inode owns a block the bnobt lists free. Added P81-DEXT probe (build D8F43418) to decide bnobt-lost-update vs in-core-extent-stale; manifestation is STOCHASTIC (alloc:2244 vs xfs_trans_cancel) so P81 didn't fire yet — re-run to catch alloc:2244."
metadata:
  node_type: memory
  type: project
  originSessionId: 138940aa-4e27-4669-9083-92212fb2ad17
---

# sess81 lessons (ccloop run 29df431e, 2026-06-04)

## Ship status: 15/16 criteria PASS; cache_coherency BLOCKS (passed=2 failed=2)
- cross_visibility PASS, rename_visibility PASS (sess80 DIR_MODIFY fix holds),
  **unlink_visibility FAIL**, **cross_write_read FAIL**.
- unlink_visibility two faces, run-to-run STOCHASTIC: (a) "rm: cannot remove
  nodeN_fileX: No such file or directory" — a node can't delete its OWN just-
  created file (dir-block lost-update, files vanished); (b) "No files remain
  after deletion actual=2" (phantom dirents). BOTH = shared-dir coherency.
- cross_write_read: reads a peer's small md5-hash file as BINARY GARBAGE
  (`expected='G<junk>'`) + occasional 123s write stall (barrier starvation).

## THE SHIP BLOCKER — bnobt double-free SHUTDOWN, fully traced this session
Isolated `unlink_visibility` (criterion-style, ~30s) DETERMINISTICALLY shuts down
a node. Two manifestations of the SAME underlying metadata inconsistency:
1. `Internal error ltbno + ltlen > bno at xfs_alloc.c:2244` in
   xfs_free_ag_extent ← xfs_inactive_truncate (during inode inactivation).
   P15 FREE-AG-EXTENT-FAIL-LEFT agno=3 bno=13 ltbno=10 ltlen=6 (block 13 is
   inside the free extent [10,16) → double-free). P47 verdict=
   **DISK-LIVE-same-gen=>A-lost-removal** (the inode IS live on disk, gen matches
   → NOT sess47's stale/reuse case). **P28 disk_differs=0** = the on-disk bnobt
   ALSO lists 13 free = DURABLE corruption on the platter.
2. `xfs_trans_cancel:1060/1061` from xfs_remove (unlink) cancelling a DIRTY
   transaction → shutdown. Different site, same root.

### Decisive new evidence (always-on P10/CAW markers, no rebuild)
- AG3 touched by ONLY test1(slot0) + test3(slot3); test2/test4 = 0 AG3 events.
- **CAW-DUP-SLOT=0** → concurrent-EX via different slots REFUTED (again; matches
  sess47/52 ex_pop=1). Timeline: test3 ACQ-FRESH → test3 **REL-INLINE-V55**
  (clean BAST drain, P75=0) → ~33s later test1 ACQ-FRESH → 4ms later crash.
- ⇒ **test3 durably wrote a bnobt where block 13 is free while a live inode
  owns it, even though test3's release was FULLY DRAINED (drain_meta_buffers
  bwrite+blkdev_flush, P75=0).** So the corruption is WRITTEN by a node whose
  release path is clean. test1 just FUA-read the already-corrupt disk
  (disk_differs=0) and double-freed.

### Why local-gen can't be the whole story (mechanism understood)
- `mxfs_ag_meta_invalidate_stale` (xfs_mxfs_dlm.c ~L3080): on read, if cached
  buf `b_mxfs_ag_gen >= pag_dlm_meta_gen` → serve cached (treated fresh); else
  if clean → invalidate+FUA re-read; else (pinned/in_ail) → PROTECT (assume
  "this-node-ahead"). Gated on pag_dlm_meta_gen (bumped on FRESH/cached-reacq
  only — sess80: STUCK at 1 ⇒ AG held nested/continuous, few fresh acquires).
- sess44 P94 PROVED: with ALL caching eliminated on read (fua_always) AND write
  (FUA-write-through) the clobber STILL persists ⇒ NOT a medium read-vs-destage
  nor write-persistence bug. Leading unchased suspect (sess44, "P95"): a stale
  IN-CORE bnobt served as an XBF_DONE cache-HIT (no I/O) because its gen-check
  uses the wrong AG association OR the "in_ail = always this-node-ahead, PROTECT"
  assumption is FALSE across a peer handoff.

## What I built this session (build D8F43418, DEPLOYED, builds clean rc=0)
- New helper `mxfs_dbg_disk_di_first_dext(mp, ino, *sb0,*len0,*off0,*ndext,*fmt)`
  (xfs_mxfs_dlm.c, after mxfs_dbg_disk_di_mode): FUA-reads the ON-DISK dinode and
  decodes its DATA-fork first extent (uses XFS_DFORK_DPTR + xfs_bmbt_disk_get_all;
  added `#include "libxfs/xfs_bmap_btree.h"`). EXPORT_SYMBOL'd.
- **P81-DEXT** probe at the alloc:2244 P47 site (xfs_alloc.c): compares the
  freed fsbno (XFS_AGB_TO_FSB(agno,bno)) against the inode's ON-DISK extent map.
  verdict `DISK-INODE-OWNS-FREED=>bnobt-lost-update` vs
  `DISK-INODE-DIFFERS=>incore-extent-stale`. **This is THE decisive datum** to
  pick the fix direction (free-space-tree coherency vs inode-extent coherency).
- NOTE: P81 did NOT fire yet — this run's crash took the xfs_trans_cancel path
  (not alloc:2244). Manifestation is stochastic. **NEXT: re-run unlink 1-3× to
  catch the alloc:2244 path and read P81-DEXT.** I started broadening P81 to the
  always-on P29 bunmapi-entry site (xfs_bmap.c ~L5235) but the Edit whitespace
  didn't match at the relay boundary — finish that edit (anchor on the
  `(unsigned long long)p29_irec.br_blockcount);` + closing braces) so P81 fires
  on EVERY inactivation regardless of crash signature.

## Cluster/infra mechanics learned this session (IMPORTANT — saves a cycle)
- After a criterion run the cluster is torn down (rmmod'd). reset4 redeploys.
- **The nodes NFS-mount the test harness at /mnt/mxfs-src from THIS host
  (192.168.120.1:/src/mxfs). That export is NOT in /etc/exports and gets LOST on
  host reboot.** Re-add: `sudo exportfs -o rw,sync,no_subtree_check,no_root_squash,fsid=42 192.168.120.0/24:/src`
  then on each node `mount -t nfs 192.168.120.1:/src/mxfs /mnt/mxfs-src`. Without
  it, run_tests fails rc=127 (`/mnt/mxfs-src/tests/mxfs_test.sh: No such file`).
  reset4 does NOT mount /mnt/mxfs-src — do it manually after every reset4.
- Run ONE sub-test criterion-style:
  `MXFS_NODE_OFFSET=16 bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`
- A bnobt shutdown wedges the node's mxfs in EIO (`ls: Input/output error`, in
  /proc/mounts but dead); rmmod fails "Resource temporarily unavailable" (refcount
  pinned). RECOVERY = reboot the VM: `ssh <node> "reboot -f"`, wait ~55s, then
  reset4. (test1 needed this once this session.)
- run_tests stdout is buffered when the harness backgrounds it (>120s); harvest
  dmesg directly for detectors. Clear dmesg BEFORE the run only if you don't need
  the prior crash; better to NOT clear and filter by timestamp.

## Next session plan
1. reset4 + remount /mnt/mxfs-src on all nodes; re-run isolated unlink_visibility
   1-3× until the alloc:2244 path fires; read **P81-DEXT verdict**.
2. If `bnobt-lost-update`: fix free-space-tree coherency (the PROTECT-in_ail /
   wrong-AG-association suspect, OR Gemini's shared on-disk AGF epoch — but note
   epoch alone can't fix read-vs-destage; the BAST release already drains clean).
3. If `incore-extent-stale`: the inode's in-core data-fork is stale vs disk
   (peer reallocated the inode #); fix inode-extent reload on the unlink/inactive
   path (extend sess48 reused-inode evict to re-read the data fork).
4. Then cross_write_read garbage-read (peer's small file read as binary junk =
   reader-side data-page/extent staleness, sess46 family).

State head = sess81. See [[sess80_lessons]] [[sess79_lessons]] [[sess47_lessons]].
