---
name: sess22-cleanslate-primary-blocker-torn-shortform-flush-shutdown
description: sess22: dir_reuse_coherency 2/tcp PRIMARY clean-slate blocker = FS SHUTDOWN from torn shortform dir flush during rm-rf reuse, NOT the leaf-hash hole.
metadata:
  type: project
---

## sess22 (ccloop 8ddb16a2) — clean-slate truth: the 90/91 leaf-hash hole was a WARM-cluster anomaly

Build 862A8487 (union-read leaf rebuild). Previous session reported 90/91 (1 leaf-hash entry missing round 15) on a **force_reset (rmmod)** cluster. On a **full virsh reboot clean slate** the SAME build fails far worse and DIFFERENTLY:
- rank1(test1) readdir=**0**/200 from round 2; rank2(test2) readdir=**101**/200 (sees only its own ~100 entries). 77/91 pass.

### PROVEN ROOT (RULE 4, exact dmesg)
The FS **shuts down during round-1's rm-rf teardown** of dir ino 131 (reported as round-2 failure because FS is already down):
```
P69-L2B ino=131 ... LEAF daddr=2095128 ... DATA daddr=120     # dir shrinking leaf->block during rm-rf
XFS (sda): Metadata corruption detected at xfs_dir2_sf_verify+0x273, inode 0x83(=131) data fork
  First 23 bytes: 01 00 00 00 00 80 00 00 00 ...               # shortform hdr count=1 i8count=0 parent=128, entry[0].namelen=0 (INVALID)
XFS (sda): Corruption of in-memory data (0x8) ... xfs_iflush_cluster (xfs_inode.c:5209). Shutting down filesystem.
P9-ICD-FAIL ino=131 last_rerr=-117                             # -117 = -EFSCORRUPTED
```
So: dir ino 131 is REUSED (round1 rm-rf → round2 mkdir). During rm-rf the dir down-converts leaf→block→shortform. **xfsaild flushes a TORN in-core shortform fork (count=1 but the single entry has namelen=0)** → `xfs_ifork_verify_local_data`→`xfs_dir2_sf_verify` fails (xfs_inode.c:4355) → `xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE)`.

Surrounding signals on test1: P62-RELOAD-FORK-SHRINK ino=131 post_release=1; repeated `DLM inode lock failed: ino=131 mode=5 rc=-35` (-35=-EDEADLK) for ino 131 + child inodes 1957/8/9 being ifree'd; a **P78-FMT-TORN-FIX storm** (~hundreds) on ino=131 in comm=xfsaild/sda (forces XFS_ILOG_DEXT each flush; ili_fields=0x1 CORE-only, in-core fmt=EXTENTS nx=3) — note the in-core if_format FLIPS between EXTENTS (P78) and LOCAL (sf_verify failure) across flushes = reuse race.

### Producer (suspect, UNCONFIRMED)
The torn shortform (count=1, zeroed entry) is in IN-CORE if_data being flushed. Candidate producers: (a) mxfs_dlm_reload_inode shortform delta re-apply (sess14 `mxfs_sf_merge`, xfs_mxfs_dlm.c ~6515) adopting/merging a torn image; (b) genuine torn commit from block→sf down-conversion under concurrency; (c) xfsaild racing a live conversion. NOT yet proven which.

### Strategy
1. PRIMARY: stop the shutdown. Either find+fix the producer, OR (defensive, definitely-correct) in xfs_iflush for a multi-node DIR, on local-data verify-fail do NOT shut down — skip cleanly (error=0 + XFS_ISTALE_CAW, like the P119/P17B skips at xfs_inode.c:4426/4470) so a known-invalid shortform is never written to the shared LUN and the authoritative image is re-read. Verify flush_out releases the AIL item (no xfsaild storm).
2. SECONDARY (leaf-hash hole, only visible once shutdown fixed): keep the coherent plain-bio union read; add C2 (derive ndb from data fork via xfs_bmap_last_offset, not stale leaf bestcount) + C4 (release-side rebuild gated on MXFS_IF_DIR_LEAF_STALE in bast_process before leaf destage). Do NOT switch the disk source to FUA — adversary proved FUA reads the STALE platter; plain bio hits the coherent peer-visible SCST write-back cache (fua_disable=1, write-through backstore).

### Test/infra
- ALWAYS full virsh reboot before trusting a result: `bash tests/reboot_cluster.sh 2` then `MXFS_TEST_ENV="DRC_ROUNDS=15" timeout 460 ./run.sh 2 tcp dir_reuse_coherency`. force_reset (rmmod) gives misleading warm results.
- run.sh prep does mkfs; needs device unmounted (tests/force_reset.sh handles a leftover mount).
</body>
