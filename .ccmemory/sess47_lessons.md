---
name: sess47_lessons
description: sess47 2026-06-02 — FIXED the cluster-crashing AG bnobt double-free (stale-inode inactivation); env recovery; remaining cache_coherency = ENOTDIR dir-visibility.
metadata: 
  node_type: memory
  type: project
  originSessionId: 29f421c9-1a8b-4f81-a9e6-eece13e85ce0
---

# sess47 (2026-06-02)

## ✅ MAJOR WIN: the AG bnobt double-free corruption is FIXED (build `29977E5D`)
The 7-session "ltbno+ltlen>bno" / AG-free-space corruption that CRASHED the cluster
under 4-node concurrent unlink (→ shutdown → cache_coherency FAIL) is fixed.

**It was NOT any DLM-side theory.** RULE-4 instrumentation REFUTED (don't re-chase):
- find_slot claim-race / duplicate slot per AG / transient concurrent-EX — a post-claim
  full-probe-chain dup detector (`CAW-DUP-SLOT`, dlm/dlm_caw.c) fired 0×.
- release-before-drain (writing bnobt without the AG lock) — a P88 `ag_held` check
  (pal/linux/xfs_buf.c) showed ag_held=1 at EVERY bnobt write.
- EX-acquire walk staling an IN_AIL committed-ahead-of-disk bnobt buffer — guards added
  at xfs_mxfs_dlm.c 4679/4725 (`P47-INVAL-SKIP-INAIL`) AND the main path P79 both 0×.
- (sess44) bad FUA reads (P92), CAW DLM split (P87) — still hold.

**ROOT (proven via `P47-INACT` detector at xfs_alloc.c:2244 + the corruption call
stack `Comm: rm` → xfs_fs_destroy_inode → xfs_inactive → xfs_inactive_truncate →
xfs_itruncate_extents → xfs_bunmapi → __xfs_free_extent):** a node runs DESTRUCTIVE
INACTIVATION on a STALE cached inode and double-frees its blocks.  Two sub-cases:
- B1 (`disk_di_mode==0`): a PEER unlinked+freed the inode; this node had instantiated it
  GRANT-LESS (readdir/lookup/stat of the shared dir during cross-visibility checks), so
  the peer's free never BAST'd it; the stale in-core inode kept its extent map.
- B2 (gen-mismatch): the inode number was REUSED — disk has a DIFFERENT incarnation
  (di_mode!=0 but disk di_gen != in-core i_generation); this node holds the stale prior
  incarnation whose extent map points at block 9.

**THE FIX** (xfs/xfs_inode.c, top of `xfs_inactive`, after `mp=ip->i_mount`): multi-node
+ nlink==0 → FUA-read the inode's on-disk dinode; if `di_mode==0` OR
`di_gen != VFS_I(ip)->i_generation`, SKIP the destructive truncate/ifree (`goto out`),
just reclaim in-core.  Logs `INACT-SKIP-STALE`.  Helper `mxfs_dbg_disk_di_mode(mp,ino,
&gen)` in xfs_mxfs_dlm.c FUA-reads di_mode(off 2) + di_gen(off **0x5C**).  Dinode
offsets: di_size=0x38, di_gen=0x5C, di_next_unlinked=0x60 (0xFFFFFFFF=NULLAGINO — an
earlier wrong gen read used 0x60).

**B2 must be UNGATED.** Tried gating gen-mismatch on grant-less (i_dlm_mode==NL, build
B482DC76) → corruption RETURNED (skip_genmismatch=0) → the corrupting reused inode is
GRANT-HELD.  So the gen-mismatch skip fires regardless of grant state.

⚠️ OPEN RISK (verify next): ungated B2 could FALSE-POSITIVE on a node's OWN
reused-but-not-yet-flushed inode (in-core gen Gy, disk still old Gx → false mismatch →
wrongly skip → leak).  gen is random (not monotonic) so it can't tell "stale old peer
incarnation" (skip) from "my newer not-flushed incarnation" (proceed).  chk_mxfs after a
run: SB icount=128(2 chunks) vs inobt 320(5 chunks) — MOSTLY pre-existing multi-node
SB-lazy-counter (SB UNDERcounts; a guard leak would OVERcount inobt) but inobt-vs-SB
allocated diff ~5 might be minor leak.  Better discriminator needed (flush+re-read, or
track did-WE-unlink vs observed-nlink0-via-reload).

## ⛔ REMAINING cache_coherency blocker = ENOTDIR dir-visibility (NOT corruption)
After the fix, `test_unlink_visibility` asserts all PASS and ltbno=0, but it's SLOW and
intermittently FAILS on cross-node DIRECTORY VISIBILITY:
- Barrier `mkdir -p .mxfs_barriers/<name>` + `touch <name>/nodeN` → "touch: cannot touch
  '.../uv_verify/node1': Not a directory" (ENOTDIR) → barrier never reaches 4/4 → 120s
  timeout per barrier → criterion slow (4 barriers × 120s).  Also "node1 sees 117/120
  files", "node4 can't rm its own file (dirent already gone)".
- ROOT (same family as the corruption): a node's LOOKUP of a name resolves to a STALE
  cached inode — barrier dir names are REUSED across test iterations, so a cached
  dentry/inode points at a freed/reused inode (wrong type S_IFREG vs S_IFDIR → ENOTDIR),
  OR within-iteration inode reuse.  MXFS has d_revalidate DISABLED (sess38, destabilizing)
  so stale dentries persist.  Fix locus = xfs_iget_cache_hit gen-check + reload on reuse
  (perf-sensitive — sess46 hit the per-lookup-FUA wall), or dcache invalidation.  This is
  the genuine remaining cache_coherency work.

## ENV recovery (the dev host was rebooted — it WORKED, cleared sess46's stuck CAW)
After a host reboot: (1) `sudo iscsiadm -m node -T iqn.2026-05.local.mxfs:disk1 -p
127.0.0.1:3260 --login` (+disk2); (2) VM disks now use STABLE by-path
`/dev/disk/by-path/ip-127.0.0.1:3260-iscsi-...disk1-lun-0` (sess47 fixed all 4 VM XMLs
off `/dev/sdc` which renames → "Cannot access storage file /dev/sdc"); (3) `cp
/home/steve/.mxfs/pass /tmp/.mxfs_pass` (reboot wipes /tmp); (4) `virsh start
test1..test4`, wait ~90s.  SCST reloads clean from /etc/scst.conf on boot.

## Detectors in build 29977E5D (gated/ratelimited, keep)
P47-INACT (xfs_alloc.c:2244, proved B), INACT-SKIP-STALE (xfs_inactive, the fix log),
P47-INVAL-SKIP-INAIL (4679/4725, harmless, fired 0×), CAW-DUP-SLOT (dlm_caw.c, 0×),
P88 ag_held (xfs_buf.c).  mxfs_dbg_disk_di_mode + globals mxfs_dbg_inactive_ino/gen.

## See also
state.md (full handoff), [[feedback_wait_in_foreground]] (run tests in FOREGROUND).
