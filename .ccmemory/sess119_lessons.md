---
name: sess119_lessons
description: sess119 — iflush→DLM-EX (KEEP, corruption gone). cache_coherency ROOT=concurrent-mkdir TOCTOU on SHORTFORM parent; EXACT hole found: refresh only evi…
metadata:
  type: project
---

## sess119 (ccloop 4eef1f39, build C69013B3)

### KEEP — DLM-EX discriminator replaces gen heuristics in xfs_iflush (Gemini RULE-5 validated)
`xfs/xfs_inode.c` ~3582: resurrection guard now **skips disk copy iff `ip->i_dlm_mode != MXFS_LOCK_EX`**
(multi-node + valid magic). Replaces di_gen compare (cross-node gen randomized per-node + bumped on free
→ not comparable → ~50% peer-clobber hole). Verified: 0 shutdowns in cache_coherency; P119-NONEX-FLUSH-SKIP
fired only 2× (correct). SAFE w.r.t. release: `mxfs_ail_drain_inode_sync` (xfs_mxfs_dlm.c:1402) flushes
inode core via xfsaild while still EX, BEFORE i_dlm_mode=NL (line 1747).

### ROOT OF cache_coherency RE-PROVEN — concurrent same-name mkdir cross-node TOCTOU on SHORTFORM parent
NOT the iflush guard. All N nodes `mkdir -p .mxfs_test/cvrepro_K` → each allocates a DISTINCT dir inode
for the SAME name at every path level (proven: 4 distinct `.mxfs_test` inodes under root 128 via P90-PICK
`parent=128 ifmt=04`). Losers orphaned→files invisible + dangling-dentry EIO; escalates over iters to
inode-cluster corruption (err117 xfs_imap_to_bp). Timeline (realns, always-on probes): all 4 acquire root
128 PR(mode=3) within ~6ms, each `P105-ACQ-DIRINODE disk_size=6` (EMPTY shortform root) → all see "no
.mxfs_test" → all create. Root 128 SHORTFORM (fmt=1: dirents inline in inode-cluster). P108/P106-STALE-EX/
P107 ZERO → not the cached-EX fast-path. Single-level `mkdir zz` from 4 nodes CONVERGES; split needs
nested mkdir -p + concurrency + cached parent locks.

### EXACT CODE HOLE (pinpointed — actionable)
xfs_create (xfs/xfs_inode.c ~1204-1257) ALREADY has the cross-node EEXIST re-check: after xfs_dialloc it
re-acquires dp ILOCK_EXCL (1206) → `mxfs_dlm_dir_modify_refresh(dp)` (1218) → `xfs_dir_lookup_locked`
(1257) → on found, orphan the alloc'd inode + return -EEXIST (P106-MKDIR logs lrc). **BUT**
`mxfs_dlm_dir_modify_refresh` (xfs_mxfs_dlm.c:657) and its read sibling `mxfs_dlm_dir_consumer_refresh`
(:594) ONLY call `mxfs_dir_evict_data_blocks(dp)` — which is a **NO-OP for SHORTFORM dirs** (no data
blocks; dirents live in dp->i_df.if_data inode core). So the EEXIST re-check reads the STALE in-core
shortform fork → misses peers' committed entries → duplicate. Proven: P106-MR-EVICT fired for ino=128 but
it's shortform → no refresh.

### FIX TO IMPLEMENT NEXT (RULE 4 step 2b)
For SHORTFORM parent dirs, the modify-refresh (and likely consumer-refresh) must reload the INODE CORE
FUA-fresh, not just evict data blocks. Primitive: `mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN)`
(xfs_mxfs_dlm.c:2519) — stales the cluster buf (clears XBF_DONE), re-reads dinode via xfs_imap_to_bp,
rebuilds fork; HAS anti-clobber guards (RELOAD-SIZE-DROP-SKIP, RELOAD-TYPEFLIP-STALE-SKIP — di_gen/di_size
based, which GPT says are NOT valid coherency, but they refuse only on mismatch/torn). RISK: reload is
in-trans at line 1218 (dp ILOCK_EXCL held, tp active, dp NOT yet dirtied by THIS create's dirent insert
which happens AFTER the check) — verify dp's dir fork is clean (no logged mutation) before reloading, else
clobber. Add to mxfs_dlm_dir_modify_refresh: `if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL) mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN);`
(gate multi-node, dir, clean). Also ensure writer DESTAGES shortform inode-cluster FUA-durable on ALL
release paths (sess85 mxfs_dir_inode_cluster_durable runs only in bast_process — GPT: funnel all
release/downconvert through one durable fn; pin inode while EX). Then test:
`bash tests/repro_double_alloc.sh 25` (KEEP, new this sess) → expect all "clean"; then
`tests/criteria/cache_coherency.sh --nodes 4`.

### GPT-5.5 fix design (RULE-5 escalation; prior Gemini sess105-107 didn't crack it)
1. PRIMARY: hold parent dir DLM EX across the WHOLE create-intent lookup→mutation (not PR). Key off VFS
   create-intent. Loser looks up AFTER winner's EX-release barrier → -EEXIST.
2. MANDATORY coherence: dirty-EX may not release/downconvert until dir HOME metadata FUA-durable
   (shortform=inode-cluster); EX/PR acquire after peer-EX must invalidate + FUA-adopt fresh ONLY when
   inode clean; invalidate NEGATIVE dentries on parent epoch change; di_gen/di_size guards are NOT valid
   coherency — use DLM stale-state rule. Drain order: log_force(SYNC)→push+wait AIL→THEN FUA-write
   (avoid xfs_bwrite on delwri = sess113 wedge).

### METHOD
Clean reboot (virsh destroy+start ALL 4) → reset4.sh 4 (fresh mkfs) before trusting results.
repro_double_alloc.sh (new, KEEP) detects split+dup-ino+corruption, keeps dmesg. Marker NOT written;
cache_coherency sole failing criterion (11/12 pass).
</body>
