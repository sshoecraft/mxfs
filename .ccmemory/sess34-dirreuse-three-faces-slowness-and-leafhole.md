---
name: sess34-dirreuse-three-faces-slowness-and-leafhole
description: sess34 dir_reuse 2/tcp: ONLY failing test. 3 faces (corruption/slowness~16s-rd/leaf-hole). MHT refuted. Leaf NOT flushed at release (P21F=0). Inv-1 l…
metadata:
  type: project
---

## sess34 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp is the ENTIRE 2/tcp blocker

Builds: baseline DBD3A375; instrumented **A815A103** = +P34-ACQ-SLOW (logs inode DLM acquire >1s:
ino/isdir/req_mode/dur_ms/attempts/rc) + per-phase `mxfs-DRCph PHASE={create-start,create-done,
verify-done,rm-done}` /dev/kmsg markers in tests/suite/dir_reuse_coherency.sh (pure logging).

### STATE: 16/17 of 2/tcp PASS. ONLY dir_reuse_coherency FAILs. THREE faces (extreme variance,
run 3-5×): (1) corruption shutdown [sess33], (2) SLOWNESS ~16s/round → TEST_TIMEOUT=300 hit before
24 rounds, (3) LEAF-HASH-HOLE (round 17 both nodes readdir=200/200 lookup_fail=6, node1_f45..f50.md5
= TAIL of node1 md5 batch, DURABLE on disk).

### NOT the cause (ruled out / refuted this session):
- Allocator double-alloc: AG affinity (node_slot%maxagi for dirs AND files) + strict AG partition
  ALREADY implemented (xfs_dialloc_pick_ag, xfs_ialloc.c:2070). TCP mxfs_v5_dlm_ag_lock = real EX.
- **MHT REFUTED as the slowness lever**: mxfs_inode_mht_ms is a runtime module param
  (`inode_mht_ms`). Ran MXFS_EXTRA_MODARGS='inode_mht_ms=0' → STILL ~16s/round, verify still 3.2s,
  6s dir stalls persist, still FAIL. So 50ms MHT is NOT the bottleneck. Default stays 50.

### SLOWNESS anatomy (~16s/round; 24 rds would be ~384s > 300s = RULE-0 FAIL on its own):
per-phase (DRCph): create 0.8-6.5s, verify 3-9s, rm ~2.5s, inter-round mkdir+barrier ~4s.
- **~6s stalls are ALL dir-131 acquires** (P34-ACQ-SLOW isdir=1 dur 5992/6142/6233ms attempts=1
  rc=0 = ONE blocking mxfs_v5_dlm_inode_lock; holder slow to release dir). Only 2-3/run.
- Dir release goes via bast_process workqueue (P138-BAST dir=1 count=0; inode bast wq =
  alloc_workqueue concurrent). The ~6s is the bast_process DRAIN being slow for the dir, NOT MHT.
  bast_process DOES settle: wait xfs_ipincount(ip)==0 (xfs_mxfs_dlm.c:3893) + log_force(SYNC) +
  then mxfs_dir_flush_data_blocks (3918) + mxfs_ail_drain_inode_sync + blkdev_issue_flush.
  → 6s is inside this drain (log_force/ail wait / I/O). NEXT: instrument bast_process phase timing.

### LEAF-HOLE root lead (PROVEN-ish, RULE 4): **P21F-RELFLUSH-LEAF = 0 on BOTH nodes** (always-on
detector, xfs_mxfs_dlm.c:1306, fires when mxfs_dir_flush_data_blocks xfs_bwrites a dir3_leaf1/leafn
buffer). 0 fires = the release-drain NEVER flushes a LEAF block. So at DLM handoff the dir LEAF is
NOT destaged (left to async xfsaild, lands AFTER handoff) → peer (and self post-drop_caches) reads a
STALE leaf missing the tail entries → durable leaf-hash-hole. mxfs_dir_flush_data_blocks
(xfs_mxfs_dlm.c:1185) iterates ALL data-fork extents incl. leaf but gates on needs_flush
(dirty|in_AIL|pinned|delwri); the leaf is apparently CLEAN/not-cached at release → skipped.
ACQUIRE-side gen/ABA/keep-guard exist (xfs_da_btree.c:3084-3213: b_mxfs_dir_gen<i_dlm_dir_gen,
owner_aba via mxfs_dir_data_buf_owner_mismatch, incarn_aba via b_mxfs_dir_incarn=i_generation,
sess43 in-AIL-undestaged keep-guard) — covers leaf reads (whichfork==DATA_FORK) but the keep-guard
can PRESERVE a stale in-AIL-undestaged leaf.

### NEXT SESSION (priority order):
1. PROVE leaf-hole: reproduce (run 3-5×, build A815) until a leaf-hole (not timeout) recurs; check
   P21F-RELFLUSH-LEAF timeline for ino=131 (a node landing SHORT leaf_count after peer's TALL =
   stale-RMW clobber) AND whether leaf is flushed at release. If leaf never release-flushed →
   FIX = force the dir LEAF block(s) destage at handoff (extend mxfs_dir_flush_data_blocks to
   unconditionally bwrite cached leaf buffers for the releasing dir, or add a leaf-specific drain).
2. The 6s bast_process dir-drain: add phase timing, find the slow step, cut it.
3. Both slowness (≤~6s/round target) AND leaf-hole must pass for 100%. Run full ./run.sh 2 tcp ×3.
- Cluster: reset2.sh before every run (D-state unmount wedge). dmesg ring WRAPS in long runs (grep
  promptly / count via DRCph not ifree). [[sess34-dirreuse-three-faces-slowness-and-leafhole]]
  supersedes; see also [[sess28-dir-data-block-RDMISS-first-block-clobber]] (same stale-RMW class,
  data-block variant) [[sess33-PROVEN-ROOT-inode-data-block-double-alloc]].</body>
