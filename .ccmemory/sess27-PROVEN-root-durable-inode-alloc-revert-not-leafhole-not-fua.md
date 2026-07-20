---
name: sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua
description: sess27 PROVEN root of dir_reuse 2/tcp: durable inode-alloc REVERT (dirent→freed inode, both nodes agree, persists drop_caches). NOT leaf-hole, NOT FU…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp ROOT, fully instrumented (RULE 4). Supersedes ALL prior framings (leaf-hash-hole, ABA-BLI-FUA, iget-stale-cache).

### PROVEN ROOT: durable on-disk inode-allocation REVERT
Build F156B768 (= C99F988B + un-capped P26-LKERR/DSCAN/IGET-FAIL detectors → ratelimited). Cluster: test1+test2, TCP, LIO target.
- `dir_reuse_coherency` fails: test1 readdir=200 (all names present), lookup_fail=57-95 (mostly node2's files).
- **P26-IGET-FAIL dp=1960 name="node2_f10" inum=2101385 err=-2 ftype=1**: dir LOOKUP SUCCEEDS (leaf finds the name → inum), but `xfs_iget(inum)` = -ENOENT. The dirent points to a **FREED inode**. (NOT a leaf-hash hole — leaf is fine; NOT a datascan gap.)
- **DURABLE + CONSISTENT**: after `echo 3 > drop_caches` (fresh disk read), BOTH test1 AND test2 show IDENTICAL d_ino via os.scandir: node2_f1→2101376 (VALID), node2_f2→2101377 (FREED), node2_f3→2101378 (FREED), … node2_f10→2101385 (FREED). Consecutive inodes. Both nodes agree → durable on-disk, NOT in-core coherency.
- **NOT double-alloc**: of 200 entries, 0 duplicate d_inos; 57 dirents reference genuinely-free inodes; none of the freed inos are reused by a node1 file. Pure REVERT (alloc lost), not reuse/double-alloc.
- node2 allocated a chunk (2101376..~2101425 for f1..f50, all in ONE 64-inode chunk aligned at 2101376). First ~9 inodes durably allocated, rest reverted to free. The `.md5` files got a separate chunk (2097783+), also partially reverted.

### Why this is a WRITEBACK revert (not a log/txn issue)
The dirent (dir data block) and the inode allocation (inode-cluster di_mode + inobt) are written in the SAME XFS transaction → atomic in the LOG. A durable split (dirent present, inode free) means the inode-cluster/inobt **destage (AIL writeback) was overwritten by a STALE buffer write** after node2's destage. The dir is rm-rf'd+recreated every round (test1=rank1 owns lifecycle) → INODE REUSE: round N-1 rm-rf frees inode X (node1 writes cluster di_mode=0); round N node2 reallocs X (di_mode set). If node1's round-(N-1) free writeback is not fully DESTAGED before its DLM release (only log-committed, in-AIL), it lands AFTER node2's round-N alloc → reverts X to free. Failure observed at the COLD READ (before THIS round's rm-rf), so the revert is the PRIOR round's free landing late. = architectural invariant #1 (durable-before-unlock) applied to INODE CLUSTER buffers.

### CRITICAL infra: FUA is DEAD on this target (see [[sess27-target-is-LIO-rejects-FUA-reads-handoff-plan-dead]])
Target = LIO-ORG, rejects SCSI READ(16)+FUA (asc=0x24) → all reads plain-bio. The ENTIRE prior fix corpus (sess21-26 + many earlier) is FUA-based (mxfs_buf_read_fua / _XBF_FUA_FRESH) and is INERT here. Read-side refresh CANNOT fix this — the disk is durably wrong. MUST fix write-side (prevent the stale inode-cluster writeback / ensure destage-before-release).

### NEXT (RULE 4): instrument the inode-cluster REVERT vector
1. Check if inode-cluster buffers (xfs_inode_buf_ops) are covered by mxfs_buf_is_ag_metadata + the write-side stale guards (P93/P110/P117/P121) and the dir/AG release destage. Likely GAP: release drains AG-meta (bnobt/agf/agi) + dir DATA, but NOT inode-cluster buffers, OR the cross-round free writeback isn't destaged before unlock.
2. Probe: log inode-cluster buffer WRITES setting an inode alloc→free (di_mode set→0) + comm + AG-lock state; correlate with the freed inode daddr across rounds.
3. Fix: ensure inode-cluster buffer is fully DESTAGED (written, out of AIL) before the dir/inode/AG DLM release on the rm-rf (free) path — so a reused inode's prior-free writeback can't land after the realloc.

### Detectors un-capped this session (build F156B768, KEEP for now): P26-LKERR, P26-DSCAN, P22-DATASCAN-HIT, P26-DSCAN-MISS, P26-IGET-FAIL → pr_warn_ratelimited (were atomic-capped ≤200, exhausted mid-run = invisible). drc_probe2.sh now checks lookup_fail (was readdir-count only — never caught the real bug).
</body>
