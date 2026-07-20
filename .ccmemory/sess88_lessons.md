---
name: sess88_lessons
description: "sess88 — dir-block durable lost-update FIXED (noino-BAST AG drain, build 73B57CCD, KEEP); DIR-STALE-SKIP 20-40→0; bnobt AG-meta in-core corruption now the isolated sole blocker"
metadata: 
  node_type: memory
  type: project
  originSessionId: 2cc57d0c-b810-4172-8dfa-1df7bb657e91
---

# sess88 (2026-06-05, ccloop) — dir-block lost-update FIXED; bnobt isolated as next blocker

## PROVEN WIN (RULE 4 + RULE 5): dir-block durable lost-update FIXED
Build **73B57CCD** (deployed test1-4, **KEEP**). One-line change in `mxfs_dlm_bast_notify`'s
NO_INODE branch (xfs/xfs_mxfs_dlm.c ~L1719, right before `mxfs_v5_dlm_inode_unlock`):
```c
xfs_agnumber_t n_agno = XFS_INO_TO_AGNO(mp, ino);
xfs_log_force(mp, XFS_LOG_SYNC);
(void)xfs_ail_push_ag_sync_bounded(mp->m_ail, n_agno, 50, 8);  /* bounded: stall_iters=50,min=8 */
blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
```
**Root (RULE-4 proven, this run):** rename_visibility node loses its OWN dirent (e.g. node3_after_1)
in 4-node concurrent same-shared-dir rename = WRITE-side durable lost-update. The `P-NOINO-BAST`
path (peer BASTs a dir inode that THIS node has RECLAIMED → no in-core inode) released the DLM slot
with NO dir-data drain (reclaim flushes only the inode CLUSTER; dir-data xfs_buf's are independent
AIL items). Proof: `DIR-STALE-SKIP ino=<shared dir> in_ail=1 (or pin=1) disk_differs=1 buf_gen=0`
fired 20-40×, with `P-NOINO-BAST` 11-15×/node on the SAME inode. A peer FUA-read the stale platter,
RMW'd, durably reverted our dirent. Invariant #1 violation (no unlock without drain). No extent map
in noino path → flush by the inode's AG (small dir's data blocks live there). **RULE 5 Gemini**
designed "Scoped Synchronous Flush-and-Evict on EX-release"; the noino-drain is the durability half.
**RESULT:** DIR-STALE-SKIP **20-40 → 0**. rename_visibility PASSES 0/240 in ISOLATION (was 2/240).
unlink_visibility shutdown ELIMINATED. cross_write_read now RUNS (baseline never reached it — node1
unmounted by unlink shutdown). Net criterion: still passed=1, but failure mode shifted + dir class resolved.

## REVERTED (RULE 4 disproven → reverted): eviction-on-reclaim
Adding `mxfs_dir_evict_data_blocks(ip)` after `mxfs_dir_flush_data_blocks(ip)` in `mxfs_dlm_evict`
(reclaim path, build 797151A1) to evict the now-durable cached dir blocks REGRESSED: clearing
XBF_DONE on a buffer whose bli is still (or re-)in the AIL makes it UN-PUSHABLE → xfsaild's
unbounded `xfs_ail_push_ag_sync` stuck at 39000+ iters (AG-AIL-STALL agno=7) = near-hang + SB-LSN
shutdowns. Confirms sess39/64: NEVER clear XBF_DONE on a dirty/pinned/in_ail buffer. REVERTED;
73B57CCD (noino-drain only) is the keeper. Eviction is UNNECESSARY anyway — once the release-side
flush makes the buffer CLEAN (not in_ail/pin), the existing xfs_da_read_buf gen-invalidation handles
the re-read (it only skips dirty/in_ail/pin). DIR-STALE-SKIP=0 confirms this works.

## NEXT BLOCKER (isolated, dominant): bnobt AG-meta in-core corruption — sess44-52 family
Full clean run (fresh mkfs, 4 nodes 73B57CCD): cross_visibility PASS, rename FAIL 40/240 (in-SEQUENCE
only; 0 in isolation = cumulative warm-cache/inode-reuse contamination), unlink FAIL 4/122 (no
shutdown), cwr FAIL 1-2/6. `P88-INSTR bnobt` fired 34-40×/node → `xfs_buf_verify_write` FAIL →
`SHUTDOWN_CORRUPT_INCORE` (pal/linux/xfs_buf.c:1656). Decisive P88 sample (agno=10): in-core
`numrecs=2 rec0=[32777,7]` vs disk `numrecs=3 rec0=[32777,1]`, **buf_gen=1 pag_gen=1 MATCH** (so
gen-invalidation treats stale buffer as fresh), ag_held=1 ex_pop=1 ex_nslots=1 (SOLE EX holder —
concurrent-EX REFUTED, sess52), in_ail=1 dirty=0 pin=0. ROOT (sess46/sess52): `pag_dlm_meta_gen`
FROZEN at 1 — bumped only on fresh CAW grant (xfs_mxfs_dlm.c L4788) + cached→held (L4627), NOT on
nested re-entry (L4612) nor when a peer modifies while we hold cached → stale cached bnobt served +
modified → in-core btree becomes structurally invalid → write-verify shutdown. sess80 RULE-5 Gemini
direction: ditch local pag_dlm_meta_gen, use a SHARED ON-DISK AGF epoch every node bumps on modify,
acquirer compares cached vs on-disk. NEXT: consult Gemini on bnobt with this evidence (started end of
sess88); implement AGF-epoch or find the specific peer-modify path that skips the gen bump.

## INFRA / GOTCHAS (cost real time this session)
- `make clean` (run by a runaway `tools/mxfs_deploy.sh` per-host loop) WIPES mxfs.ko AND the
  userspace tools (tools/mkfs_mxfs, chk_mxfs). Rebuild: `make modules` + `make tools`.
- `tools/mxfs_deploy.sh <host>` takes ONE host (not --nodes N) and does `make clean && make` on the
  SHARED NFS dir per node = SLOW (>180s each) + self-conflicting. FAST deploy instead: all node
  kernels == dev kernel (6.8.0-101-generic), so just `insmod /mnt/mxfs-src/mxfs.ko` (or /src/mxfs/
  mxfs.ko) directly per node, no rebuild.
- Two NFS exports: deploy uses 192.168.120.1:/src/mxfs→/mnt/mxfs-src; reset4/lib.sh uses
  192.168.1.4:/src→/src. Ensure BOTH where needed; run_tests needs /mnt/mxfs-src test scripts.
- Shutdowns leave on-disk FS corrupt (bnobt, SB-LSN-ahead) + leaked module refcount=1 (rmmod "in
  use" with NO mount) → node WEDGED. Recovery: `virsh destroy <vm>; virsh start <vm>` (LIBVIRT_DEFAULT_URI=qemu:///system),
  wait for boot, then `tests/reset4.sh 4` (does fresh mkfs). First mount post-shutdown often hits a
  transient SCSI reservation conflict (-117/EFSCORRUPTED "Structure needs cleaning") → RETRY mount 2-4x.
- First-ever mount when forming cluster races (reservation conflict); always retry.
