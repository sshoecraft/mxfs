---
name: sess80-posix-multi16-root-dir-bmap-hole-and-contamination
description: sess80 (run 14d31183, build 305641B7): posix_multi16 >600s ROOT = durable dir-bmap HOLE corruption (xfs_dabuf_map !HOLE_OK line 2814) on a shared dir…
metadata:
  type: project
---

## sess80 — gate status + posix_multi16/rsync_paired diagnosis

### Gate truth (.criteria_results.json, build 305641B7)
17/20 PASS. 3 FAIL: **rsync_paired** (235% of XFS, threshold 120%), **posix_semantics_multi16**
(>600s), posix_semantics_multi2 (n/a — NOT in verify_ship.sh gate, ignore). cache_coherency,
strong_consistency, zero_silent_loss, crash_consistency, fence_during_write all PASS now (the
resume summary citing cache_coherency as blocker was stale).

### posix_multi16 >600s ROOT (confirmed this session, clean reboot)
- `verify_ship.sh` runs `posix_semantics.sh --nodes 16` = run_tests.sh --phase all: 12 single
  (~16s, all fast) + 14 CLUSTER + 6 stress. All cost is the cluster phase.
- On a CLEAN reboot, individual cluster tests pass but timing varies HUGELY by contamination.
  Clean: concurrent_mkdir 22s, concurrent_touch 30s, concurrent_write 15s, cross_visibility 127s,
  cross_write_read 9s. CONTAMINATED (orphan run_tests procs from a prior killed run holding D-state
  AGI locks): concurrent_touch 182-264s. **sess77 mandate confirmed: kill ALL orphan ssh/mxfs_test
  procs + clean before trusting timing.** Wrote tests/reboot_cluster.sh (virsh destroy+start all N).
- The >600s FAIL is NOT pure slowness — it's **durable corruption → shutdown → hang**. This run
  test_cv_disc (6th cluster test) triggered: `XFS (sda): xfs_dabuf_map: bno 8388609/8388610 inode
  131 ... Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at line 2814 xfs_da_btree.c` on multiple
  nodes (t2,t3,t4,t12...) → `mxfs: DLM shutting down` → all ops EIO → barrier_wait 120s timeouts ×
  many → hang (>16 min). Same signature as sess77.
- bno 8388608=0x800000 = dir2 LEAF address space. HOLE at 0x800001/2 = the dir grew leaf→node
  (added leaf/node blocks) but the **data-fork bmap extent for the new block is MISSING** → read
  via xfs_da3_node_lookup_int hits a hole. = durable dir-bmap lost-update under 16-node concurrent
  same-dir modify during sf→block→leaf→node growth.
- chk_mxfs -v after unmount: ERROR inodes 137,138 nlink=0 (allocated but parent dirent LOST =
  durable dirent lost-update orphans); superblock icount=320 but inobt sum=5120, ifree mismatch
  (durable SB counter drift across nodes). chk is SHALLOW (8/11 inodes checked) — did NOT
  deep-validate inode 131's dir bmap, so on-disk(H2) vs in-core(H1) of the HOLE is still OPEN.

### NEXT (RULE 4) — decisive H1/H2 test
test_cv_disc has built-in drop_caches discrimination (H1=in-core stale/on-disk present,
H2=on-disk lost) but HUNG before logging. Re-run cluster phase on clean reboot, capture FIRST
`xfs_dabuf_map` inode#, the DISC H1/H2 line, and chk that inode. H1 → reload bug (mxfs_dlm_reload_inode
xfs_idestroy_fork+from_disk rebuilds extent map but maybe stale). H2 → writer drains dir DATA but
releases dir EX without durably flushing the INODE carrying the new extent (Invariant #1 gap; note
sess135 "dinode iflush refused by P119 non-EX authority guard"). Then guard. Target: cluster phase
0 shutdowns, suite <600s.

### Perf (rsync_paired 235% + create throughput)
- ct_decompose microbench (tests/ct_decompose.sh): 16-node concurrent touch into ONE dir.
  CREATE phase dominates (55s of 182s); stat/ls fast. Fastest node 100 creates in 0.196s
  (510/s uncontended) but aggregate ~29/s under 16-way contention = ~17× CAW EX-handoff penalty;
  slowest node starved 54.8s for the lock.
- `mxfs_dlm_dir_modify_refresh`→`mxfs_dir_evict_data_blocks` evicts ALL dir blocks per create when
  peer-modified (O(dir-blocks)/create → O(n²)); reads are lazy O(log n). MHT (`inode_mht_ms`,
  default 50, runtime-writable /sys/module/mxfs/parameters/inode_mht_ms) amortizes by batching a
  node's creates per tenure. inode_mht_ms 250→create 55s→16s (3.4×), 150→7.8s — BUT durable
  divergence appears (test1 sees 600, test8/16 see 0, no converge). **Raising MHT trades correctness
  for speed — NOT a safe fix.** Default 50 is tuned to the correctness edge.
- The shared dabuf_map HOLE fix is the prerequisite; once correct, attack handoff throughput.

Build 305641B7 unchanged this session (diagnosis only). Tools: tests/reboot_cluster.sh,
tests/ct_decompose.sh. Related: [[sess77-posix-multi16-durable-dir-format-content-corruption]]
[[sess43-dirdata-pin-rootcause]] [[sess88-lessons]] [[sess90-fua-reads-logged-not-checkpointed-root]]</body>
