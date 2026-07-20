---
name: sess45-MILESTONE-full-suite-14of17-three-remaining
description: sess45 MILESTONE: clean full ./run.sh 2 tcp = 14 PASS / 3 FAIL (was ~8/17 sess44) after the partial-iwrite fix. Remaining 3 (all node1): cache_cohere…
metadata:
  type: project
---

## sess45 (ccloop 8ddb16a2, build EF006296) — full 2/tcp suite now 14/17

### Clean baseline (reboot both nodes, then `./run.sh 2 tcp`, ONE prep):
PASS (14): precond_readiness, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss,
dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, **crash_consistency**,
fence_during_write, fault_netpartition, soak.
FAIL (3) — ALL on node1/test1, all dir/visibility/perf coherency, NO mid-suite cascade:
1. **cache_coherency** 1/2: `uv gone node2_file21..30` + `uv none remain(exp=0 got=10)` — node1 sees
   10 of node2's UNLINKED files still present (cross-node unlink-VISIBILITY staleness). 190/201. No shutdown.
2. **dir_reuse_coherency** 1/2: `drc r1 r1 leaf-hash lookup_fail(exp=0 got=1)` — 144/145, ONE leaf-hash
   lookup miss (readdir lists name, lookup ENOENTs = dir LEAF hash block missing an entry; sess20/26
   leaf-hash-hole family). No shutdown.
3. **tcp_dlm_scaling** 1/2: `tds node1 completed rounds(exp=150 got=41)` — node1 SHUT DOWN mid-test
   via `__xfs_trans_commit+0x2c4 Corruption of in-memory data (0x8)` at xfs_trans.c:890 (uptime 548s,
   during the last test). So this is a real in-memory-corruption-on-commit bug, not pure slowness.

### KEY: my fix recovered the suite from contaminated/wedged to 14/17. crash_consistency PASS in-suite
confirms [[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]] holds. force_block=0 kept.

### GOTCHA (cost a confusing 0/17): if a prior full-suite run is TaskStop'd mid-prep, the NEXT full run
reports 0/17 (false cascade — early DABUF_MAP_HOLE/trans_cancel on contaminated state). ALWAYS reboot
both nodes clean (virsh destroy/start) before trusting a full-suite result. The DABUF_MAP_HOLE
(xfs_create→xfs_dabuf_map !MAP_HOLE_OK, dir extent-map hole) did NOT recur on the clean run — it was
a contamination artifact, NOT a standalone bug (precond+cache_coherency standalone = no DABUF_MAP_HOLE).

### NEXT (3 distinct dir-coherency residuals, all node1; pick the closest first):
- dir_reuse leaf-hash lookup_fail=1 — closest (1 check). Leaf-hash hole: a dir LEAF block written
  missing a peer's hash entry (sess19/20 P56-LEAF probes in pal/linux/xfs_buf.c:2286+). 
- cache_coherency uv — node1's reader view keeps node2's deleted dirents (dir-block read staleness;
  b_mxfs_dir_gen invalidation / FUA-reread path xfs_da_read_buf).
- tcp_dlm_scaling trans_commit corruption(0x8)@xfs_trans.c:890 — instrument what dirties+fails the
  commit on node1 around round 41. [[sess45-MILESTONE-full-suite-14of17-three-remaining]] self-link ok.</body>
