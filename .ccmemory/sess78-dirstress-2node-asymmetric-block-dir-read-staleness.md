---
name: sess78-dirstress-2node-asymmetric-block-dir-read-staleness
description: sess78 BREAKTHROUGH — posix_multi16 blocker reproduces at 2 NODES as test_dir_stress FAIL (40/81), asymmetric block-format-dir read staleness; cheap fast repro.
metadata:
  type: project
---

## sess78 (run 14d31183) — posix_multi16 root reproduces CHEAPLY at 2 nodes

### THE KEY FINDING (user pushed: stop going straight to 16; ladder 2→4→8→16)
`run_tests.sh --nodes 2 --phase cluster` (no posix_semantics wrapper → NO internal reboot,
goes straight to tests; ~50s for first 6 tests):
- concurrent_mkdir/touch/write, cross_visibility, cross_write_read, cv_disc: **PASS fast**.
- **test_dir_stress: FAIL — 40 failures / 81 assertions in 7.7s.** discovery PASS after.
- So posix_multi16 is NOT primarily 16-node contention/slowness — there is a CORRECTNESS bug
  in dir_stress reproducible at **2 nodes in ~8s**. Cheap deterministic reproducer at last.
- (My earlier "slow even at 2 nodes" was WRONG — the run was progressing fine through the
  late tests; I cut it at a 320s foreground timeout. dir_stress is the late test
  unlink_visibility's predecessor; the run reaches uv_verify at BOTH 2 and 16 nodes.)

### Symptom (test_dir_stress.sh): ASYMMETRIC block-format-dir read staleness
- Test: both nodes mkdir -p shared parent `/mnt/shared/.mxfs_test/dir_stress`; each creates
  DIRS_PER_NODE=20 subdirs (node${ID}_dir1..20), each w/ FILES_PER_DIR=10 files →
  2×20=40 entries added to the SAME parent → parent grows shortform→BLOCK/BTREE.
- barrier ds_create_done + `sleep 2`; Phase 2: each node reads the OTHER node's 20 dirs.
- **node1.log: 40 FAILs** — "Dir node2_dirN visible: directory not found" + "has 10 files:
  expected=10 actual=0" for ALL of node2's 20 dirs. node1 sees only its OWN 20.
- **node2.log: 0 FAILs** — node2 sees node1's 20 dirs fine. → **ASYMMETRIC.**
- node1 = the parent-dir creator/owner (mkdir -p wins). So: the node that OWNS/caches the
  block-format parent dir FAILS to reload a PEER's later additions; the cold-reading peer
  (node2) reads the parent from disk correctly.
- This is the block-format-dir reader-staleness family (v0.4.7 read-time i_dlm_dir_gen
  invalidation; sess41/46/83 F08CE615). It PASSES cache_coherency (4-node) because that uses
  small/shortform dirs; dir_stress drives the parent to block/btree where node1's cached
  dir-data blocks are not invalidated/reloaded on node2's EX modify+release.

### NOT yet determined (NEXT SESSION, RULE 4): write-loss vs read-staleness
Decisive test: after the failure, on node1 `umount`+remount (or fresh node3) and re-count
node2's dirs. If they APPEAR → pure node1 read-cache staleness (data durable, i_dlm_dir_gen
reload not firing for the parent-dir owner). If still absent → node2's adds not durable /
clobbered. Build a clyde-orchestrated minimal repro (clyde sequences phases via ssh; no
in-test cleanup): node1 mkdir parent+20 dirs; node2 +20 dirs; node1 count node2_*; then
remount-verify. Cluster is CLEAN-mounted at 2 nodes right now (reset4.sh 2).

### State at handoff
- Build **7D1492FC** (P78 format/literal torn-dinode barrier) deployed on all 16 nodes;
  P78 did NOT fix dir_stress (different failure mode — read staleness, not torn-dinode shutdown).
  P78 still correct-by-construction for the torn-format case; keep it.
- **SCST abort-reclaim fix DEPLOYED + LIVE**: target now 3.11.0-pre+caw-abort-reclaim.1 (core
  scst.ko + scst_vdisk.ko from /src/scst/scst/src + rebuilt iscsi-scst.ko/isert-scst.ko to
  match the version string — SCST does an internal version-string check, "Incorrect version
  of target iscsi" if mismatched). Old modules backed up as *.pre-caw* in extra/. The first
  16-node run hit the exact D-state iscsi_conn_cleanup wedge it fixes; cleared it WITHOUT
  reboot via scst_unwedge.ko (4 edge-breaks on the 2 CAW + 2 READ cycle). See
  [[sess78-scst-caw-abort-reclaim-fix-and-p78-torn-format-barrier]].
- Ship gate: posix_semantics_multi16 + rsync_paired (148%, multi-node contention; single-node
  mxfs is FASTER than xfs) still FAIL; tcp_dlm_scaling PENDING. Marker NOT written.

Related: [[sess51-multi16-state-cwr-fixed-dirstress-discovery-blockers]]
[[sess83-lessons]] [[sess77-posix-multi16-durable-dir-format-content-corruption]]
