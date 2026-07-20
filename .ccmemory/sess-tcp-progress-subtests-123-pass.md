---
name: sess-tcp-progress-subtests-123-pass
description: 2-node TCP: build B77AD901 (4 fixes incl atime-EX skip) makes cache_coherency subtests 1,2,3 PASS; subtest4 failure traced to barrier desync from slo…
metadata:
  type: project
---

## Build B77AD901 (4 fixes, KEEP) — extends [[sess-tcp-2node-three-root-fixes]]
Adds FIX 4 (atime-EX skip) to the 3 prior fixes:

### FIX 4 — atime-on-read takes cluster DLM EX → deadlock. `pal/linux/xfs_iops.c::xfs_vn_update_time`
sess45 skip only covered PEER-AG inodes (`mxfs_inode_is_peer_ag`). A relatime atime
update on this node's OWN-AG file still took `XFS_ILOCK_EXCL` → `mxfs_dlm_ilock_begin`
(cluster EX acquire), which under concurrent cross-node reads (rename_visibility subtest)
WEDGED (proven: `cat` D-state 122s+ in mxfs_dlm_ilock_begin, peer idle; stack
cat→touch_atime→xfs_vn_update_time→xfs_ilock(EXCL)→mxfs_dlm_ilock_begin). Fix: also skip
ALL atime-only updates when multi-node (`mp->m_mxfs_dlm && !single_node`) — cluster-wide
effective-noatime. mtime/ctime still update.

## Measured result (build B77AD901, run 20260614T232237Z, COORD_TIMEOUT=25)
cache_coherency FAIL 0/2 but MUCH further: subtests 1 (cross_visibility), 2
(cross_write_read 1MB md5 both ways), **3 (rename_visibility)** all PASS now. Fails only
subtest 4 (unlink_visibility): `test1: uv all files present pre-delete(exp=60 got=30);
test2: uv barrier create / uv barrier preverify` (timeouts).

## Subtest 4 is NOT a coherency bug — it's barrier desync from slowness
Proven by isolation tests:
- Sequential: test2 creates 30 files in 0.03s; test1 sees all 30 in 0.015s. Prompt+correct.
- CONCURRENT both-nodes-30-files-same-dir + coord_barrier: test1 sees 60 IMMEDIATELY
  (immediate1=60, no lag). Concurrent dir-insert coherency is correct AND prompt.
- The real-run failure = the `uv_create` barrier TIMED OUT at COORD_TIMEOUT=25 because the
  two nodes drifted >25s apart in cumulative timing during subtests 1-3 (the coordinated
  reloads / DLM round-trips make some ops slow), desyncing the barrier so rank-1's count
  fired before rank-2's files were observed.

## OPEN QUESTION (running now): is it slow, or just barrier-marginal?
Re-running with COORD_TIMEOUT=60 TEST_TIMEOUT=240 (generous barrier headroom). If it
PASSES → coherency fully correct, remaining issue is PERF (slow coordinated reloads /
DLM round-trips making the test drift) which is a RULE-0 concern to optimize but not a
correctness bug. If it still fails the count → a real concurrent-dir promptness gap to chase.
Per RULE 0, slowness IS a fail — but first confirm correctness, then attack the slowness
(likely the P-TCP-VERIFY-COORD per-file coordinated reload + atime path overhead).

## Harness notes
- Background Bash tasks run in ISOLATED /tmp — can't read their intermediate files from
  foreground; only the task's .output (final stdout). run.sh records to criteria.json
  (NFS, visible): `jq '.categories[].tests[]|select(.name=="cache_coherency").runs["2/tcp"]'`.
- `tests/setup/reset2_tcp.sh` (smoke) and `tests/setup/bartest.sh` (barrier test) are in-tree.
</body>
