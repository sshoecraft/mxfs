---
name: sess97_lessons
description: sess97 — WRITER-SIDE FIXED: publish-before-notify at commit (rename PASS, KEEP). READER-SIDE in progress: consumer-refresh eager dir-block evict (sur…
metadata:
  type: project
---

# sess97 (2026-06-06, ccloop run 29df431e)

## Build lineage
- `476E164C` = sess96 FB9573F7 + WRITER-SIDE publish-before-notify. rename_visibility PASS.
- `AF60EC48` = +CONSUMER-REFRESH eager dir-block evict on reader path. unlink 2→1 survivor.
- **`1B611843` (HEAD, BUILT, NOT YET DEPLOYED/TESTED)** = +evicted_gen retry-on-skip fix.
- fua_disable=1 default (correct, do NOT re-enable FUA).

## WIN 1: publish-before-notify at COMMIT (KEEP) — rename_visibility 2/240 → 0 PASS (32s)
Wired `mxfs_dlm_dir_durable_signal(dp)` (log_force(SYNC)+mxfs_dir_flush_data_blocks(xfs_bwrite+wait_unpin each dir DATA block)+note) POST-commit, ILOCK+EX held, into xfs_remove(~2841), xfs_create(~1342), xfs_rename(~3229 both src_dp+target_dp). Safe at COMMIT (buffer = this node's own change; EX excludes peers) where sess96's RELEASE-time flush clobbered. Unpins the buffer → next acquire re-reads fresh (eliminated DIR-STALE-SKIP, 0 now). Writer side + on-disk MEDIUM now always correct.

## WIN 2 (partial): CONSUMER-side eager dir-block refresh (reader half)
Root (proven, RULE4): peer reader served STALE in-core dir block. Medium is CLEAN (remount fixes it). The lazy per-buffer hook (xfs_da_btree.c:2999) stamps b_mxfs_dir_gen BEFORE reread → a block reread when a DIFFERENT writer bumped the shared per-dir gen (while THIS block's writer not yet visible) caches stale-as-current, never re-read.
FIX: `mxfs_dlm_dir_consumer_refresh(dp)` at top of xfs_file_readdir (pal/linux/xfs_file.c) + xfs_lookup (xfs_inode.c:~619). When i_dlm_dir_gen > i_dlm_dir_evicted_gen (peer modified since last refresh), eagerly evict ALL clean dir DATA blocks via mxfs_dir_evict_data_blocks → next read refetches durable image. New field `i_dlm_dir_evicted_gen` (xfs_inode.h:116, init xfs_mxfs_dlm.c:~3993). EVICT-RING gen delivery WORKS (gen bumps arrive ~100x). 
RESULT on AF60EC48: unlink_visibility 2→1 survivor; P97-CONSUMER-REFRESH fires ~50x/node, P-EVICT-DONE fires.

## The remaining-1-survivor bug + fix (in 1B611843, UNTESTED)
P-EVICT-SKIP fired 1x on test1: an UNDURABLE (pinned/in-AIL) block was skipped, BUT evicted_gen still advanced → that stale block never retried (gen matches) = the 1 survivor. FIX: mxfs_dir_evict_data_blocks now returns bool all_evicted; consumer_refresh advances i_dlm_dir_evicted_gen ONLY on full success — a skipped block leaves evicted_gen behind so the NEXT read retries once durable.

## NEXT SESSION (immediate)
1. `LIBVIRT_DEFAULT_URI=qemu:///system virsh destroy/start test1-4` (clean), `bash tests/reset4.sh 4` deploys 1B611843 (NFS /src/mxfs/mxfs.ko, fua_disable=1). Confirm srcver on all 4.
2. Run unlink_visibility (target: 1→0). Also rename_visibility (must STAY 0) + cross_write_read + cross_visibility. If unlink passes, run full `tests/criteria/cache_coherency.sh`.
3. Watch: P-EVICT-SKIP (if a block stays undurable forever = perf wall / different bug) and P97-CONSUMER-REFRESH evicted_gen lagging.
4. The test verify is POST-barrier (writers done) so refetch is fresh; the eager-evict avoids the restamp race AT verify time. If a survivor persists, it's an undurable-skip that never clears, or the create-phase lookup path racing. 
5. If still failing after the retry fix: implement the full GPT durable-epoch seqlock design — see [[sess97-gpt-dir-coherency-design]] (the robust correctness fix that removes the heartbeat from the correctness path; current consumer-refresh still depends on EVICT-RING gen delivery which can be lossy/slow under concurrent modify).
6. Separate blocker: intermittent bnobt double-free shutdown ~1/2 runs.

## Single-subtest cmd
`MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16 tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`
Survivor inspect: `ls /mnt/shared/.mxfs_test/unlink_visibility/node*_file*` per node via tools/mxfs_sshpass.sh testN.vm.localdomain /tmp/.mxfs_pass. instr: `echo 1 > /sys/module/mxfs/parameters/instr`.
