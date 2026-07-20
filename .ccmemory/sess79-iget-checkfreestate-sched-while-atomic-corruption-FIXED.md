---
name: sess79-iget-checkfreestate-sched-while-atomic-corruption-FIXED
description: sess79 ROOT FIX (build 305641B7): always-on P-IGET-ENOENT diagnostic did sleeping FUA read under rcu+i_flags_lock → sched-while-atomic → inobt corrup…
metadata:
  type: project
---

## sess79 (ccloop run 14d31183) — posix_semantics correctness: corruption/shutdown ROOT FIXED

### Ground truth at session start (from .criteria_results.json, NOT state.md/p which are stale)
- 11/12-ish criteria PASS. The `p` prompt (cache_coherency/P110) and state.md head (sess134/zero_silent_loss) are BOTH stale — zero_silent_loss now PASSES (06-14 12:35). Real gate blockers in `verify_ship.sh` order: **rsync_paired** (perf 148%→235% on 7D1492FC), **tcp_dlm_scaling** (never run), **posix_semantics --nodes 16** (timeout / correctness).
- posix_semantics_multi2 is NOT a gate criterion (session-78 diagnostic).

### THE FIX (build 305641B7, VERIFIED — keep)
**Root (PROVEN via kernel BUG + stack):** `xfs_iget_check_free_state` (xfs/xfs_icache.c ~669-714) holds an ALWAYS-ON diagnostic block `P-IGET-ENOENT` (sess40/sess127) that does SLEEPING I/O: `xfs_buf_incore` + `mxfs_pal_scsi_read_fua_bdev` (FUA SCSI read = blk_execute_rq wait). It runs on the mode==0 ENOENT cache-HIT path — and `xfs_iget_cache_hit` calls check_free_state at line 981 while holding BOTH `rcu_read_lock()` AND `ip->i_flags_lock` (spinlock; unlocked at out_error:1051) ⇒ preempt_count=2. Sleeping there = `BUG: scheduling while atomic: mxfs-worker preempt_count=2`, reached via `bast_recv_fn→v5_bast_cb→mxfs_dlm_bast_notify→xfs_iget(XFS_IGET_INCORE)`. The forced schedule lets an RCU grace period reclaim/free the inode under us → use-after-free → `inobt record corruption in AG8` → `Metadata I/O Error at xfs_inactive_ifree (xfs_inode.c:2391)` → fs SHUTDOWN. The concurrent unlink/create storm produces mode==0 (freed/reused) inodes constantly, so it fired every run.

**Patch:** guard the sleeping probe with `if (!in_atomic() && xfs_buf_incore(...))`. `in_atomic()` is reliably true at the dangerous site because the spinlock `i_flags_lock` bumps preempt_count regardless of RCU config. Diagnostic-only change; no functional behavior altered. Two OTHER `xfs_buf_incore` diagnostics in the same fn (~544/~594) are on the XFS_IGET_CREATE alloc path (non-atomic, -EFSCORRUPTED shutdown paths) — NOT reached from the atomic cache-hit site; left as-is.

**Verified:** before fix, standalone `run_tests --nodes 2 --phase cluster` → rename_vis_dbg + unlink_visibility FAIL, dmesg = sched-while-atomic ×N + inobt corruption + shutdown (node1 fs shut down, dropped mount). After fix (305641B7): 12 PASS / 1 FAIL, **0 sched-while-atomic, 0 corruption, 0 shutdown**; unlink_visibility + rename_vis_dbg PASS.

### REMAINING blocker (posix gate): test_dir_stress block-format-dir READ STALENESS
- node1 (the shared-parent-dir owner via mkdir -p race) fails to see SOME of node2's later dir additions (e.g. node2_dir14/15 "directory not found / actual=0"), 3 fails/81 — much reduced from sess78's 40, asymmetric (node2 sees node1 fine). node2's dirs ARE durable on disk (a cold/fresh reader sees them); node1's cached block-format parent dir-data blocks aren't reloaded on node2's EX modify+release. This is the v0.4.7 read-time i_dlm_dir_gen invalidation NOT covering the parent-OWNER case once the dir is block/btree format. NEXT: RULE-4 instrument the dir-block reload-on-peer-EX path for the owner; cheap repro = `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes 2 --phase cluster` (~90s).

### Infra notes (this session)
- test1-4 /dev/sda = QNAP iSCSI (192.168.1.4, iqn.2004-04.com.qnap). It FLAPS conn-error(1020) per-initiator (test1/test4 were bouncing; test4 mount couldn't write). Fix = power-cycle the node (virsh -c qemu:///system destroy/start) for fresh iSCSI sessions, THEN reset4.sh.
- run_tests.sh MUST be invoked with `MXFS_TESTS_DIR=/src/mxfs/tests` (default /mnt/mxfs-src is NOT mounted on nodes → rc=127 "command not found" masquerading as test failures). /src is the QNAP NFS mounted on nodes.
- Repro script: tests/repro_lost_entry.sh (orchestrated concurrent dir writes + fresh-reader/remount classifier). Loose-timing isolated repro is unreliable; the real harness reproduces deterministically.

Related: [[sess78-dirstress-2node-asymmetric-block-dir-read-staleness]] [[feedback-ccmemory-unavailable-is-hard-stop]]
