---
name: sess57-clean-rerun-true-state-ino128-deadlock
description: sess57 (run 14d31183): user-ordered CLEAN re-run of ALL criteria on build A1F53770 exposed 3+ hidden FAILs; dominant root = ino=128 root-dir DLM EX s…
metadata:
  type: project
---

# sess57 — CLEAN re-run reveals true ship-gate state (build A1F53770)

User (2026-06-13) ordered: clear ALL `.criteria_results.json` PASS entries to
not-run and re-run the ENTIRE gate to "see where we REALLY are". The stale
dashboard (dated 2026-06-12, 18/19 PASS) was **masking real regressions**.
Backed up old results to `/src/mxfs/.criteria_results.json.bak.sess57`; reset
file to `{}`; ran `tests/criteria/verify_ship.sh --keep-going`.

## Clean-run results on A1F53770 (sess56 dir-format fix + P56 probes gated behind mxfs.dirwr)
PASS: mkfs_timing, chk_clean, dkms_install, online_resize, cluster_ops_timing,
wedged_unmount, online_membership, dmesg_clean, cache_caps, posix_semantics_single,
**cache_coherency (4/4 — the old long-standing blocker now PASSES)**,
strong_consistency, crash_consistency, single_node_paired, scaling_curve (147%, barely under 150%).

**FAIL (real, were stale-PASS before):**
- **zero_silent_loss**: total_fs_silent=1600 iters_with_loss=1/3 completed=0/3. iter1 "node0 find returned non-numeric"=loss; iters 2-3 INFRA FAIL "teardown test1 FAILED — mount/module still live, refusing to mkfs" (test1 wedged).
- **fence_during_write**: lost=400 — test2(claimed=200,visible=0) test4(claimed=200,visible=0). Survivor cannot see fenced peers' acked writes.
- **rsync_paired**: ratio=148% (threshold ≤120%; was 113%). Perf regression / RULE 0.
- **posix_semantics_multi16**: pending at handoff (test1 wedging → likely FAIL).

## DOMINANT ROOT (test1 repeatedly wedges under 16-node load) — ino=128 root-dir DLM EX self-deadlock
test1 dmesg signature (recurs, forces VM restart — D-state `mxfs-ino-bast/sda` kworker, unkillable):
```
DLM inode lock failed: ino=128 mode=5 rc=-35   (-EDEADLK)
P138-WAIT ino=128 mode=5 elapsed_ms=2095
P34D-RELOAD-FRESHSRC ino=128 ... protected buffer; adopting coherent on-disk dinode
P112-IFLUSH-CALLER ino=128 set IFLUSHING caller=mxfs_inode_cluster_durable+0x82 <- mxfs_dlm_dir_inode_durable+0x4e
SESS50-STARVE ino=128 our_mode=5(EX) waiter_mode=3(PR) waiters=9bce waiters_ex=0 h_ex=1 h_pr=0 gen=4051
mxfs: DLM shutting down
```
ino=128 = **root dir inode** (sb_rootino) — all 16 nodes hammer it (creates/removes/atime under /mnt/shared subdirs).
Mechanism: test1 holds ino=128 EX; peer BASTs; release path `mxfs_dlm_dir_inode_durable -> mxfs_inode_cluster_durable` (xfs_mxfs_dlm.c:733/864) sets IFLUSHING via iflush_cluster (which loops ≤8x on pincount>0 / trapped shared-cluster buffer, NOT a DLM lock itself). Concurrently another thread acquires ino=128 EX (mode=5) -> **rc=-35 EDEADLK** while 9 peers starve for SHARED -> shutdown. Related: sess115 iflush_cluster wedge, [[sess123-caw-ex-starvation-gemini-fairness-design]], [[sess48-phantom-ex-waiter-bit-leak-rootfix]].

OPEN QUESTION (next): did sess56's A1F53770 (forced dir-EX reload on MXFS_IF_DIR_RELOAD, xfs_mxfs_dlm.c ~L5429) REGRESS this by forcing extra EX acquires on the hot root inode? Compare against the build the 2026-06-12 PASSes came from. Per RULE 4, instrument before concluding.

## Infra note
test1 is the recurring wedge victim (slot 0 / preferred AG 0 / root-inode home). When teardown fails "mount/module still live", recover via `virsh -c qemu:///system destroy test1 && virsh -c qemu:///system start test1` (allowed; only clyde host is protected). The earlier harsh repro (rm-rf storm) ALSO wedged test1 via xfs_remove trans_cancel — distinct AGI/remove path, secondary.

## Repro
A single clean round of 16x20-file concurrent same-dir create + self-stat PASSES; failure needs accumulated multi-test load. The faithful fast repro path is the criterion itself. test_rename_visibility (in posix16) fails 80/960 asserts = node loses its OWN just-created dirents after rv_create barrier (mv ENOENT on own source) — dir lost-update, same family as zero_silent_loss dirent loss.
