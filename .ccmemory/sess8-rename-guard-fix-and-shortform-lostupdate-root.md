---
name: sess8-rename-guard-fix-and-shortform-lostupdate-root
description: sess8 (2/tcp): FIX rename dirty-cancel shutdown via pre-dirty revalidate in xfs_rename (build E143DF7B); remaining = shortform-dir last-committer los…
metadata:
  type: project
---

## STATE after sess8: 2/tcp = 14-15/16, NO shutdown cascade. Build E143DF7B7A2717564D68C65 (local; deploy via reboot+run.sh, picks up /mnt/mxfs-src/mxfs.ko). Marker NOT written.

## FIX 1 (KEEP, build E143DF7B) — xfs_rename dirty-trans-cancel SHUTDOWN eliminated.
PROVEN root (full-suite run, call trace): `xfs_trans_cancel at xfs_rename+0x90b ... Corruption of
in-memory data (0x8)` FS SHUTDOWN. Mechanism: in `xfs_dir_rename_children` (libxfs/xfs_dir2.c
~1550) the TARGET `xfs_dir_createname/replace` DIRTIES the txn, then the SOURCE
`xfs_dir_removename` (~1647) returns -ENOENT (peer durably erased the src dirent) → returns error →
xfs_rename `goto out_trans_cancel` → cancel of a DIRTY txn = shutdown. This SHUTDOWN cascaded:
every test after dlm_fairness FAILed on the dead mount (1/16 → looked like 6/16).
FIX: added the SAME pre-dirty revalidate `xfs_remove` already had (xfs_inode.c ~3481) to
`xfs_rename` (xfs_inode.c, right after the `mxfs_dlm_dir_modify_refresh(src_dp)` calls ~3869):
multi-node only, `xfs_dir_lookup_locked(tp, src_dp, src_name, &cur)`; if -ENOENT or cur!=src_ip
→ clean-abort `error=-ENOENT; goto out_trans_cancel` (txn still CLEAN, no shutdown). Also revalidates
target for RENAME_EXCHANGE. Logs `RENAME-REVALIDATE-MISS`. RESULT: dlm_fairness no longer shuts
down; full suite went from cascade-to-6/16 to a clean 14-15/16 with only BENIGN failures.

## REMAINING BLOCKER — shortform-dir last-committer lost-update (the rotating benign failure).
After FIX1, full-suite fails ~1-2 of {dlm_fairness, tcp_dlm_scaling, crash_consistency,
cache_coherency} per run with BENIGN `shared dir drained got=1` (stray dirent) / `cc total durable
file count exp=100 got=98` (2 missing dirents). NO shutdown, both nodes stay mounted. Failures ROTATE
(run1: crash_consistency; run2: dlm_fairness+tcp_dlm_scaling). Reproduces STANDALONE ~1/6 via
`MXFS_EXTRA_MODARGS=dirwr=1 ./run.sh 2 tcp dlm_fairness` (loop, reboot first).

### PROVEN mechanism (dirwr=1 dmesg, dir ino=131 .dlm_fairness is SHORTFORM dp_fmt=1):
Leftover `n1_r10` (ino 8388736) visible on test2, GONE on test1. test1 created n1_r10, then
`RENAME-REVALIDATE-MISS src=n1_r10 lookup_rc=-2` — node1 LOST ITS OWN just-created dirent after a
DLM lock round-trip (last-committer / SELF-REVERT lost-update, P-SFDIR-REVERT family sess84/85).
Mechanism: node1 creates n1_r10 (in-core shortform), RELEASES dir-inode DLM lock BEFORE its create
is durable on the LUN; node2 acquires, reloads dinode (plain-bio = SCST/LIO write-cache coherence
point, mxfs_fua_disable=1), modifies+commits a base LACKING n1_r10 → durably; node1 reacquires,
reloads dinode → loses its own n1_r10. For SHORTFORM dirs the WHOLE dir-DATA-block machinery
(mxfs_dlm_dir_modify_refresh evict, mxfs_dlm_dir_durable_signal flush, release-drain
mxfs_dir_flush_data_blocks) is a NO-OP (dirents are inline in the dinode, no data blocks) — coherency
depends ENTIRELY on (a) writer dinode durable-on-LUN before dir-inode lock release [invariant #1 inode
drain] + (b) reader dinode reload-on-acquire. The gap is (a): the dir-inode release is NOT making the
shortform dinode durable on the target before handoff.

### NEXT (RULE 4): find the dir-INODE BAST release path + confirm it does a synchronous inode drain
(log_force SYNC + mxfs_ail_drain_inode_to so the inode-cluster buffer is WRITTEN to the target) BEFORE
mxfs_v5_dlm release for a SHORTFORM dir. Reload path = xfs_mxfs_dlm.c ~5330-5720 (reads plain-bio when
fua_disable; P-SFDIR-RELOAD/REVERT probes). durable_signal (9658) is now PUBLISH-ONLY (sess97 flush
removed for perf) — fine for shortform (no data blocks) but means the inode drain on release is the
ONLY durability guarantee. Verify/strengthen it. Don't restore per-modify log_force in durable_signal
(busts rsync_paired RULE-0 budget). See [[sess-tcp-DLM-double-grant-FIXED-gen-token]] (prior remaining
= "intermittent dir-coherency"), [[sess84_lessons]] [[sess85_lessons]].
Fallback builds: E8BF16B2 (pre-rename-guard, 15/16 w/ shutdown cascade), 404BC55C (double-grant fix).
</body>
