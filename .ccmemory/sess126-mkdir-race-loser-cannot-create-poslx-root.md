---
name: sess126-mkdir-race-loser-cannot-create-poslx-root
description: sess126: cache_coherency unlink_visibility ROOT = mkdir-race LOSER can't create files (POSIX violation); fix = stale parent on EEXIST + dirs skip aff…
metadata:
  type: project
---

## sess126 (ccloop) — unlink_visibility TRUE ROOT: mkdir-race loser can't create into the winner dir

Build **104BEBA07BF8413358FE2EE** on dev host (NOT yet deployed/tested). cache_coherency still RED.

### PROVEN ROOT (RULE 4, decisive probes added this session)
test_unlink_visibility: 4 nodes each `mkdir -p .mxfs_test/unlink_visibility` then loop `echo > unlink_visibility/nodeN_fileM` (30 files), barrier, list (expect 120), delete own.

The 58–90 "missing" files were **NEVER CREATED** (not a dir-block lost-update — that was the wrong lead). Decisive evidence:
- `P-GENCREATE` (NEW probe, xfs_iops.c xfs_generic_create entry) + `P105-CREATE-PARENT`: the mkdir-race LOSERS (3 of 4 nodes this run) logged **ZERO** file creates reaching the FS. Their `echo > unlink_visibility/fileN` failed in VFS path-walk (parent component `unlink_visibility` → ENOENT) and never reached xfs_create.
- On-disk dir block peaks at 62 = winner's 30 + `.` + `..` ... ≈ 60 node-files + 2. (62 = the only node(s) that won.)
- `P106-STALE-EX`=0 → mutual exclusion intact (NOT a stale-EX bug). `P-IGET-ENOENT`=0 → NOT iget-free-state ENOENT.
- Timeline (node1 loser): mkdir EEXIST at t=55.95 (found `existing_ino`=winner under parent EX). echo-loop ran t≈56–57, all 30 failed. The async DIR_MODIFY signal for parent `.mxfs_test` (131) arrived at t=57.87; node1's reload of 131 showing `unlink_visibility` completed t=58.197 — AFTER the create-loop finished. First successful `P-VNLOOKUP unlink_visibility`→winner only at t=179 (delete phase).

### MECHANISM
Parent `.mxfs_test` (ino 131) is a SHORTFORM dir in node1's AFFINE AG, but a SHARED dir (all nodes add children). d_revalidate's **affine fast-path** (`P-DREVAL-AFFINE`) blesses any positive own-AG dentry valid with no coordinated re-lookup → node1 trusts its STALE cached 131 (missing the peer-winner's `unlink_visibility` child) between reloads. `mkdir -p` returns success (EEXIST) but the dir is not yet usable on the loser = **POSIX violation** (after mkdir returns, dir must exist). The loser HELD parent EX and SAW the winner during its own mkdir, but threw it away (only `d_drop`, no cache refresh) → async signal lost the race against the create-loop.

### FIX LANDED (build 104BEBA0; both per Gemini RULE-5 consult #2)
1. **Phase 1 — stale parent on EEXIST** (xfs/xfs_inode.c ~1275, `if (lrc==0)` loser branch): `dp->i_dlm_stale = true;` so the loser's next child path-walk reloads the parent from the durable peer-committed on-disk image instead of the stale cached shortform. (Gemini said do NOT d_instantiate the dentry to the winner on -EEXIST — VFS anti-pattern; and do NOT iget the winner inside the aborting create txn — pipeline-stall/deadlock risk. Invalidate-and-let-next-lookup-refetch is the safe path.)
2. **Phase 2 — dirs skip the affine fast-path** (pal/linux/xfs_super.c mxfs_drevalidate ~1935): added `!S_ISDIR(VFS_I(ip)->i_mode)` to the affine fast-path gate. DIR dentries now fall through to the coordinated lookup (ILOCK_SHARED → reload-if-stale), refreshing the shared dir's child list. Files keep the fast-path. Cheap under fua_disable=1.
Also still carried: **P-DREVAL-RESURRECT** (d_revalidate positive-dentry mode==0 winner-dir reload) — landed earlier this session but fired 0× (wrong manifestation; KEEP, harmless, targets sess125's variant).

### PROBES ADDED (keep for next test cycle)
- `P-GENCREATE dir_ino=.. pos=.. name=..` (xfs_iops.c, every multi-node create, BEFORE xfs_create) — shows if/where creates reach FS.
- `P-DREVAL-AFFINE` probe was REPLACED by the Phase-2 fix (removed).

### NEXT (RULE 4 — deploy + measure)
Power-cycle all 4 (virsh destroy+start) → `INSMOD_OPTS="fua_disable=1 instr=0" bash tests/reset4.sh 4` → verify srcversion 104BEBA0 + `dmesg -C` → run `MXFS_NODE_OFFSET=0 MXFS_TESTS_DIR=/src/mxfs/tests timeout 600 bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`. CHECK: every node's `P-GENCREATE _file` count == 30 (all losers now create), on-disk count→120, node1 actual=120. Watch for regressions (rename_visibility / cross_write_read timing — the affine-fast-path removal adds a coordinated lookup per dir access; should be cheap under fua_disable but VERIFY timing stays healthy ~2–6min). If losers STILL can't create, the i_dlm_stale flag isn't forcing a reload on the SHORTFORM parent — escalate: make the next lookup do a hard FUA reload of the shortform parent inode, OR (Gemini Phase-1 alt) call the exact internal fn the DIR_MODIFY async handler uses (mxfs_dlm_dir_modify_refresh / bump i_dlm_dir_gen) on dp before EEXIST return. If 2nd Gemini-class fix fails → escalate to ask_gpt (RULE 5 chain; 2 Gemini consults already done this session).

Related: [[sess125-shortform-parent-dir-lost-update-is-the-root]] [[sess114_lessons]] [[sess48_lessons]] [[feedback_timing_is_first_class]]
