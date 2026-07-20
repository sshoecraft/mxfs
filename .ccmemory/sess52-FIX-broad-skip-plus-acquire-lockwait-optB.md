---
name: sess52-FIX-broad-skip-plus-acquire-lockwait-optB
description: sess52 HEAD: build D67776EC = option B (broad-skip+acq-wait) + TWO freed-reuse-dir reload guards (P52). C16AAEAC was 3/5, CE9B0FD4(+1 guard) was 3/4…
metadata:
  type: project
---

## sess52 HEAD — build D67776EC (NOT yet deployed/tested at relay)

### What ships (all KEEP, in build order):
1. **Option B** (xfs_mxfs_dlm.c): broad release-skip `dir_pr_release_fast=2` (existing param) +
   NEW acquire-side LOCKED-block bounded-wait `mxfs_dir_acq_lockwait=60` (~3605 in
   mxfs_dir_drain_evict_data_blocks). FIXES the tcp_dlm_scaling PR->EX upgrade LIVELOCK +
   dir_reuse SLOWNESS. Pass via `MXFS_EXTRA_MODARGS='dir_pr_release_fast=2 dir_acq_lockwait=60'`.
   Build C16AAEAC alone = **3/5** reliable (runs 2,3 failed on the DABUF corruption, NOT livelock).
2. **P52-RELOAD-FREEDREUSE-DIR-SKIP** (xfs_mxfs_dlm.c ~6841, before the sess116 P116 guard): in the
   inode reload, if the RAW cached buffer `dip` reads FREE (di_mode S_IFMT==0) for a live in-core
   S_ISDIR with a DIFFERENT di_gen -> keep in-core, don't adopt. Build CE9B0FD4 = **3/4** (runs 1-3
   17/17; run-4 FAIL).
3. **P52-FRESHSRC-FREEDREUSE-DIR-SKIP** (xfs_mxfs_dlm.c ~7295, inside the P34D FUA-fresh adopt block):
   run-4 PROVED the corrupting adopt is the **P34D FUA-read `fresh` image**, NOT the raw `dip` (guard
   2 checked the wrong image — raw dip matched in-core gen, fresh was the freed incarnation). So guard
   3 skips `memcpy(snap, fdip, ...)` when fdip reads FREE (mode S_IFMT==0) for a live dir with gen
   mismatch, keeping the protected cached buffer. **Build D67776EC.** Guards 2+3 are complementary
   (raw-buffer path + FUA-fresh path).

### THE BUG (single residual, multiple faces): dir-inode FORK REVERT -> {di_format=EXTENTS/BTREE, nx=0,
size>0} invalid state -> xfs_create/xfs_remove maps a dir block -> xfs_dabuf_map !HOLE_OK (xfs_da_btree.c:2814)
-> EFSCORRUPTED -> DIRTY xfs_trans_cancel -> `Corruption of in-memory data (0x8) Shutting down` -> node1 FS
down -> cascade (whatever create/rm-heavy test runs then fails 0/2: fence_during_write, rsync_paired,
tcp_dlm_scaling, soak...). Run-2/4 sub-case = GEN-MISMATCH freed-reuse reload adopting a freed
different-incarnation image (P-RELOAD-IOPS-REWIRE new_mode=00) — the P52 guards target this. Run-3
sub-case = ROOT dir ino=128 SAME-incarnation revert via P32-IFLUSH-NXSHRINK (no reload signature;
likely sess32/33 legit-conversion leaf-vs-data tear) — **NOT yet addressed** by P52.

### NEXT SESSION (cluster is CLEAN, idle; build D67776EC on local /src/mxfs/mxfs.ko, NOT deployed):
1. DEPLOY+TEST: `rm -f /tmp/relrun_*.log /tmp/relrun_*.dmesg; setsid bash -c 'export MXFS_EXTRA_MODARGS="dir_pr_release_fast=2 dir_acq_lockwait=60"; exec bash /src/mxfs/tests/tcp/reliability_loop.sh 5 > /tmp/sess52_optB3.log 2>&1' </dev/null & disown` — watch /tmp/sess52_optB3.log; grep P52-FRESHSRC + P52-RELOAD on node dmesg to confirm guards fire. (reliability_loop.sh dumps /tmp/relrun_${r}_node{1,2}.dmesg on PARTIAL.)
2. If a PARTIAL run still shutdowns: read the failing node's dmesg for the DABUF inode's reload chain
   (P133/P34D/P62/IOPS-REWIRE/P32-NXSHRINK). If GEN-MISMATCH + P52 fired but still corrupted -> guard
   incomplete. If P32-IFLUSH-NXSHRINK with NO reload (run-3 root face) -> implement the GPT Step-4
   fork-flush fence in **xfs_iflush_cluster** (xfs_inode.c:5393 skip-loop, NOT xfs_iflush) +
   reload-reconcile, OR extend P33-DIRGROW-REVERT-SKIP (~6940) to keep in-core when i_dlm_mode==EX
   even if clean (under EX disk can't be legit-smaller). See [[sess52-residual-is-dir-fork-revert-DABUF-shutdown-cascade]] + [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]].
3. If 5/5: make dir_pr_release_fast=2 (flip `int mxfs_dir_pr_release_fast = 1;` -> 2, xfs_mxfs_dlm.c
   3876) the DEFAULT (keep dir_acq_lockwait=60 default), rebuild, re-run reliability loop with PLAIN
   `./run.sh 2 tcp` (NO modargs), confirm reliably 17/17, THEN `echo YES > .ccloop/runs/8ddb16a2-.../criteria-met`.

Criterion = full `./run.sh 2 tcp` reliably 17/17. Marker NOT written.
Related: [[sess52-residual-is-dir-fork-revert-DABUF-shutdown-cascade]] [[sess51-FIX-narrowed-self-demote-durability-skip-17of17]]
