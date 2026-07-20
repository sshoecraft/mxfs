---
name: sess5-END-abba-grow-stack-proven-design-next
description: sess5 END (build 1120BA0E): ABBA fully stack-proven — dir-grow btalloc blocks on peer AG w/ dirty trans+dir EX. Design: bounded/rotating AG acquire i…
metadata:
  type: project
---

# sess5 END — state @ build `1120BA0E3B136DE568FE01D` (deployed, in-tree)

READ FIRST: [[sess5-THREE-ROOT-FIXES-p5f-p91bast-abba-plus-remaining]] (fixes 1-3 + probe map + env cadence).

## Run ledger (8/tcp dir_reuse_coherency, timeout 595, reboot-before-each)
- run32 (dirwr): 17 rounds ALL CORRECT, pace-timeout (~30s/rd).
- run33 (default): ABBA @r15 → ag=4 -110 (test7) → shutdown → cascade FAIL. ~22-27s/rd before.
- run34 (default): NO shutdowns/-110; **r9 single durable dirent loss** (node3_f11.md5, 799/800 unanimous); pace-timeout @r20 (~27s/rd).
- run35 (dirwr): ABBA ino-side — test1 dd `ino=131 rc=-110` @t416 → shutdown. test1 held AG-0 t312→t418 (its dd's trans-deferred hold from dialloc) while test3 held ino-131 t354→t417 blocked on AG-0. test3's MHT sampled `P36-MHT-REARM ino=131 busy ex/pr` **130×/60s** = dir ILOCK held the whole wait ⇒ NOT dialloc.
- run36 (dirwr, cap-48 stacks): 18 rounds ALL CORRECT, pace-timeout. **19 trans_dirty=1 P1-AGWAIT stacks captured.**

## ABBA — FULLY PROVEN, both edges stack-named
Edge 1 (yieldable, FIXED by P5D): xfs_create → xfs_dialloc AG wait, trans CLEAN, dp ILOCK dropped (v0.3.148) but dp BAST trans-DEFERRED (ilock_end Approach-A) → P5D fires deferred inode BASTs pre-block. Verified run34.
Edge 2 (UNYIELDABLE, remaining): run36 stack: `xfs_dir_createname → xfs_dir2_leaf_addname → mxfs_dlm_grant_dir_epoch → xfs_dir2_grow_inode → xfs_da_grow_inode_int → xfs_bmapi_write → xfs_bmap_btalloc → xfs_alloc_vextent_start_ag → xfs_alloc_vextent_prepare_ag → mxfs_ag_dlm_lock` with **trans_dirty=1**, dir ILOCK+DLM-EX held (must be). Blocks up to 61s (dlm.c mxfs_dlm_lock 60×1.02s retry loop) on ONE peer-held AG. If that peer's create holds the AG (trans-deferred) while waiting for OUR dir → deadlock; loser -110s at 61s: AG side → `v5_mount.c:1595 DLM AG lock failed` → xfs_create dirty-cancel SHUTDOWN; ino side → `DLM inode lock failed ino=131 rc=-110` → ilock_begin is VOID, create proceeds UNSERIALIZED → EFSCORRUPTED → dirty-cancel SHUTDOWN.

## NEXT SESSION — fix design (Edge 2): bounded + rotating AG acquire for the grow/btalloc path
`xfs_alloc_vextent_start_ag` iterates AGs (wraps); first pass TRYLOCK (mxfs nb-probe, sess77), second pass BLOCKS on one AG for 61s. Fix: when `current->journal_info` trans is DIRTY (the unyieldable case), the blocking AG acquire must be BOUNDED (~4-8s) and on timeout return retryable so the vextent iteration ROTATES to the next AG (with 8 AGs and ≤2 nodes stuck on our dir, rotation finds a grantable AG fast; the cycle dissolves because we finish the grow and release the dir). Implementation options:
 (a) plumb a deadline into __mxfs_ag_dlm_lock (nonblock arg → tri-state or ms budget) used when journal_info dirty; on -ETIMEDOUT let xfs_alloc_vextent_prepare_ag/iterate_ags treat the AG as busy-skip (like trylock fail). CHECK: how prepare_ag maps errors; upstream iterate_ags continues on -EAGAIN w/ TRYLOCK only.
 (b) simpler: in __mxfs_ag_dlm_lock, if journal_info-dirty then ALWAYS use nb acquire + short internal retry loop (e.g. 40×100ms) instead of the dlm.c 60×1.02s blocking call, return -EAGAIN after → callers of btalloc path see busy AG and rotate (verify xfs_alloc_vextent_* retries/loops rather than ENOSPC-failing! If total failure → args->agbp NULL → xfs_bmap_btalloc may retry lowmode/return ENOSPC — must NOT corrupt).
 Also consider capping dlm.c retry loop param per-call via a new arg (mxfs_dlm_lock_bounded) instead of task flags.
- ALSO make ilock_begin -110 failure NON-SILENT: today the create proceeds unserialized → EFSCORRUPTED shutdown (run35 test1). At minimum propagate failure (ilock_begin void → needs an error path or a shutdown-free bail via the xfs_inode.c:1560 dialloc-orphan machinery).

## Blocker: pacing (26-30s/rd; need ≤20 for 480s budget; healthy ref 14s/rd)
- P36-RETRY 1.02s stalls sprinkle every round (~92/run on test1, run35). Each = one full ACQUIRE_WAIT_MS(1024ms?) timeout+re-request. sess35 fixed the 6s variant via POSTGRANT-BAST; residue: find why a dir handoff still needs a retry (grant delivered but pending already timed out? measure grant-latency distribution via P37-GRANT-RECV matched=0 count).
- Reference healthy build did 14s/rd — regression may partly be probe overhead + the P91-BAST-PROTECT skip changing invalidation patterns (more FUA re-reads later?). Measure per-phase (create/verify/rm) from DRCph markers.

## Blocker: rare durable dirent loss (run34 r9)
node3_f11.md5 P13-NADD @t276.03 daddr=10466208 aoff=1896 → GONE by t283.6 (P26-DSCAN-MISS scanned=801). t274.6-274.9: t4 adds @b_epoch=623, t3 @621, t2 **P46-GROW newdbno=4 @b_epoch=618 dirty=1 DIFFER** — divergent epoch bases on the same dbno=4; t2 materialized the block as new-grown from a 5-epoch-old base. Suspect P46-GROW/first-materialization missing epoch/tenure check (sess61/62 'tenure-cookie' family). Needs dirwr run that catches the loss (~1-in-2) then P35E-DIRWR/P50-WR ledger for the victim daddr.

## Criteria ladder (unchanged)
fix Edge-2 ABBA → pacing to ≤20s/rd → dirent-loss → 8/tcp ×5 consecutive clean → 4/2/1 regression → FULL `./run.sh N tcp` suites N∈{1,2,4,8} (sess49: criterion = full suite per N) → only then YES.

Cluster state at relay: 8 VMs up (build 1120BA0E loaded via run36), scratchpad runs 29-36 ledgers on host at /tmp/claude-1000/-src-mxfs/eb622727-4cd0-48e6-b4d0-116afe6eaa47/scratchpad/.
