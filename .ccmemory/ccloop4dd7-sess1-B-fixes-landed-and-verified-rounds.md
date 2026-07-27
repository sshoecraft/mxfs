---
name: ccloop4dd7-sess1-B-fixes-landed-and-verified-rounds
description: ccloop-4dd7 sess1 part B: 6 fixes landed (dead-shell defer+sanitize VERIFIED-rescue, own-free bypass, unleak, gen converge, zombie arm, busy-dup guar…
metadata:
  type: project
---

# ccloop-4dd7 sess1 part B — fix ladder + verification state (v0.11.46, build 13ABFACB)

Continues [[ccloop4dd7-sess1-dialloc-corruption-campaign-state]]. All builds deployed via
`MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster`; churn repro = `N1=test1 N2=test2
MXFS_PASS=/tmp/.mxfs_pass scripts/agi_wedge_repro.sh 180 24` (ONE per Bash call, ~230s;
batching 3 blows the 600s cap). Live capture per round into tests/logs/vmrig_dialloc_*Z/.

## Fix ladder (all in-tree, uncommitted; VERSION 0.11.41→0.11.46)
1. **v41 dead-shell defer+sanitize** (xfs_icache.c): P-CR63-DEADSHELL-DEFER (cache_hit,
   IRECLAIMABLE+nlink==0+CREATE skips check_free_state) + P-RECYCLE-SANITIZE in
   xfs_iget_recycle(,,deadshell_create) — disk-free ⇒ emulate missed local uninit (destroy
   forks, zero, adopt disk gen); disk-LIVE ⇒ P-CR63-DEFER-DISKLIVE + fail recycle (flows
   into existing re-add recovery).  **VERIFIED-RESCUE**: fired on both nodes across rounds
   (DEFER=1+SANITIZE=1 twice) — the exact pve chain (P-CR63-SHELL→GATE adopt=0→SANITIZE→
   create proceeds, P4L-ALLOC follows) with ZERO resulting corruption.  Pre-fix the same
   chain shut the FS down (ino 139 autopsy).
2. **v42 recycle-gate ordering guard** (xfs_icache.c P-RECYCLE-GATE): adopt only when
   (s32)(disk_gen - incore_gen) > 0 (was: any inequality — adopted OLDER images, proven
   ino 1862 resurrection).
3. **v42 P116 zombie arm** (xfs_mxfs_dlm.c): disk-free && disk_gen==incore+1 && !dirty ⇒
   P116-ZOMBIE-ADOPT (adopt freed image; truncate no-ops) instead of keep.  Fired 3× in
   clean round.  P116 skip print now includes gens.
4. **v42 P134-IDENTICAL-BUFSTALE probe** (reload_identical branch): coherent plain-read
   crosscheck vs the buffer image (reader-side stale-serve discriminator; 0 fires so far).
5. **v43 MX-REMOVE-DEADCHILD guard** (xfs_dir2.c non-dir branch, before removename):
   nlink==0 child ⇒ clean -ENOENT.  (Fires rarely; the -117 turned out to be xfs_iunlink,
   see 6.)
6. **v44 P2L-UNLEAK** (xfs_inode.c INACT skip): local_unlink && dlm_locked && skip ⇒ pull
   our own AGI unlinked-list insert in a standalone tr_ifree trans (mirrors ifree AG-DLM
   pattern).  Fired 895+/round, 0 failures.  **v45 SUPERSEDED for the main case by:**
7. **v45 P2L-OWNFREE bypass** (xfs_inode.c guard): disk_mode==0 && local_unlink &&
   dlm_locked ⇒ do NOT skip — proceed with the authorized free (difree frees the inobt
   alloc; iunlink_remove pulls our insert).  Root: unpublished reused create read
   disk-free (prior life's image) and was misclassified as peer-freed (ino 680 autopsy:
   test1 skip+unleak → test2's legit free found EMPTY bucket → P71-INSTR NULLAGINO head
   → -117 shutdown).  OWNFREE fired 270+266/round.
8. **v45 flag+gen hygiene**: MXFS_IF_LOCAL_UNLINK cleared at reset4create / SANITIZE /
   recycle-adopt (sess37 leak); reset4create adopts PLATTER gen via plain read (fallback
   ++) — kills multi-cycle gen drift (ino 680 showed 8-figure drift making +1-zombie
   undetectable).
9. **v46 P-BUSY-DUP guard** (xfs_extent_busy.c insert_list): EXACT-duplicate bno ⇒ log +
   bail (upstream ASSERT(0) no-op then *rbp never advances = INFINITE LOOP holding
   eb_lock — PROVEN 2-CPU soft-lockup: insert spins in-loop, xlog_cil_committed→
   busy_clear spins on lock; node wedges; peer's dir-131 DLM request times out 184s →
   "DLM inode lock unrecoverable rc=-110" → peer shuts down).  P-BUSY-OVERLAP ratelimited
   log for partial overlaps.

## Result trajectory (each churn round previously shut down a node in 45-180s)
- v45 round 1: **CLEAN** (first ever) — OWNFREE 270/266, UNLEAK 895, ZOMBIE 3, CORRUPT 0.
- v45 round 2: **CLEAN**.
- v45 round 3(contaminated by overlap w/ killed round): DLM 190s timeout → shutdown.
- v45 round 4 (clean load): test1 busy-tree INFINITE LOOP wedge (→fix 9) → test2 DLM
  timeout 184s → shutdown.  Root for the wedge = duplicate in-flight extent free.

## OPEN (next steps in order)
1. **Busy-dup ROOT**: who queues the same extent free twice in-flight on one node?
   P-BUSY-DUP/P-BUSY-OVERLAP now name the moment (comm; correlate realns with P3-EFREE-Q
   ino=/agbno= lines).  Suspects: hot-dir (ino 131) block free via STALE in-core extent
   map after handoff adopt (P63/P32-IFLUSH-NXSHRINK "extent-map revert" fired earlier);
   xfs_free_eofblocks on stale nlink=1 shells (NO multinode guard on that path!).
2. **DLM timeout escalation policy**: 184s dir-lock wait → whole-FS shutdown is RULE-0-
   hostile even when the peer wedged.  After busy-dup fix, re-evaluate; consider fencing/
   retry instead of shutdown (peer death must not cascade).
3. Dead-peer journal recovery ("Starting recovery (logdev: internal)" on survivor)
   tripped __xfs_dir3_data_check on the dead peer's half-written dir block → survivor
   ALSO dies.  = sess17 crash-consistency foreign-replay work (3 of 6 done).  Only fires
   after a peer death.
4. Full FIXED-AND-VERIFIED for task#1 still needs: N consecutive clean churn rounds on
   v0.11.46+ (target ≥5×180s) + deadshell_repro.sh 8/8 + a full `./run.sh 2 tcp` suite
   pass.  Then pve rig re-verify when hardware returns.
5. Un-updated awareness docs (Stop-hook nag): pal.md (xfs_buf.c P144), xfs.md (icache/
   ialloc/dir2/extent_busy changes) — update before session end.

## Watchouts
- pkill -f with a pattern that matches your own Bash command kills your own shell (exit
  144) — quote/anchor patterns or use pgrep-then-kill by pid.
- test VMs: open-iscsi was auto-logging-in to stale targets at boot, wedging boot for
  minutes + leaving pam_nologin banner that corrupts run.sh SSH parsing ("System is
  booting up...") → prep ABORT with mounted-anyway confusion.  FIXED durably:
  `systemctl disable --now open-iscsi iscsid` + rm /etc/iscsi/nodes/* on both (done
  2026-07-24; osimager-built replacements will need the same).
- After a VM wedge: virsh destroy/start test1 test2 + FORCE_PREP (mkfs) — the LUN may
  hold half-written state that trips the survivor's recovery (open #3).
- agi_wedge_repro exit 42 on escalation, 0 on clean; monitors SIG on BOTH nodes.
