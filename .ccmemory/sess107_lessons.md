---
name: sess107_lessons
description: sess107 — ROOT PROVEN: stale-cached-EX = deferred-publish never publishes shared inodes (unpublished=no slot→peer acquires w/o BAST). Backstop fix (b…
metadata:
  type: project
---

# sess107 (2026-06-06, ccloop run 29df431e)

Continues sess106. Builds: `B64499C5` (probe) → `0DB3BA32` (backstop FIX, current deployed).

## ROOT CAUSE — FULLY PROVEN (RULE 4 + code trace)
rename_visibility lost-update + inobt/defer corruption = the **deferred-publish design gap**.
`mxfs_dlm_grant_local_new` (xfs_mxfs_dlm.c:4010, called from xfs_icache.c:1114 on
IGET_CREATE) grants a new inode EX **locally only** (i_dlm_mode=EX, state=CACHED,
i_dlm_unpublished=true, on m_mxfs_unpub_list) with **NO on-disk CAW slot**. Publish
(`mxfs_dlm_publish_unpublished`, acquires real slots) is triggered ONLY by an incoming
BAST (inode bast_notify:2077, AG bast:7066). FLAW: an unpublished inode has no on-disk
slot, so a peer reaching it (e.g. via a cached parent dirent → .mxfs_test ino131) acquires
the empty slot CLEANLY and **never BASTs the creator** → publish never fires → both nodes
hold EX → concurrent dir-block RMW → durable lost-update + (escalates to) inobt-AG4 /
xfs_defer_finish_noroll corruption shutdown.

## STEP 1 PROVEN (probe B64499C5): added `mxfs_v5_dlm_inode_held(ctx,ino)` (v5_mount.c, mirrors
ag_held→caw_held) + header. At dir-EX fast-path cache-hit logged `P106-STALE-EX
on_disk_held=0 cached_mode=EX` — fired repeatedly. Confirms in-memory EX w/o on-disk slot.
(NOTE: also fires for legit brand-new inodes that were never on-disk-locked = same
unpublished mechanism, not a separate bug.)

## STEP 2 FIX (build 0DB3BA32, RULE 5 Gemini design D = A+B). KEEP (partial win).
Implemented the **fast-path BACKSTOP (B)** only so far:
1. xfs_mxfs_dlm.c ~3286 fall-through condition: a dir at `pin_count==0` now falls to slow
   path when `state!=CACHED` **OR `(i_dlm_unpublished && mode==EX)`** — forces a real
   on-disk EX acquire before modifying an unpublished dir.
2. Slow-path acquire (~3600): if `i_dlm_unpublished`, `mxfs_dlm_unpublish_drop(ip)` (list
   hygiene) + `P107-PUBLISH` log, then ALWAYS do the real acquire. Safe because
   caw_lock "already held" path (dlm_caw.c:1413) returns success / self-heals — NOT a
   shutdown — so a racing publish_unpublished can't cause double-acquire shutdown, and we
   never proceed before on-disk EX is confirmed (avoided a skip-race).
Gemini pin==0 ⇒ no AGF held ⇒ blocking CAW acquire can't ABBA-deadlock.

## RESULT (cross_visibility PASS, rename_visibility still FAIL)
- **Corruption shutdowns ELIMINATED**: NO inobt-AG4, NO defer_finish, NO "Shutting down"
  (previous probe run had all three). Big win — broken mutual exclusion was the corruption
  driver.
- **P107-PUBLISH fired** 1-4×/node (backstop engaging, publishing on-disk).
- **P106-STALE-EX still fires 29× on test1** (0 on test2/3/4) → RESIDUAL stale-cached-EX NOT
  covered by the backstop. Hypotheses for next session (RULE 4 — instrument to pick):
  (a) unpublished inodes hit at **pin>0** (my gate excludes them) or **mode==PR**;
  (b) genuinely non-unpublished stale (sess106's "released slot but kept i_dlm_mode=EX" —
      a real release path leaving mode stale); 
  (c) the residual is on test1 only → maybe a node-role asymmetry.

## NEXT SESSION
1. Find what the 29 test1 STALE-EX inodes ARE: add to the P106-STALE-EX probe a dump of
   `i_dlm_unpublished` + `pin_count` so we know if they're (a) or (b). That decides whether
   to widen the backstop (drop the mode==EX/pin==0 gate, or cover PR) or hunt a release path.
2. Implement Gemini Part A (proactive post-commit publish in xfs_create/xfs_mkdir/symlink/
   mknod after xfs_trans_commit, before xfs_irele: if i_dlm_unpublished → real acquire) to
   close the background-AIL/reclaim hole and reduce per-op backstop slow-paths.
3. Re-run rename_visibility; then unlink_visibility + cross_write_read; then full
   cache_coherency criterion. Watch corruption stays gone + rename→0.
- Reload-clobber risk (backstop slow-path reloads disk for unpublished inode that might be
  our own non-durable create) did NOT manifest this run, but watch for it.

## INFRA (cost cycles)
`tools/mxfs_sshpass.sh <host> <PASSFILE=/tmp/.mxfs_pass> <cmd>` — THREE args. 2-arg call =
ssh password-prompt HANG (looks like all nodes wedged; they're fine). Don't over-spawn
concurrent ssh to one node. Full clean cycle: virsh destroy+start all 4 → wait ssh →
reset4.sh 4 → dmesg -C per node → run. Build/probe: always `strings mxfs.ko | grep <tag>`.
