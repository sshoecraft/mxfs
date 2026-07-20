---
name: sess10run2-BREAKTHROUGH-clregress-owned-stale-dirty-ili-livelock
description: sess10 BREAKTHROUGH: P10-CLREGRESS 1630x on t1 (ds2 FAIL artifact 20260703T210920Z): OWNED dirty ili (ofields=0x3) holds EMPTY SF dir (buf_size=6) vs…
metadata:
  type: project
---

# sess10 breakthrough — CLREGRESS verdict

## Data (artifact /tmp/run_dlm_scaling_20260703T210920Z, build 89321B9D, relverify=1)
- FAIL face: node1 rate>=floor only (others PASS). t1 kernlog: **P10-CLREGRESS ×1630**, t2/t3/t4: 2/3/1.
- Every t1 line: `daddr=128 off=2048 disk_size=18 buf_size=6 disk_sfcnt=1 buf_sfcnt=0 owned=1 ofields=0x3 comm=kworker` @ ~20ms cadence for the whole test window.
- Read: the ROOT-region inode cluster slot (isize 512 → slot 4, ino≈132 — resolve exactly next session; likely `.dlm_scaling` or `.mxfs_barriers`-family dir created this run). test1's OWN inode-log-item at that slot is DIRTY (ILOG_CORE|ILOG_DDATA) with the EMPTY shortform (size 6) while the PLATTER holds the 1-entry image (size 18, presumably a peer's add flushed durably — transport proven clean earlier).
- Interpretation: **stale-dirty-ili livelock**: some write-side guard (P22-SFTORN-SKIP family / dirty_seq / P119?) keeps refusing to let the stale image flush → xfsaild retries forever → node1's op pace collapses (rate face). When no guard catches it (or before these guards), the stale image LANDS → the platter regression seen by P-SFDIR-REVERT (fua==disk==N-1) → quota-0/ENOENT + fence leaks + resurrection family.
- SFREVERT=0 in this artifact (the guard held; no adoption-revert happened).

## The question that root-causes everything
WHY does test1 hold a DIRTY ili whose SF content predates the peer's update?
Candidates (check in order):
1. test1 created the dir (mkdir commits empty SF, ili dirty) → EX handoff to peer: the release-side mxfs_inode_cluster_durable SHOULD flush+clean it. If the release path CONSUMED/kept ili_fields without the content landing (sess3 P22-SFTORN-SKIP recurrence — "flush_out CONSUMED ili_fields w/o writing"), ili stays dirty-with-old.
2. i_mxfs_dirty_seq/ex_grant_seq guard (xfs_inode.h ~159): dirty from a PREVIOUS EX tenure should be skipped as ghost — is THIS the guard producing the 1630 retries (skip → stays dirty → requeued)? If so the MISSING piece is: after skip, the ili must be CLEANED (its content superseded; keeping it dirty = livelock) — or the inode reloaded/adopted so ili content is current.
3. Re-dirty AFTER handoff without adoption: test1 re-acquired (PR/EX) and something logged the inode from a stale in-core copy (reload bail → i_dlm_stale left → op proceeded anyway?).

## Next steps (concrete)
1. ds2 loop (8×) may still be running/done — harvest ALL artifacts incl. more CLREGRESS shapes (owned=0 cases? quota-0 face?). ds2_loop.log in scratchpad 2eca429b.
2. Identify the exact guard emitting the skip for these 1630 writes: grep t1 kernlog around the CLREGRESS window for skip/warn lines (P22-SFTORN, P119, P-DIRTYSEQ names) — the guard's name pins mechanism 1 vs 2.
3. Resolve ino at daddr=128 off=2048 (slot 4): ino 132? check `ls -i` of /mnt/shared after a run or the P-SFDIR-REVERT ino in matching runs (8389057 ≠ this — different cluster! daddr 128 is ROOT cluster; 8389057 was AG-something — MULTIPLE dirs affected).
4. Fix per mechanism; then validate: ds standalone ×8 clean → full 4/tcp ×3 clean → 8/2/1 ladder.

## Session's fix-relevant inventory (all in tree, build 89321B9D)
watch_ino/watch_light probe scoping; P10-DIRDUMP/.mxfs_dirdump; P10-RDBLK; P-DIRWR watched+leaf-owner; P5D plat_act+trans; lastrel ledger (i_mxfs_lastrel_*) printed by P-SFDIR-REVERT; P10-CLREGRESS (pal xfs_buf.c, relverify-gated); run.sh FAIL kernlog capture; suite_cycle_run.sh (cycle+archive+test-filter+MXFS_WATCH_ARM); lib.sh watch hygiene. Transport exonerated (0/6000). Marker NOT written.
