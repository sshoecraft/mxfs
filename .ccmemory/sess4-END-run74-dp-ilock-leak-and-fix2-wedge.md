---
name: sess4-END-run74-dp-ilock-leak-and-fix2-wedge
description: sess4 END: run72/73 drc 8/tcp PASS ×2 (build 75F70CA40), run74 FAIL = dp-ILOCK write-hold LEAKED by exited create (pid gone) + FIX-2 loop stuck in dr…
metadata:
  type: project
---

# sess4 (a9a03929) END-of-session state — build `75F70CA401646F3BE5327AF`

READ WITH [[sess4-TWO-ROOT-FIXES-nest-deadlock-preunlock-audit]] (the two fixes + probe inventory).

## Ladder: run72 PASS, run73 PASS (consecutive ×2), run74 FAIL 0/8 @ round 7

## run74 root (NOT yet fixed) — leaked dir ILOCK write-hold by an exited create

- test3 (node_id 791468612) held dir ino=131 EX **417s** (master dump P-LKTIMEOUT-HOLDER held_ms=416901, 7 peers queued; peers' creates errored EIO after retry exhaustion — test2 bash printed "Input/output error").
- On test3: `P132-ILOCK-STUCK ino=131 cnt=-510 wr_last=xfs_create+0x4e1 pid=2747` every 30s from 150s→440s+. **pid 2747 (bash) EXITED — /proc gone — while the dir's XFS i_lock rwsem stayed WRITE-HELD** (down_read_trylock fails forever ⇒ genuinely write-owned, not just waiter-flagged).
- The bast kworker (dir release) is stuck: `mxfs_dlm_bast_process+0x1d22 → mxfs_drain_ilock_read → msleep` — **this offset is likely INSIDE my FIX-2 enforcing P3B loop**, whose first step each iteration is mxfs_drain_ilock_read(ip); drain_ilock_read retries internally FOREVER (its own msleep loop prints P132), so the FIX-2 try-counter (5000×) NEVER advances and its shutdown backstop never fires → release holds the dir EX forever → cluster convoy. **FIX-2 needs a bounded drain_ilock_read (or skip-degrade after N ms so its own bound governs).**
- 139.978 `DLM inode lock failed: ino=131 mode=5 rc=-35` (v5_mount.c:1331, EDEADLK, caller unknown — print has no comm) 9ms before FIX-2's P3B try=0/try=1 (which CONVERGED fine at 139.99-140.01). P79 fired ZERO times in run74 (FIX-1 not involved). No P-CR3-CANCEL / P-CREATE-ERR1 / P-CR62 / P-DIALLOC prints on test3 in the window ⇒ 2747's create did NOT exit via out_trans_cancel or the err1 path (both print), and the normal-success path unlocks dp at xfs_inode.c:1943, out_* tail honors unlock_dp_on_error at 2135. **Open question: which path leaks the write-hold.** Note wr_last only records mxfs_ilk_note_lock callers — xfs_ilock (line 230) and xfs_ilock_nowait (327) both note; a leak via a note-skipping taker would leave wr_last stale — but cnt=-510 is definitive that SOMEONE write-holds.
- Candidate paths to audit next: xfs_create's EEXIST-loser commit branch (unlocks at 1646 ✓), the icreate-fail (1703→cancel prints ✓ absent), **paths that xfs_ilock(dp) then return WITHOUT the unlock_dp_on_error flag having been set/honored — including any early `return` between 1487 and the joins**, and xfs_lock_two_inodes/xfs_dir helpers that take dp EXCL at create+0x4e1... ALSO check whether `xfs_ilock(dp, XFS_ILOCK_EXCL|XFS_ILOCK_PARENT)` + error + `xfs_iunlock(dp, XFS_ILOCK_EXCL)` is symmetric (it is — PARENT is lockdep-only).
- ALSO open from run74: what called the EDEADLK'd EX at 139.978 (v5-level print, no comm) — candidates: publish_drain_loop (P78 would print — check), __mxfs_dlm_dir_inode_durable, xfs_inactive direct EX.

## Next steps (exact)
1. Fix FIX-2's unbounded drain_ilock_read (bounded variant / own timeout), so a leaked ILOCK degrades to the 10s shutdown instead of a 400s cluster hang.
2. Root-cause + fix the dp-ILOCK leak (instrument: on xfs_create's every return path when unlock_dp_on_error==true assert/print; or a capped probe in mxfs_ilk_note_unlock asymmetry — simplest: P-CREATE-EXIT print (error, unlock_dp_on_error) at out_release_dquots + the return-0 path... better: find callers of xfs_ilock(dp) in create that can return early).
3. Re-run drc 8/tcp to 5 consecutive PASS (currently best streak 2: run72/73).
4. Then full `./run.sh N tcp` N∈{8,4,2,1} on the final build (ALL old criteria.json PASSes predate the sess3/4 fixes).
5. Marker only after all four conditions pass.

## Infra notes
- Per-run cycle: virsh destroy×8 → start×8 → SSH-ready ~30-36s → `timeout -k 15 700 ./run.sh 8 tcp dir_reuse_coherency` detached + foreground poll (~450s healthy PASS).
- Console capture NOT restarted for run74 (was for 71-73) — restart per cycle: `nohup tests/suite/console_capture.sh start DIR 8 > log 2>&1 < /dev/null &`.
- run74 artifacts: /tmp/claude-1000/-src-mxfs/a582dc32-abe3-4e0e-aff1-32adbe8525f4/scratchpad/run74/test*.dmesg; test3 cluster still up in wedged post-run state (useful for live inspection if not yet cycled).
