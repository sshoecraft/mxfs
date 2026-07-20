---
name: sess16run-FIXL2-dir-dlm-phaseA-before-rwsems
description: sess16 FIX-L2 (CC3B3372): k1 tds ABBA = rename blocked in dir PR→EX conv holding child ILOCK → child unflushable → AG-4 drain stall 312s. Fix: GFS2 P…
metadata:
  type: project
---

# FIX-L2 — dir DLM grants Phase-A (before any rwsem) in the lock-set paths

## The k1 wedge (2/tcp, build F7A60942, iter2_k1: tds 0/2)
- test2 rank2: **0 rounds in 61s** (first create blocked then errored);
  test1 rank1: 150 rounds in 67.9s (>60 window).
- test2 blocked on **AG-4 EX**: `P-LKTIMEOUT-HOLDER type=3(AG) ag=4
  holder=test1 hstate=GRANTED held_ms=312065` — test1 held AG-4 since t≈57
  (5 min before tds; cached by design).
- test1 blocked on **dir 8530875 PR→EX conversion**: `P-CONVBLK-DENY
  held_mode=PR req_mode=EX deny→EDEADLK` from test2 + `DLM inode lock
  failed rc=-35` retry storm.
- test1's AG-4 BAST **did** run its drain but stalled 63s+:
  `P67-AG-BAST-STALL ag=4` loop, `stuck_ino=8529046 iflags=0x20040
  (EOFBLOCKS_RELEASED|sess118-neverflushed) pin=0 buf_locked=0
  ili_fields=0x1 in_ail=1` — resolved the INSTANT the rename finished.
- Root: `xfs_lock_inodes` sorts ascending → child 8529046 ILOCKed BEFORE
  dir 8530875; the sess58 arm then did **blocking** `mxfs_dlm_ilock_begin
  (dir, EX)` with the child rwsem held; `xfs_iflush_cluster` REQUIRES
  `xfs_ilock_nowait(SHARED)` (P129-CLSKIP why=ILOCK_NOWAIT_FAIL probe
  exists there, prints rwsem owner comm) → child unflushable → AG drain
  stalls → peer starves → cross-node ABBA (dir↔AG).

## FIX-L1 (REVERTED — do not retry): try + bare begin/end + goto-retry
livelocked: with zero holders the pending peer BAST fires INLINE in
ilock_end and forfeits the grant instantly → nodes ping-pong the grant,
nobody completes a set.  2/tcp L1: `rm` 184s rc=-110 → force shutdown →
12-test cascade.  **A dir grant can only be kept across a retry by
HOLDING it (ex_holders≥1).**

## FIX-L2 (build CC3B3372) — GFS2 pattern, both set-lock functions
`xfs_lock_inodes` + `xfs_lock_two_inodes` (xfs/xfs_inode.c):
- Phase A: for every EXCL-mode DIRECTORY in the set, ascending,
  `mxfs_dlm_ilock_begin(ip, EX)` BEFORE any rwsem — blocking cross-node
  waits happen with nothing locked locally (everything stays flushable).
  Hold persists (dlm_pre[i]/pre0/pre1) until the caller's xfs_iunlock
  (which unconditionally calls ilock_end — exactly one hold per inode).
- Phase B: pre-held dirs take rwsems via xfs_ilock_nowait ONLY (xfs_ilock
  would double-hold); backoff releases their rwsem RAW
  (`mxfs_ilk_note_unlock` + `up_write(&ip->i_lock)`) so the DLM hold
  survives the retry.  Non-dirs unchanged (blocking xfs_ilock, or the
  sess58 nowait-no-DLM arm when try_lock).
- Global lock order now: dir grants (ascending) before ANY rwsem before
  child DLM (inside xfs_ilock) — uniform across nodes → acyclic.
- SHARED-mode dir in two_inodes (ip1_dlm=PR) keeps the old sess58 arm
  (blocking begin(PR) with ip0 rwsem held) — narrower hazard, untouched.

## Validation so far (CC3B3372 = 0F1666F1 + FIX-K + P16-ILOCKED probe + L2)
- tds standalone 2/tcp: 3/3 PASS (plus 4/4 on the flawed L1 build, 6/6 on K).
- paired: 101% PASS (no rename-path perf regression).
- 2/tcp suites: L2 16/17 (dir_reuse_coherency 0/2: `mxfs-drc-FAIL round=2
  rank=2 readdir=197 exp=200 lookup_fail=0 missing=[]` — getdents
  undercount, lookups all fine; known drc flake family, 1-of-3), L3 17/17,
  L4 17/17.  4/tcp: 17/17.  8/tcp L1 in flight.
- Probes armed: P16-ILOCKED (`ilocked=` in P67 AG-AIL-STALL line,
  xfs_trans_ail.c) + pre-existing P129-CLSKIP owner-comm.

## Watchlist
- drc readdir-undercount signature (197/200, missing=[]) — if it recurs on
  L2 builds, suspect the longer Phase-A dir-EX hold duration interacting
  with reader-side dir-block enumeration; start at xfs_dir2_readdir.c
  coherency gates.
- tds long-tail: r21 (0F1666F1 8/tcp) was REL-ABORT starvation flavor;
  k1 was the ABBA — two distinct mechanisms; L2 addresses the second.
