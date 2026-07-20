---
name: sess127-shared-dir-create-starvation-after-removing-harmful-stale-flag
description: sess127: removed sess126's harmful i_dlm_stale-on-parent (stuck-stale thrash); root shifted to concurrent shared-dir create EX-starvation (120s holds…
metadata:
  type: project
---

## sess127 (ccloop run 14d31183) — cache_coherency / test_unlink_visibility

Build progression this session: **104BEBA0** (sess126, tested→FAIL) → **A583257879B28DDE7AD2633** (removed harmful Phase-1; tested→still FAIL but root moved).

### RULE 4 finding #1 (PROVEN): sess126 Phase-1 (`dp->i_dlm_stale=true` on EEXIST) was HARMFUL + UNNECESSARY
- Deployed 104BEBA0 on clean-power-cycled 4-node cluster. test_unlink_visibility FAIL, 6m22s. ALL nodes' `echo > $TESTDIR/nodeN_fileM` failed ENOENT (node logs line 21).
- Decisive dmesg (test1, echo window t=57.8–58.6): **8× P-DREVAL-STALEFLAG ino=131 name=.mxfs_test, ZERO P-VNLOOKUP**. The path-walk hit d_revalidate(.mxfs_test) → returned INVALID every time (i_dlm_stale=1, never cleared — no reload fired to clear it) → walk died at the PARENT component, never reached the `unlink_visibility` child lookup. = the sess91 stuck-stale d_revalidate thrash, REINTRODUCED by sess126's fix.
- The premise was FALSE: the loser's own mkdir acquires parent 131 **ILOCK_EXCL** (forcing winner release) and reloads it fresh — P-SFDIR-RELOAD at t=57.8 already shows `names=[test_unlin unlink_vis]`. Parent is coherent WITHOUT the flag.
- FIX: removed `dp->i_dlm_stale = true;` from xfs/xfs_inode.c EEXIST loser branch (`if lrc==0`), replaced with probe `P127-EEXIST-LOSER`. Kept sess126 Phase-2 (dirs skip affine fast-path in mxfs_drevalidate). Build A5832578.
- Re-test: 2m22s (thrash gone), walk NOW reaches child lookup (P-VNLOOKUP unlink_visibility present), test2/test3 each created 8 files. But test1/test4 created 0. Root MOVED.

### RULE 4 finding #2 (root now): concurrent shared-dir create EX-STARVATION
- All 4 nodes create 30 files EACH into ONE shared dir `unlink_visibility` (ino 2097281, in a peer's affine AG). Classic shared-disk-FS hot-directory contention.
- test1: **acquired 2097281 EX at t=1020.847 (P106-EXGRANT) and held it 121s** (P-DIR-SEQ REL at t=1142.020) — NO P-GENCREATE for any node1_file in that window (create never reached xfs_generic_create; blocked in path-walk resolution of the shared dir).
- SESS50-STARVE fires on 2097281 (test2 ×10, test3 ×4): `our_mode=3 waiter_mode=5 h_pr=1` = PR holders starve the EX writer. The sess126 Phase-2 coordinated d_revalidate takes ILOCK_SHARED(PR) on the dir on EVERY path-walk into it → 4 nodes walking in to create files generate a PR storm that starves create-EX → 120s stalls → barrier timeouts.
- Likely compounding: XFS allocates a child inode in the PARENT dir's AG (locality). 2097281 is in a PEER's affine AG, so each create's dialloc wants a peer-owned AG lock → cross-AG CAW poll (the "ILOCK held across CAW poll" tension) while holding the dir EX.

### OPEN QUESTION for GPT (RULE 5 — 2 Gemini consults already spent in sess126 on this issue cluster)
How to make N-node concurrent file creation into a single SHARED directory complete promptly (no 120s stalls) on a CAW disk-based PR/EX DLM. Candidate directions: (a) EX-writer anti-starvation / PR-defer on hot dirs (extend sess50 defer_for_waiter); (b) reduce d_revalidate PR traffic on the shared dir (cache the coordinated result / gen-gate so repeat walks don't re-PR); (c) child-inode allocation affinity to the CREATING node's AG, not the parent dir's AG, for shared dirs.

### Current ship state: cache_coherency RED. Marker NOT written. Build A5832578 on dev host + deployed on all 4.
Related: [[sess126-mkdir-race-loser-cannot-create-poslx-root]] [[sess50_lessons]] [[sess91_lessons]] [[feedback_timing_is_first_class]]
