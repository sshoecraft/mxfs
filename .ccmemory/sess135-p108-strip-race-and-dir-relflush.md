---
name: sess135-p108-strip-race-and-dir-relflush
description: sess135: P108 slot-loss ROOT = bast_notify inline cleanup-unlock CAS-strips fresh EX grant (FIXED 7E3AC2BF, P108 21→1); dir tear root = dir release i…
metadata:
  type: project
tags: [zero_silent_loss, P108, dlm-caw, dir-coherency, ccloop-14d31183]
---

# sess135 (ccloop run 14d31183, session 13) — two root causes, RULE-4 chains

## Context
zero_silent_loss dpn=100 storm, 16 nodes. Carried in build 5306E3F8 (bmbt lock-leak fix, VERIFIED: P133-BMBT-RELFLUSH fires up to 10×/node with NO wedge). Mass failure mode = dabuf-map HOLE on shared dir ino=131 → EFSCORRUPTED → 7-12 node shutdowns. P133-DIRINO-REVERT=0 (sess134 dinode-clobber fix HOLDS).

## ROOT 1 — P108 "on-disk slot lost" = bast_notify cleanup-unlock strip race (FIXED, VERIFIED)
Instrumentation: P135-SLOTWR (logs every successful CAW write for INODE ino≤256 in caw_slot, gen-ordered), P135-HELD-MISS (slot dump when held()==0), P135-INO-UNLOCK (caller %pS in mxfs_v5_dlm_inode_unlock).
Proof chain (test1 run p135c): P135-INO-UNLOCK caller=bast_notify+0x2ec @88.3794 → P106-EXGRANT @88.3806 → P135-SLOTWR hex=1→0 caller=caw_unlock @88.3814 → P108 @88.3821.
Mechanism: bast_notify NONE_mode_NL branch called mxfs_v5_dlm_inode_unlock INLINE (no serialization, no drain). caw_unlock's CAS-retry re-reads after miscompare and re-clears whatever appears — including a fresh EX grant CAS'd in by this node's own concurrent slow-path acquire. P108's forced reload then discards logged-not-durable dir growth → tear.
Refuted en route: duplicate-slot claim race (CAW-DUP-SLOT=0), slot repair false-positive (P-H22-REPAIR=0), dead-node purge (P-H22-PURGE=0), foreign-bit strip (P135-FOREIGN-STRIP=0).
FIX (build 7E3AC2BF): (a) bast_notify NONE/NL branch: held() check first (2441 stale-BAST cleanups/run now no-ops), genuine orphan → state=DEMOTING + queue i_dlm_bast_work (serialized, drains; P135-ORPHAN-RELEASE log); (b) caw_unlock early-exit without CAS when own bit absent from holders+waiters+yield_to (untrack_held on exit). VERIFIED: P108 21→1 cluster-wide.

## ROOT 2 — dir tear = release flush refused by P119 for dirs (FIX BUILT 9C2D4FA6, NOT TESTED)
With P108 gone, HOLEs persisted on ACQUIRERS: P106-EXGRANT @88.3687 → P-SFDIR-RELOAD nx=9 @88.3691 → HOLE @88.3701 inside next create. On-disk dinode lags on-disk dir data blocks: release drain flushes dir DATA+bmbt blocks durably, and the sess84 fall-through runs the deterministic iflush loop for dirs, BUT xfs_iflush_int refuses the copy-in at the P119 non-EX guard because MXFS_IF_DLM_RELFLUSH was set "Reg files only" (sess17). P119-NONEX-FLUSH-SKIP ino=131 observed in every release window.
FIX: set/clear MXFS_IF_DLM_RELFLUSH for S_ISDIR too (xfs_mxfs_dlm.c ~2553/2611). Build 9C2D4FA6 compiles clean; NOT yet deployed.

## NEXT
1. Deploy 9C2D4FA6 (cluster_reset_n.sh 16), run scripts/p133_storm_errcap.sh 100 (timeout 320). Expect: 0 HOLE, 0 shutdowns, P119-NONEX-FLUSH-SKIP ino=131 → 0 during releases, low/zero silent loss.
2. Watch P124-ALLOC-REVERT (bnobt/cntbt analog, 2-8/node every run, log-only) — may also shrink if it shares the P108-reload producer; if it persists with corruption, it needs its own chain.
3. Storm clean → 2 more storms → tests/criteria/zero_silent_loss.sh --iters 3 --dpn 100 --mode 1.
4. P135-SLOTWR/HELD-MISS instrumentation is chatty (ino≤256) — strip or gate before perf-sensitive criteria (rsync_paired!).
5. Probe archives: /tmp/p135a (12-shutdown run, 5306E3F8), /tmp/p135b (mild run +P135), /tmp/p135c (caller run, 21×P108), /tmp/p135d (post-fix-1, P108=1, HOLEs remain).
VERSION revved 0.4.6→0.4.10. Storm script needs `bash scripts/p133_storm_errcap.sh` (no +x).
