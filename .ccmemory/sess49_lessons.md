---
name: sess49_lessons
description: sess49 MXFS — slowness fix (force_peer_flush) + drevalidate deadlock fix; 1/4→3/4 cache_coherency; rename regressed
metadata: 
  node_type: memory
  type: project
  originSessionId: d41aca09-0dca-465c-9dbd-4396736cbb59
---

# sess49 (2026-06-02) — cache_coherency: 1/4 → 3/4 PASS; two fixes landed

Build progression: sess48 DDF05EA7 → **D9B3F53A** (slowness) → **FE42546D** (deadlock).
Both fixes KEEP. State detail + next steps: /src/mxfs/state.md (sess49 section at top).

## FIX #1 — reused-inode eviction SLOWNESS (build D9B3F53A)
sess48's reused-inode type-mismatch eviction in `xfs_lookup` waited up to 120s (barrier
timeout) for the peer's reused dir-inode to become durable (gen-gated recycle re-read kept
seeing stale disk). FIX: new `mxfs_dlm_force_peer_flush(ip)` (xfs/xfs_mxfs_dlm.c, next to
mxfs_read_coherency_envelope; type-agnostic ilock_begin(PR)+ilock_end(PR), i_dlm_stale MUST be
clear so NO in-place reload) called in the xfs_lookup eviction block before setting i_dlm_stale.
A PR acquire BASTs the creator's sticky-cached EX → it drains+iflushes the new dinode before
downconverting → next iget's recycle adopts the fresh incarnation. Proven: rename 133→26s,
unlink 264→35s. The CREATOR holds inode EX (xfs_create→xfs_ilock→ilock_begin(EX), sticky), so
the PR-BAST mechanism is valid.

## FIX #2 — drevalidate PERMANENT DEADLOCK, fixed AT SOURCE (final build 10A04B9E)
`tests/repro_barrier_dir.sh` (concurrent 4-node `mkdir -p <d>/sub; touch sub/nodeN` = barrier_
signal) WEDGED a `touch` D-state forever: `mxfs_drevalidate → xfs_dir_lookup → xfs_ilock(dp,SHARED)
→ ilock_begin → mxfs_dlm_reload_inode → down_write(&dp->i_lock)`. d_revalidate runs in
lookup_fast() (path-walk); the dir-inode reload's blocking down_write wedges when another holder
of dp->i_lock is parked (a thread holding ILOCK_SHARED across a CAW poll — the CLAUDE.md "ILOCK
held across CAW poll" tension; only ONE D-state task = holder is a non-D sleeper).
First tried LOCKLESS drevalidate (FE42546D) — REVERTED: it fixed the deadlock but REGRESSED rename
(375s, barriers 1/4) because it removed the coordinated dir reload rename needs, and return-0-for-
every-negative = re-lookup storm.
FINAL FIX (10A04B9E): fix the deadlock AT SOURCE — `mxfs_dlm_reload_inode`'s down_write (xfs_mxfs_
dlm.c ~L1249) → bounded `down_write_trylock`+cond_resched (1000×), bail on contention leaving
i_dlm_stale set (buffer already staled above → next uncontended access re-reads). Then RESTORED
coordinated drevalidate (sess45 version). Result: repro_barrier_dir 0/60 NO wedge; **ALL 4
cache_coherency sub-tests PASS INDIVIDUALLY** (cross_vis 135s, rename 26s, unlink 152s, cwr 135s).

## ⛔ REMAINING (the real blocker) — SLOW/FLAKY barrier-dir visibility; sticky dir grant not BAST'd
Each sub-test passes ALONE but the SEQUENTIAL criterion (cache_coherency.sh: 1 reset, 4 tests on
ONE mount) still FAILS: cross-test contamination + a flaky 120s barrier stall tips whichever test
runs late (FE42546D failed rename; 10A04B9E failed cross_vis-when-4th, though cross_vis PASSES
alone). VARIANCE, not a per-test bug. Even passing tests take ~135s = ONE 120s barrier timeout
that eventually resolves. ⚠️ ROOT NOT PROVEN — instrument per RULE 4 (see state.md "ROOT
UNCONFIRMED"). My mid-session "sticky PR mode → peer EX never BASTs" theory is LIKELY WRONG:
bast_process DOES set i_dlm_mode=NL (xfs_mxfs_dlm.c L690) before releasing the grant, so after a
BAST the next acquire correctly slow-paths (reload + i_dlm_dir_gen bump L1923 + read-time dir-block
invalidation xfs_da_btree.c L2907). The unknowns to INSTRUMENT (mxfs.instr=0): (Q1) does node1
actually RECEIVE a BAST when a peer adds a marker, or is its on-disk CAW PR slot dropped when
holders→0 (sticky keeps i_dlm_mode==PR but releases the slot → peer EX sees no holder → no BAST)?
(Q2) is the 120s a dir-BLOCK miss or a MARKER-FILE child-inode miss (could be sess48 reused-inode/
empty-file coherency, not the dir block)? (Q3) extend tests/repro_barrier_dir.sh to MEASURE
first-visible latency. Fix ONLY after proven; NOT per-op FUA (sess43 too slow). TEST ALL 4
sub-tests after any drevalidate/reload/grant change — they interact. MXFS_TESTS_DIR=/src/mxfs/tests
REQUIRED when calling run_tests.sh directly.
