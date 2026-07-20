---
name: AAA-ccloopcc87-sess4-BUG3-B2fix-REJECTED-topologyA-confirmed
description: sess4: B2 gen-mismatch fix REJECTED after GPT+Fable consult (would trade crash for silent corruption). Topology A confirmed structurally. New diagnos…
metadata:
  type: project
---

## Context
Continuing BUG3 from `AAA-ccloopcc87-sess3-BUG3-refcount-audit-clean-still-hunting`: rare
(~20-25%) `VFS_BUG_ON_INODE(I_FREEING|I_CLEAR)` crash in `iput()`, hit via plain `rm ->
do_unlinkat -> dentry_unlink_inode -> iput()`, under `fence_during_write@8/caw` (needs
`dir_reuse_coherency` immediately before it in the SAME cluster session — isolated
fence_during_write never reproduces it).

Current build state: VERSION 0.10.84 (unchanged — everything this session is
diagnostic-only, no behavior change survives). Latest srcversion: 2AE187BE67804705D03578C.

## What this session did

1. **Live-captured the crash TWICE** (dmesg -T -w streamed per-node during repro, so the
   FULL log up to the exact crash survives even though the guest reboots and wipes its own
   dmesg ring buffer). Both times, immediately before the crash, on the SAME inode number,
   within the same wall-clock second:
   ```
   P25-INSTR sync-inactive ino=X nlink=0 mode=0x81a4
   P19-B3DEC ino=X ... dlm_mode=5(EX) dlm_locked=1 will_skip=1 (b2_genmis=1, all others 0)
   P2L-INACT-LEAK ino=X ... reason=gen-mismatch — RIGHTFUL FREER SKIPPING (AGI bucket leak)
   INACT-SKIP-STALE ino=X ... reason=gen-mismatch — skipping destructive inactivation
   P25-INSTR sync-inactive-DONE ino=X rc=0
   [crash: kernel BUG at fs/inode.c:1798 (upstream line differs — running kernel is Ubuntu
   6.8.0-101-generic, NOT the /src/linux 6.19-rc0 reference tree; use addr2line/function-name
   search against /src/linux for structure, not line numbers), RIP iput+0x1c5/0x250]
   ```
2. **Found a real comment-vs-code discrepancy** in `xfs_inactive()`'s B1-B5 multi-node
   TOCTOU-closure gate (xfs_inode.c ~3417-3610): B2's own comment says "Only skip when we
   are GRANT-LESS (i_dlm_mode==NL)... a node's OWN inode is held at PR/EX while it owns it,
   so this never false-skips" — but the CODED condition (`mxfs_dmode != 0xFFFF &&
   mxfs_dgen != mxfs_igen`) never implemented that qualifier, unlike siblings B4/B5 which
   both explicitly gate on `ip->i_dlm_mode != MXFS_LOCK_EX`. Live captures show `dlm_mode=5`
   (EX) yet B2 fires anyway.
3. **Proposed fix REJECTED after 2-model consult** (user directed: ask GPT first, then
   Fable — see RULE 5 escalation chain; this exchange updates that precedent, user
   explicitly asked for GPT-then-Fable order in the moment). I initially added the
   documented `ip->i_dlm_mode == MXFS_LOCK_NL` requirement to B2 (matching B4/B5's
   pattern exactly). **Both GPT-5.6 and Fable independently rejected this as unsafe**:
   the crash-adjacent captures ALSO show `dlm_locked=1` — a FRESH low-level per-inode EX
   re-acquire, taken specifically to close the disk-read TOCTOU window, succeeding
   immediately before the mismatched read. This means the gen-mismatch read is NOT racy
   (no peer can be concurrently mutating under that lock) — it is the STRONGEST possible
   evidence this in-core struct is a genuinely stale incarnation whose inode NUMBER a peer
   already reused. The DLM lock is keyed by inode NUMBER only, not (number, generation);
   holding EX proves exclusion on the number, never proves current-incarnation identity.
   Requiring i_dlm_mode==NL to gate the skip would make B2 proceed to DESTRUCTIVE FREE
   in exactly the case its own post-lock read just proved unsafe — trading an intermittent
   crash (current behavior: skip + leak an AGI bucket entry, loud via P2L-INACT-LEAK) for
   intermittent SILENT DISK CORRUPTION (freeing a peer's live blocks). **DO NOT make this
   change** — reverted in this session, left as original unconditional-on-genmismatch
   behavior. Added a loud capped forensic-only tripwire instead: `P2L-EX-GENMIS` fires
   (no behavior change) whenever B2's gen-mismatch condition is true while
   `ip->i_dlm_mode != MXFS_LOCK_NL`, logging incore_gen/disk_gen/dlm_mode/dlm_locked/
   local_unlink/ip pointer/pid/comm.
4. **Structurally proved Topology A** (an over-release somewhere; NOT a self-contained
   single-call artifact): traced that `xfs_inode_mark_reclaimable()`/`xfs_inactive()` (where
   "sync-inactive" fires) has exactly ONE call site reachable from userspace-triggered
   activity — `xfs_fs_destroy_inode()` (pal/linux/xfs_super.c:773-784), which IS the
   standard `sb->s_op->destroy_inode` hook, only ever called from VFS's `destroy_inode()`
   <- `evict()` <- `iput_final()`/`evict_inodes()` when i_count has ALREADY hit zero. So by
   the time "sync-inactive" prints, SOME `iput()`/`xfs_irele()` call already fully consumed
   the last reference and VFS already set I_FREEING — meaning the crash is a genuine
   OVER-RELEASE bug: something calls the final release ONE time more than the number of
   independently-held references, stealing what should remain a legitimate holder's (e.g.
   a dentry's) reference. Fable additionally confirmed a single `iput()` call cannot
   recursively re-enter and trip its own entry-check — the crash is definitely two SEPARATE
   release events on the same struct, not literally the same call frame.
5. **Prime suspect, not yet proven**: `mxfs_dlm_bast_notify()` (xfs_mxfs_dlm.c, starts
   ~line 14871, ~700 lines, ~15 distinct exit paths). Justification: a SEPARATE live capture
   this session (unrelated repro iteration) caught a genuine 2+-minute kernel soft lockup —
   `mxfs-worker` (kernel thread running `bast_recv_fn -> v5_bast_cb -> mxfs_dlm_bast_notify
   -> xfs_irele -> iput -> evict`) stuck spinning in `_raw_spin_lock` inside `evict()`,
   CONCURRENTLY with `umount`'s own `evict_inodes()` also active (stuck at
   `_raw_spin_unlock`, likely just a very long walk over a huge cached-inode set —
   `cache caps: inode=367319` — not necessarily a classic ABBA deadlock, could be pure
   lock-fairness starvation under an enormous list walk). This PROVES bast_notify's
   `xfs_irele()` calls DO trigger full synchronous eviction in production, live, not just
   theoretically. addr2line on that softlockup's exact RIP (`mxfs_dlm_bast_notify+0xade`,
   resolved against the CURRENT build since xfs_mxfs_dlm.c has NOT changed this session —
   verify via file mtime before trusting old-build addr2line results) resolved to
   xfs_mxfs_dlm.c:15567, the tail `xfs_irele(ip)` of the "BRANCH=NONE_mode_NL — no orphan,
   nothing to release" fallthrough (mode==NL, ex==pr==0, no phantom/orphan/reconcile
   condition matched). This SPECIFIC call, on inspection, looks like a textbook-correct drop
   of bast_notify's own entry ref (acquired via `xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0,
   &ip)` at the top, which internally does a proper `igrab()` checked against
   I_FREEING/I_WILL_FREE in `xfs_iget_cache_hit()`, xfs_icache.c ~1218) — not an obvious
   "borrowed reference" bug at THIS exact site. **Dispatched a subagent (general-purpose,
   background, see agentId in this session's tool-call history if resuming same session —
   otherwise just re-launch fresh) to exhaustively audit ALL ~15 exit paths of
   mxfs_dlm_bast_notify line-by-line** (not spot-checks) for a double-drop or
   foreign-reference-drop — this was in flight when the session context got long; CHECK
   ITS RESULT FIRST if resuming.
6. **Also instrumented `mxfs_trans_drain_inode_unlocks`'s `iput(VFS_I(ip))`** (xfs_mxfs_dlm.c
   ~28429, the OTHER remaining candidate from an earlier-session hypothesis about
   `mxfs_inode_dlm_defer_bast` possibly being callable twice for the same `ip` within one
   transaction with no dedup check against its own pending list) — new `P127-TRANSDRAIN`
   diagnostic logs i_count/i_state/ip pointer/pid/comm immediately before this iput(), capped
   at 8000. NOT yet proven or disproven — no live capture with this diagnostic active yet.

## Diagnostics currently live in the tree (all diagnostic-only, capped, no behavior change)
- `P126-DEMOTE-RACE` (xfs_mxfs_dlm.c, bast_notify's stale-DEMOTING branch): fires OFTEN
  (dozens/run) — proves a DIFFERENT, real but so-far-uncorrelated-to-BUG3 double-demote
  race is reached constantly under this workload (work_busy(&i_dlm_bast_work) is blind to
  Approach-A/dwork-driven releases). Confirmed via 2 live crash captures this session that
  P126 does NOT fire on the SAME inode near the crash — so it's not (by itself) THE cause
  of BUG3, but may be worth fixing on its own separate merits later (not yet done).
- `ip=%px pid=%d comm=%s` added to: P25-INSTR sync-inactive/-DONE (xfs_icache.c ~3301/3314),
  P19-B3DEC, P2L-INACT-LEAK, INACT-SKIP-STALE (xfs_inode.c). P19-B3DEC's b2 field split into
  `b2_genmis_raw` (unconditional gen-mismatch, for visibility) vs `b2_reused` (the actual,
  UNCHANGED-behavior decision variable — same as raw, no NL gate, per the rejected-fix
  reversion).
- `P2L-EX-GENMIS` (xfs_inode.c, new): fires when B2's gen-mismatch is true AND
  `ip->i_dlm_mode != MXFS_LOCK_NL` — the exact "should be impossible per the comment"
  anomaly. Not yet observed firing (no live capture since it was added).
- `P127-TRANSDRAIN` (xfs_mxfs_dlm.c, new): logs every entry drained by
  `mxfs_trans_drain_inode_unlocks` before its iput(). Not yet observed.

## Validation status
- 9 full-combo (`dir_reuse_coherency`+`fence_during_write`@8/caw) repro iterations run this
  session with the P126 diagnostic active: 2 hit BUG3 (iters 1,2 — both analyzed above), 1
  hit the SEPARATE softlockup (iter 9), 6 clean (iters 3-8). This matches the historical
  ~20-25% rate — NOT yet enough clean iterations to trust any fix, and no fix has actually
  landed yet (the B2 change was reverted).
- criteria.json / matrix_check.py showed "100% PASS" lifetime-best across 1/2/4/8/16/32
  BEFORE this session started, but almost all of it is STALE (recorded on older builds,
  well before this session's diagnostics — some cells as old as 0.10.66/0.10.74). Do NOT
  trust that surface reading. The only cells actually fresh on anything resembling the
  current tree are `dir_reuse_coherency`/`fence_during_write`@8/caw from session 3's tail
  end (0.10.84, iso ~2026-07-13T19:17-19:18Z) — a SINGLE clean sample, not remotely enough
  given BUG3's known ~20-25% hit rate and complete lack of a landed fix.

## Next steps (in priority order)
1. Check the dispatched subagent's bast_notify full-audit result FIRST.
2. If it finds a concrete double-drop/foreign-drop: that's the fix. Implement narrowly,
   rebuild, re-run the SAME full-combo repro many times (RULE 4 — this bug's ~20-25% rate
   means 2-3 clean is NOT sufficient evidence; want 10+ clean or a deterministic proof).
3. If it finds nothing: resume live-capture hunting with the P127-TRANSDRAIN and
   P2L-EX-GENMIS diagnostics active (use the SAME `dmesg -T -w` per-node live-streaming
   technique — captures the FULL log up to the exact crash moment even across a guest
   reboot, since the serial console log is loglevel-filtered and misses pr_warn-level
   diagnostics entirely; SSH-based `dmesg -T -w` is NOT filtered and is the only way to
   catch these). Also consider: does the softlockup's `_raw_spin_lock` inside `evict()`
   indicate a genuine ABBA deadlock with `evict_inodes()`, or pure lock-fairness starvation
   under a huge (367K-cap) cached-inode walk during unmount? Not yet investigated — may be
   a second, independent bug (or may share root cause with BUG3; unclear).
4. Only after a PROVEN, validated fix for BUG3: proceed to task #5, the full fresh
   1/2/4/8/16/32 @ caw sweep with `matrix_check.py --since <fix-build-epoch>` as the honest
   YES gate for the ccloop criteria. Do NOT write YES to the criteria-met marker before
   that full fresh sweep passes on a build that includes a PROVEN (not just proposed) BUG3
   fix — the criteria covers all of 1/2/4/8/16/32, and 8-node is not yet reliably clean.
