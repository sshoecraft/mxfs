# v6a roadmap — mxfs_clayer/ (sess35 sketch)

**Status: HEADERS ONLY.** invalidate.h, release.h, acquire.h are
stubs documenting the intended structure per
`docs/v6-cache-architecture-proposal.md` §3. The `.c` files are
deliberately unbuilt (gated by `MXFS_CLAYER_INVALIDATE_BUILD_NOT_READY`
or just absent).

Sess36+ task: implement the bodies, migrate v5's release sites to
the chokepoint, then remove the v5 per-site invalidations.

## Why these files exist now

Sess35 confirmed via instrumented evidence (E1, E1b, H22-H29 falsifications)
that the test_concurrent_mkdir bug is **Mode A duplicate-create** —
the same Mode A bug sess20-34 chased. Storage stack is fine. v5's
bolted-on per-callsite invalidations leave race windows that the
test triggers reliably (100% bug rate over 10 runs).

The architectural fix per `docs/v6-cache-architecture-proposal.md`
§3 is a single chokepoint for token acquire/release that:
- Cannot be bypassed (no escape paths)
- Atomically pairs DLM-grant with cache-invalidation
- Eliminates the skip_locked-style escapes that v5's
  BAST-DIR-STALE walk has

This roadmap captures the architectural shape sess36+ should build
toward.

## File map

| File | Purpose | Status |
|------|---------|--------|
| `invalidate.h` | Five GFS2-shaped primitives (ag, inode, pagecache, ail-push, log-force) | Sketch — sess36 to implement |
| `invalidate.c` | Implementations, gated `BUILD_NOT_READY` | Stub |
| `release.h` | `mxfs_clayer_release_token()` chokepoint | Sketch |
| `acquire.h` | `mxfs_clayer_acquire_token()` chokepoint with epoch | Sketch |
| `pinned_resource.{c,h}` | D9 pin counter (already in v5) | Live in v5 |
| `yield_quantum.{c,h}` | D10 yield counter (already in v5) | Live in v5 |

## Migration strategy

Per proposal §6:

### Phase 1: implement primitives (sess36, ~1-2 sessions)
1. Lift `mxfs_dlm_invalidate_ag_meta` body from xfs/xfs_mxfs_dlm.c:2480-2716
   into `invalidate.c::mxfs_invalidate_ag()`.
2. Lift BAST-DIR-STALE walk body from xfs/xfs_mxfs_dlm.c:300-470 into
   `invalidate.c::mxfs_invalidate_inode()`.

   **CRITICAL — the skip_locked problem needs a real solution.**
   Sess34/sess35 references to `xfs_buf_delwri_pushbuf` were WRONG —
   that function doesn't exist in the kernel XFS source. The real
   options for sess36 to research:

   a. `xfs_buf_delwri_submit_nowait` (kernel XFS API) — but it ALSO
      uses `xfs_buf_trylock` (kernel XFS xfs_buf.c:2024), so same
      skip_locked problem.

   b. Block on `xfs_buf_lock(bp)` (synchronous wait). This is what
      sess34 H8/H10 tried — caused 6m+ stalls due to lock inversion
      against xfsaild's iflush which holds ILOCK_SHARED.

   c. **Architectural change in BAST-DIR-STALE walk**: instead of
      trying to push the buf ourselves, BLOCK NEW TRANSACTIONS on
      the inode (set i_dlm_state=DEMOTING + wait for in-flight
      transactions to drain). Then the dir3 buf will be unlocked
      naturally because no one is using it. Then we can stale it.
      Trade-off: longer drain at unlock; risk of new lock inversion.

   d. **Use a dedicated workqueue** that runs in a context with
      different locking constraints. xfsaild typically runs at
      sched yield points; if we run in a higher-priority queue,
      we may avoid the deadlock.

   e. **Force log_force_lsn for this transaction's LSN** before
      releasing — guarantees CIL has flushed, AIL has the BLI,
      xfsaild WILL push. Then wait on AIL drain via the existing
      mxfs_ail_push_ag_sync. This is the "make xfsaild do it"
      approach, which doesn't have lock inversion since we're
      not holding any conflicting locks.

   Sess36 should pick (e) first — it's the most XFS-idiomatic and
   sidesteps the lock-inversion landmine sess34 hit. If (e) doesn't
   work, try (c).

3. Implement chokepoints in `release.c`, `acquire.c`.
4. Wire ONE callsite (e.g., bast_process inode release) through the
   chokepoint as a pilot. Verify with sess35_capture.sh that the bug
   doesn't worsen.

### Phase 2: migrate all callsites (sess37+, ~1-2 sessions)
- bast_notify NO_INODE/NONE_NL branches: synthesize transient state
  to drive the chokepoint correctly.
- mxfs_dlm_evict: route through chokepoint.
- AG-token release sites: route through chokepoint.

### Phase 3: remove v5 per-site invalidations (sess37+, 1 session)
After all callsites use the chokepoint, the per-site
xfs_buf_stale + blkdev_issue_flush + invalidate_inode_pages2
calls scattered through xfs_mxfs_dlm.c can be deleted. Leaner
codebase, single source of truth for invalidation.

### Phase 4: measure (sess38, 1 session)
- 10-run baseline with chokepoint vs. without — should drop from
  100% bug rate to ~0%.
- bench/rsync_bench.sh comparison.
- Mode A reproducer (test_concurrent_mkdir) should pass cleanly.

### Total: 4-6 sessions for v6a phase 1.

## What's NOT in scope for v6a

- LVB stat cache (v6b — gated on H3 measurement showing stat reads dominate)
- Multi-class tokens (D3 — orthogonal optimization)
- CXFS asymmetric model (v7+)
- Storage stack changes (sess35 proved storage works for v6a's needs)

## Sess35 evidence files

- `notes/sess35_findings.md` — full evidence trail
- `~/.claude/projects/-src-mxfs/memory/sess35_lessons.md` — summary
- `notes/sess35_h22.md` — original H22 hypothesis (disproven)
- `notes/sess35_h29.md` — REQ_META hypothesis (falsified)
- `notes/sess36_storage_diagnostic_plan.md` — diagnostic plan
  (mostly moot now that sess35 proved storage works, but still
  useful as a template for hypothesis-driven debugging)
- `scripts/sess35_capture.sh` — reproducer with /dev/kmsg follower
- `scripts/sess36_e1_xinit_durability.sh` — cross-init durability test
- `scripts/sess36_e1b_concurrent_xinit.sh` — concurrent cross-init test
- `scripts/sess36_quickstart.sh` — sess36 startup helper
