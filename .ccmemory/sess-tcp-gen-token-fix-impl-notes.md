---
name: sess-tcp-gen-token-fix-impl-notes
description: Impl notes for the double-grant gen-token fix: wire-format change needed (pads too small), empirical validation ~15-20 consecutive standalone passes…
metadata:
  type: project
---

## Implementation feasibility notes for the generation-token double-grant fix.
(Design rationale: [[sess-tcp-double-grant-instrumentation-impossible]].)

### WIRE-FORMAT change required (include/mxfs/mxfs_dlm.h):
- struct mxfs_dlm_lock_req: only `pad[3]` spare after `mode` (uint8) — NOT enough for a uint32
  held_gen. Must ADD a field (e.g. `uint32_t held_gen`), growing the message.
- struct mxfs_dlm_lock_resp (grant): only `pad[2]` spare — must ADD `uint32_t grant_gen`.
- struct mxfs_dlm_lock_release: only {hdr, resource} — must ADD `uint32_t grant_gen`.
- struct mxfs_lock (dlm/dlm.h): ADD `uint64_t grant_gen` next to request_epoch/granted_at.
Single-version cluster (both nodes same build) so wire growth is OK, BUT verify the recv path's
length handling (mxfs_dlm_msg_hdr.length + any sizeof()-based validation in the peer recv/dispatch)
does not REJECT the larger message — a too-strict length check would make ALL locks fail
(catastrophic). Check mxfs_peer_recv / the dispatch in dlm/ + mxfs_clayer for size asserts.

### ALGORITHM (guards the REQUEST-path stale-removal, the proven removal site):
1. Global monotonic `mxfs_grant_gen` (under table_rwlock). On creating a GRANTED entry:
   entry->grant_gen = ++mxfs_grant_gen; echo it in the LOCK_GRANT (grant_gen) and store on the
   granted node (local lock state / pending).
2. A node re-requesting carries held_gen = the grant_gen it currently believes it holds (0 if none).
3. process_remote_request stale-removal (dlm.c ~2081-2134) + local (~890-911): only REMOVE the
   sender's existing GRANTED entry when req.held_gen != entry->grant_gen (genuinely stale: holder
   moved on / released). When req.held_gen == entry->grant_gen, the holder STILL holds the same
   grant → re-affirm / convert, do NOT remove + promote a conflicting waiter (that was the
   double-grant).
4. Release paths (process_remote_release, mxfs_dlm_unlock) likewise gen-checked (defensive; the
   proof shows the holder didn't release, but late/dup releases are possible under load).

### VALIDATION (no in-band instrumentation possible — empirical only):
- tcp_dlm_scaling is ~50%/run. Confirm fix = ≥15-20 CONSECUTIVE standalone passes
  (`./run.sh 2 tcp tcp_dlm_scaling`, reboot+reset between — a fail wedges the FS). 0.5^15 ≈ 3e-5.
- Then FULL suite ×2-3 for regressions, ESPECIALLY posix_multi + cache_coherency (depend on the
  Bug-51 fix [[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]]) — the gen guard changes the same
  stale-removal logic Bug-51 added.
- Budget ~1hr/attempt. Fallback build if it regresses/doesn't validate: 30D3C28E (B4, 15/16) —
  revert the dlm.c/message edits.
See [[sess-tcp-double-grant-mechanism-refinement]].
