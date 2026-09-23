---
name: trap-a-withdrawn-predicate-that-reads-only-the-authority-object-misses-the-forced-shutdown-withdrawal
description: TRAP (s149a, 0.89.68): a mount withdraws two ways — authority CLOSED (lease expiry / PR conflict) and forced shutdown (poison, ctx->withdrawn) — and…
metadata:
  type: feedback
tags: [dlm, lease, withdrawal, authority, harness]
---

# A withdrawn predicate must read both withdrawal producers

`v5_lease_member_state_cb` (dlm/v5_mount.c, 0.89.68) answered WITHDRAWN only when
`ctx->disklock->auth->state == MXFS_AUTH_CLOSED`. The lap built to measure it
(`SUSPECT_FIRST=1 tests/post_closure_renewal_at_peer.sh`, s149a,
tests/evidence/20260922T113929Z_pcren_s149a) withdraws the mount with
`dbg_dialloc_shutdown` — a FORCED SHUTDOWN. That path is
`mxfs_v5_dlm_withdraw` → `mxfs_v5_dlm_poison`: it sets `ctx->withdrawn`,
stamps the slot WITHDRAWN (`P163-WITHDRAW-STAMP`) and keeps the lease renewals
running on purpose, but it never moves the authority object off ADMITTED. So
every renewal after the stamp said MEMBER, no `P-LEASE-WITHDRAWN-RENEWAL` was
logged, and the peer promoted the SUSPECT entry back to ACTIVE 546 ms after it
had read the stamp.

The two producers of "this mount is withdrawn":

1. authority CLOSED (`mxfs_authority_close`: lease expiry, PR conflict,
   revocation) → `P290-AUTH-CLOSED` → the withdraw pump → `P290-AUTH-WITHDRAW`
   → `mxfs_v5_dlm_withdraw`;
2. forced filesystem shutdown (`xfs_do_force_shutdown` hook, the
   `dbg_dialloc_shutdown` injector, a log I/O error) → `mxfs_v5_dlm_withdraw`
   directly, authority object untouched.

Both end in `ctx->withdrawn = true`. A predicate about "withdrawn" reads
`ctx->withdrawn` (or `mxfs_v5_dlm_is_withdrawn`) — the authority object alone
covers only producer 1. Fixed in 0.89.69 by reading both.

The general form: when a state has more than one producer, a consumer wired
to one producer's flag reads the other producer as the opposite state, and a
lap that drives the other producer measures the consumer's blind spot as the
defect it was built to disprove.
