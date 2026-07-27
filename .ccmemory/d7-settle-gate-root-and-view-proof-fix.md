---
name: d7-settle-gate-root-and-view-proof-fix
description: D7 CLOSED: 4.7-20s joiner EX stall = sess39/45 wall-clock membership-settle gate (memb_settle_ms=20000). Fix v0.11.78: lease-beacon view-hash converg…
metadata:
  type: project
tags: [d7, settle-gate, membership, lease, view-hash, rule4-proven, ccloop-c7ee71c6]
---

# D7 root cause + fix (v0.11.78, ccloop c7ee71c6 sess1)

## Root cause (RULE 4 PROVEN)
The 4.7-20s joiner root-ino EX acquire stall (physrig samples 4676/4681/19765/20070ms; VM repro 20138/20107ms) is the **sess39/sess45 membership-settle gate** in `dlm/dlm.c dlm_lock_impl()`: every EX acquire blocks until the membership view has been *wall-clock stable* for `mxfs_memb_settle_ms` (=20000 since sess45; raised from 6000 for the 1→N formation-ramp split-brain). A joiner's first EX (root ino 128, `comm=mount`) necessarily lands ~250ms after its own join event → waits ~19.8s. The 4.7s family = residual-window cases (acquire landing ~15.3s after the last change). Probe: `P-D7-SETTLEGATE ino=128 since_change=245ms settle_ms=20000 waited=19000ms` accounted for 19.0s of the 20.1s mount.
**Scope**: the gate freezes EVERY node's EX acquires for up to 20s after ANY membership change (join/leave/death) — not just the joiner. P11-ACQSTALE-SELFBAST stale=1 src=7 was a downstream symptom, not the cause.

## Fix (v0.11.78): view-signature convergence proof
Wall-clock window kept as FALLBACK; fast path settles on positive proof:
- `dlm.c update_active_nodes`: on change, compute FNV-1a-64 over the sorted member ids + count → `my_view_hash/count` (under active_nodes.lock).
- Lease UDP beacon (500ms cadence) grew `view_count/view_hash` (`lease.h mxfs_lease_udp_msg`; RX accepts old-length packets as beacon-without-report via MXFS_LEASE_UDP_MSG_V1_LEN — short packet can never fake a confirmation).
- `dlm_view_confirmed()`: TRUE iff every node in my active view reported hash==mine && count==mine && rx_ms >= last_memb_change_ms. `dlm_membership_settling()` returns false early on proof.
- Plumbing: `mxfs_dlm_get_view_sig` / `mxfs_dlm_report_peer_view` (dlm.h), `mxfs_lease_set_view_provider/report_cb` (lease.h/c), glue `v5_view_sig_provider/v5_view_report_cb` wired in v5_mount.c TCP branch before lease_start (CAW branch: ctx->dlm NULL → no-op).
- Safety: equal hashes over sorted sets = identical nodes[hash%count] mastery mapping (the exact property the wall-clock approximated). Divergent/absent confirmations → behavior identical to pre-fix (20s fallback). sess45 formation-ramp: pairs that mutually confirm proceed CONSISTENTLY; singleton late joiners are held by the v5 mount gate (disklock slot ground truth), not this gate.

## Verification
- Repro (mount n1, touch no-sync, mount n2): join wall 20138ms → **662ms**; `P-D7-SETTLEGATE waited=300ms confirmed=1`.
- Membership-sensitive subset on v0.11.78: cache_coherency 534, dlm_fairness, dlm_membership, fence_during_write, fault_netpartition ALL PASS. Prep converge 18s (was 41-88s).

## VM repro recipe (for regressions)
umount both → mount n1 → touch (no sync) → timed mount n2. Healthy: <1.5s. The P-D7-SETTLEGATE probe (dlm.c) stays in-tree.
