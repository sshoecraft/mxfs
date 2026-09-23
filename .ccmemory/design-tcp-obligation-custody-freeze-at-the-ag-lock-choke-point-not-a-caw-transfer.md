---
name: design-tcp-obligation-custody-freeze-at-the-ag-lock-choke-point-not-a-caw-transfer
description: D-FOREIGN-SLICE-INTENTS-ABANDONED 2/tcp fix shape (sess611-614, 0.85.0/0.85.1): OPEN record at IMAGES_REPLAYED, freeze mask at __mxfs_ag_dlm_lock, ea…
metadata:
  type: project
tags: [D-FOREIGN-SLICE-INTENTS-ABANDONED, recovery, design, item5, tcp]
---

# The 2-node TCP custody model for open EFI obligations (built sess611-614, 0.85.0 + 0.85.1)

Why this shape and not the sess463 CAW ruling's transfer/receipt machinery: on TCP a dead
node keeps mastership + ledger EX holds until the ladder's remaster/purge trio, so a
custodian cannot acquire a victim-mastered AG at all before that trio; and the AG grant
alone is not local exclusion (nested fast path admits any local caller). So:

1. Verdict flip (xfs_log.c, `P226-FR-INTENTS-RECOVERABLE`) only when recover>=1,
   quarantine==0, !fswide, malformed==0, list exported, !rmapbt, !reflink, TCP transport,
   `mxfs.obl_complete_enable=1` (default 1). CAW keeps the terminal refusal.
2. The ladder's IMAGES_REPLAYED CAS carries the verdict: `recov_advance_impl` writes the
   OPEN record (list first by obl_write) or `MXFS_RECOV_F_CENSUS_ZERO`. The XFS layer parks
   the verdict (`mxfs_v5_dlm_recovery_set_obligations/_set_census_zero`) BEFORE complete2;
   a ladder entered below IMAGES_REPLAYED with nothing parked is HELD.
3. GRANTS_RELEASED refuses OPEN records and "no record and no CENSUS_ZERO".
4. OPEN branch in `v5_recovery_complete_ladder`: freeze cb, `v5_dead_grants_retire` ONCE per
   (victim epoch, pub_seq) — seq alone aliased the slot's next victim (sess612) — returns
   OBLIGATIONS_OPEN / -EINPROGRESS. FSWIDE or CAW → HELD.
5. The freeze: `m_mxfs_oblf_*`, checked at the top of `__mxfs_ag_dlm_lock` before every fast
   path: nonblock → -EAGAIN, blocking → 120 s wait → -ETIMEDOUT; custodian task and a txn
   already retaining the grant exempt. Installed from the platter on every node (ladder cb,
   monitor observer per sector, registration-time scan).
6. Engine `xfs/xfs_mxfs_recov_obl.c`: per extent one tr_itruncate txn, bnobt has_records:
   EMPTY→free (ANY_OWNER)+busy; FULL→skip; SPARSE→terminal reason 9. Then log force +
   home flush, two-phase proof, OBLIGATIONS_DONE, lift, complete2.
7. Takeover: defer while another dead slot is non-terminal below IMAGES_REPLAYED; the mount
   barrier hands OPEN slots to the post-mount worker (`mxfs_barrier_note_open_cases`) — and
   `mxfs_dlm_cache_init` must NOT zero the dead bitmap afterwards (sess614).
8. Total outage on two nodes (0.85.1): the sole-survivor WE(1) gate outlives its holder —
   a joiner proves the holder dead over a dead window and preempts it
   (`v5_tcp_dead_gate_holder`, P-PR-DEADGATE-*); a successor re-proves a kind-20
   certificate as sole live member (`v5_gate_reprove`); a non-gate certificate accepts
   WE(1) held by our own key; the PAL compares the SAM status byte (0x118 == conflict).
   The test hold forces the log before parking so the successor meets the FULL branch.

Verified 8330C6DFDB0B731E3308020: s614d custodian_kill fails=0 (323 s), s614e/f complete
fails=0 (145/142 s). Record removed from the queue 2026-09-13. Filed separately:
D-SOLE-SURVIVOR-GATE-NEVER-RESTORED-AFTER-A-TERMINAL-REFUSAL-… (live-holder case). Astra
consult attempted twice (sess613, sess614): HTTP 429 credit exhausted both times.
