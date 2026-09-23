<!-- sess442 RULE-5 code review of the 0.47.0 item-5d landing: 4 provisional concerns REFUTED by the code; NEW STOP-SHIPs: norecovery false K_REPLAY_OK, R… -->
# sess442 RULE-5 code review — item 5d (0.47.0) as landed

Reviewed with the actual code bodies (v5_bootstrap_adopt, run tail, unwind, ladder hook, finish/terminal, victim_desc_read, claim_victim_slot, escrow prepare/advance, slot_complete/complete, xfs_log_mount adoption + P-BOOT-ADOPTED-REFUSED, barrier).

## Refuted (code satisfies the ruling)
1. Escrow-before-claim / TOCTOU: prepare CAS + readback (state, slot, 120-byte desc memcmp); claim_victim_slot re-reads K under lock and CAWs from exact guarded image with descriptor memcmp.
2. READ KEYS truncation: `total > nkeys -> -EOVERFLOW` fails closed.
3. K certified complete before replay: adoption precedes xfs_log_mount; finish() runs after the barrier which runs after xfs_log_mount. Ordering correct.
4. Teardown unregistering owner key: retain_key on both stop and unwind paths.

## STOP-SHIP (new)
S1. `xfs_has_norecovery(mp)` skips xlog_recover but finish() still advances K_CLAIMED -> K_REPLAY_OK. Reject bootstrap adoption under norecovery (or carry an explicit "K replay executed" proof into finish).
S2. RESUME unreachable: mxfs_bootstrap_resume exists but the mount path never calls it. Durable states that need it: PREPARED + K still guarded (claim failed), PREPARED + our ACTIVE K (escrow advance failed after claim), K_CLAIMED (mount unwound after claim), K_REPLAY_OK (unwound after barrier advanced escrow but before COMPLETE).
S3. Reconcile only rejects unexplained keys; an empty list (or successors only) passes. Require ctx->pr_key present (and reservation holder if the design needs it).
S4. slot_complete bit lands after GRANTS_RELEASED but BEFORE sector zero/purge (deliberate: evidence precedes erase). Therefore RESUME must redo/verify zero + purge for every complete bit whose sector is still guarded; mxfs_bootstrap_complete trusts the bitmap.

## My own finding (a), consistent with S2
v5_bootstrap_unwind marks escrow K_REPLAY_REFUSED(-EIO) + record REFUSED on ANY unwind after K was claimed — including failures unrelated to K's replay (barrier -EBUSY, peer I/O). That converts a transient fault into a terminal term needing `chk_mxfs --clear-bootstrap`. Fix: K_REPLAY_REFUSED only from the typed refusal in xfs_log_mount (P-BOOT-ADOPTED-REFUSED / xlog_recover error on the adopted log); otherwise leave RECOVERING + K_CLAIMED (resumable, S2).

## Fix-later
- Barrier should return immediately after bootstrap_terminal persists REFUSED rather than continue and rely on finish() -EIO.
- keys[k]==0 accepted as "no registration" is fine only because the parser never uses 0 for unknown; verify.
