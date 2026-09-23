<!-- sess403 RULE-5 ruling (D-FOREIGN-REPLAY-UNGATED-IMAGES / D-402): REDUNDANT_CLEAN certificate = IN-LOG release-marker log item (B), marker durable BEF… -->
# sess403 RULE-5 ruling — clean-release certificate carrier (gpt-5.6-sol)

## Evidence brought
kill5b (0.23.16, enforce armed): victim test3 logged AG1 images at epoch 19, cleanly released
to test31 (epoch 20), test31 demoted back at 04:39:26.0 (holders=0, ex_epoch=20), test3 destroyed
04:39:26.4 before re-acquire; replay ~70 s later: tokens {AG1,19} vs slot holders=0 ex_epoch=20 ->
not_held -> ATOMIC-SKIP -> POLICY-REFUSED -> AG1 quarantine (test31 EIO). Same on AG6 (43/44).
Strip audit (scout, sess403): the ONLY non-owner EX/PW bit clears are caw_strip_node_state via
(1) mxfs_v5_dlm_recovery_complete -> mxfs_dlm_caw_purge_node (post-verdict) and (2) closure strip
(post-recovery); dlm/mount.c (purge_node_dlm keep_ex=false on peer disconnect) is NOT in Kbuild
(dead code); v5 CAW registers NO peer-disconnect purge (TCP-only cb, and it purges the TCP DLM).
Own-bit clears: caw_unlock_gen_body (after drain), caw_release_all_body (unmount),
caw_force_release_self_body (stranded own-bit repair, no in-core tenure).
Epoch: caw_grant_epoch_update mints on every non-write->write grant (incl. PR->EX and same-node
reacquire after release); mid-tenure mode change preserves; tombstone carries; post-surrender
readopt of a stranded own bit mints (P294-READOPT-MINT).

## Options presented
A) slot-resident last_clean_release_epoch[64] (u32) + last-strip record in reserved[336], stamped
   in the unlock CAS. B) in-log release-marker log item {class,resource,lineage,grant_epoch,owner
   slot,owner incarnation} logged by the releaser in its own slice after the drain, sync-forced
   before the unlock CAS; pass-1 table (buffer-cancel pattern); pass-2 REDUNDANT_CLEAN.

## Ruling
- SHIP B. A is DISQUALIFIED: tombstone recycle under inode churn turns routine clean failover
  into quarantine; u32 epoch aliasing; no incarnation binding; 'ex_epoch>E' is an inference over
  exceptional paths, not a certificate; single strip record unreasonable across wrap/lineage.
- Marker durable BEFORE the holder-bit clear. Sequence: enter RELEASING (block new writers /
  formatting under E) -> force CIL for E -> drain -> bdev flush -> commit + SYNC force marker ->
  CAS bit clear -> successor grant/epoch advance. AFTER-CAS ordering rejected (crash window with
  cleared bit and no certificate = avoidable quarantine; violates certificate-before-clear).
- CRITICAL: once the marker is durable the release is NON-ABORTABLE back to ACTIVE(E). The
  P15-REL-ABORT shape (holder re-acquired during drain, keeps writing under E) after a marker is
  UNSOUND (marker + later strip => all E records wrongly clean). If the holder needs the resource:
  finish clearing the bit, reacquire via the normal grant path, mint E+1. (Alternative: durable
  marker-invalidating record with refusal precedence — rejected as more complex.)
- Crash between marker force and CAS is safe: bit V + epoch E still in manifest -> APPLY.
  Same-node reacquire E+1 safe: E records match marker -> skip; E+1 apply if held at death.
  Use the FULL epoch, never truncated.
- Fence-time manifest snapshot: RETAIN for the APPLY class (explicit freeze boundary, TOCTOU
  protection, per-txn consistency); B removes the need for it for REDUNDANT_CLEAN. Precedence:
  (1) snapshot says held {lineage,epoch} -> APPLY; (2) exact marker -> REDUNDANT_CLEAN; (3) refuse.
- Own trusted mount-time replay: markers must parse and be no-ops (RELEASE_WHEN_COMMITTED, never
  AIL). Adopted slices: match the COMPLETE identity incl. owner slot + incarnation; never accept a
  marker from another incarnation on the same node slot; malformed/uncommitted/identity-conflict
  markers never certify. Proto-gen bump + mixed-gen refusal appropriate.
- Log lifetime: sound because the marker is emitted after all logging under E is quiesced — if an
  E record pins the tail the marker is behind the head; once the tail passes the marker it has
  passed the E records. Pass 1 collects only markers from fully committed txns in the active
  range; bound/validate the table.
- Do NOT enable a 'wrote anything' skip-marker optimisation initially.
- Transaction/reservation liveness: never reserve/force from a non-sleepable DLM callback; use a
  sleepable release worker; ACQUIRE THE MARKER LOG RESERVATION BEFORE entering the non-abortable
  phase; if it cannot be acquired leave the bit held and defer the release — never clear without
  the marker; audit AIL push paths for reacquiring the resource being released. A tiny-reservation
  internal log item is preferable to a raw side channel. Pre-reserved per-slice marker tickets are
  reasonable if simultaneous release demand is bounded.
- Ordering: detect -> fence -> freeze non-owner mutation -> snapshot -> pass-1 markers -> classify
  + replay -> flush -> terminal verdict -> purge/closure strip -> epoch advance -> grant. Admission:
  every buffer item APPLY or REDUNDANT_CLEAN AND every non-buffer item independently authorized,
  else refuse the whole txn; REDUNDANT_CLEAN = silent skip (no quarantine). Markers prove clean
  release only — never authorize unrelated non-buffer items. Keep di_changecount inode gate.
