<!-- sess420 RULE-5 ruling on the mount recovery barrier (D-MOUNT-WINDOW): NOT rig-ready — item 3 needs obligations in completion eligibility, item 4 need… -->
# sess420 GPT ruling — mount recovery barrier (items 3/4/6C) + window-arm design

## Verdict: not yet sound for ACCEPTANCE rig cycles (diagnostic runs ok). Two stop-ships.
1. Item 3 NOT closed: a slot may reach GRANTS_RELEASED / heartbeat-zero only if
   IMAGES_REPLAYED && (OBLIGATIONS_DONE or enforced QUARANTINED). Until
   D-FOREIGN-SLICE-INTENTS-ABANDONED supplies obligation completion, the acceptable behaviour
   is FAIL-BEFORE-PURGE (never publish a slice whose intents/obligations are undischarged).
   Canonical durable order: FENCED -> IMAGES_REPLAYED -> OBLIGATIONS_DONE/QUARANTINED ->
   authority purge+flush -> GRANTS_RELEASED -> heartbeat zero; no alternate path may set
   GRANTS_RELEASED during barrier step (c). 6C closes only once that eligibility is in code.
2. Item 4: 0/91 pass-1 observations are NOT a safety invariant. Closure requires: the fresh
   claim provably inherits no authority; settle_own_slot performs NO destructive purge on the
   unproven (pass-1) path, with an assertion that no old-incarnation match occurred; pass-1
   disabled/failed pending D-OWN-CRASH-RECLAIM. SKIP_TRACKED still has a victim if tracking
   misses authority needed by deferred intent replay (peer takes the bit between (e) and
   xfs_log_mount_finish). If a destructive current-slot purge must remain, move it AFTER
   xfs_log_mount_finish + obligation completion.
3. Late-death double recovery: serialization = one durable descriptor keyed by victim
   slot+incarnation, one linearizable execution-lease winner, every survivor engine consults it
   (join/observe, never a second election), idempotent CAS transitions, takeover from the last
   durable stage. P233-MPHASE-DEATH must suppress ordinary election for that victim while the
   mphase record is owned/pending — if not shared by every survivor, stop-ship. Harness asserts
   (cluster-wide, incarnation-qualified): exactly one lease winner; exactly one replay
   start/complete owner; no replay-start by C; PR fence precedes replay; IMAGES_REPLAYED +
   obligation terminal precede authority purge; flushed purge precedes GRANTS_RELEASED;
   GRANTS_RELEASED precedes heartbeat zero; exactly one publication/zero.
4. Window arm as proposed does NOT necessarily exercise late-death folding: B killed at +30 s
   expires ~+92 s but D's confirm lets the barrier leave ~+62 s; and killing D 3 s before
   DLM step 6.5 may not make D eligible for the initial snapshot. Use a deterministic
   hold/faultpoint: D already stale enough to be in the initial cohort; PAUSE A after mphase
   is armed; kill B; hold until B is confirmed dead and P233 durable; release. Minimal
   positives: P233(B inc, barrier epoch) while A owns the mphase; one lease winner = A; B
   fenced before replay; no heartbeat-zero/purge before replay + obligation terminal; one
   GRANTS_RELEASED then one publication; C performs NO election/lease/replay-start for B (not
   merely no 'recovered' line). Negative control as proposed is correct.
