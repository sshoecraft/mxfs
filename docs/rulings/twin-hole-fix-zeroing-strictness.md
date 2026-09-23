<!-- sess412 design-consult ruling: (b) ophdr-discontinuity assembly strictness FIRST (terminal not TORN on stable snapshot), (a) claim-time FUA slice zeroing MAN… -->
# sess412 GPT ruling: twin-hole -117 fix design (follows sess411 snapshot ruling)

Context: stabilization verified working (P-FRSTAB-STABLE 3/3 arms, one full replay served from snapshot); -117 recurred FROM STABLE SNAPSHOT in the churn arm as `xlog_recover_reorder_trans: unrecognized type of log operation (0)` = twin-hole mis-assembly with read instability disproved. Idle arm's -117 was the separate icreate blanket (ledger #1).

## Ruling (implementation order)
1. **(b) FIRST/concurrent — assembly strictness**: hard invariant "no item or transaction may be assembled across an ophdr region not unambiguously owned by that transaction and expected continuation sequence". Instrument every unknown-tid ophdr (physical record location, cycle, CRC status, tid, client, flags, region count, assembly context). Unknown-tid/slack INVALIDATES any in-progress item whose region sequence would cross it; an item may never resume after an unknown/skipped/malformed region; validate first region + type before dispatching type-specific state; validate region counts/continuation flags/boundaries before an item is complete. Unknown regions provably OUTSIDE every txn span stay ignorable slack.
2. **(a) MANDATORY near-term — durable claim-time slice initialization** for (filesystem_incarnation, slice_id) pairs. Durable lifecycle record {slice_id, fs_incarnation (fresh per mkfs — sb UUID candidate), lifecycle_generation, state INIT_REQUIRED|ZEROING|READY, owner/fencing gen, CRC/version} in reserved control sectors OUTSIDE the journal payload. mkfs establishes fs incarnation + INIT_REQUIRED (need not bulk-zero; current pwrite-O_SYNC zero is untrusted). First claimant: exclusive INIT lifecycle lease -> persist ZEROING (FUA) -> zero whole 64MB payload via kernel PAL FUA path -> drain + flush barrier -> (optional zero-readback) -> persist READY (FUA, ordered) -> only then first journal write -> release lease. READY is STICKY for the fs incarnation. Crash in ZEROING => next holder RESTARTS the FULL zero (no progress metadata). NEVER zero from "no live head", node identity, adoption, or log-content inference; adoption of a used slice never zeroes; ambiguous lifecycle = fail closed. INIT lease mutually exclusive with foreign replay/snapshot/recovery/adoption/ownership/reassignment.
3. **(c) Phase-4 per-record incarnation stamp**: still required (rollback/cloning/init-bug/stale-media provenance).

## Retry classification
Discontinuity detected from a PROVEN-STABLE snapshot = **terminal for that snapshot + lifecycle generation** (re-read cannot change bytes) — distinct fail-closed status (LOG_OPHDR_DISCONTINUITY / EUCLEAN-class), NOT 'TORN', not retryable; quarantine may still apply (committed txns can't be discarded) but it must be reported as a diagnosable assembly refusal with telemetry (offsets, tids, cycles, CRC results, snapshot hash). Before stabilization succeeded, the existing retryable classes still apply.

## 2026-09-19 consult (Astra): a recovery-side uuid mask is NOT a substitute for item (a)

Asked, with the s60j measurement in hand (a slice planted with a previous
incarnation's records beyond a zero block 0: first mount clean, a committed
log-forced transaction, then recovery landing on a stale header and refusing
the slice, the node unmountable): whether serving every block not covered by
a current-sb_uuid record header as zero to head/tail discovery (nothing
written to the platter) is sound as the fix. Ruling: **no — implement (a).**

- Header coverage is not the set of blocks whose cycle stamps matter. After
  a wrap, an obsolete record's body blocks can lose their header to a later,
  shorter record while their cycle stamps remain exactly what the head search
  reads (block 0 carrying the newer cycle, the final blocks the previous one).
  Masked to zero, `xlog_find_zeroed` reads block 0 as "totally zeroed log" and
  recovery is skipped with required, forced transactions still in the slice:
  silent omission, worse than the refusal it replaces. No foreign bytes needed.
- A torn current record with a correct `h_len` leaves foreign bytes inside
  its advertised extent; the mask does not produce the image durable zeroing
  would have produced, and discovery consumes cycle stamps before any record
  validation can save it.
- "Never zero from inference" is about recovery semantics, not platter
  writes: removing information from recovery's input has the same data-loss
  consequence as removing it from the disk. A malformed or null-uuid header
  must never become "unmarked, therefore zero" — that suppresses the evidence
  of corruption; report it or handle it by a rule that establishes it is an
  incomplete head record.
- (a)'s encoding is not mathematically minimal (INIT_REQUIRED can double as
  "interrupted, restart in full"; a device zero-out may replace a stream of
  zero buffers; records may live in one reserved control area rather than
  beside each slice) but its guarantees are: durable binding to fs
  incarnation and slice, unambiguous authority to initialise (the exclusive
  claim), fencing of every other writer, durable completion before READY, no
  journal write before READY is durable, and no initialisation of an
  ambiguous or possibly used slice. A volume formatted before the region
  exists keeps today's behaviour; never synthesise INIT_REQUIRED for an
  existing slice.
- Lazy activation "when a foreign header is first met" is too late: discovery
  consumes foreign cycle stamps from data blocks and chooses branches before
  any uuid check.

## Sequencing plan (the instrument-first loop: one fix, measure, next)
- Land (b) as 0.27.2 -> rerun churn arm -> expect clean diagnosable refusal, NO type-0/di_magic garbage.
- Land (a) as 0.28.0 (envelope format work: mkfs_mxfs lifecycle records + dlm claim-path zeroing) -> rerun -> holes zeroed.
- NOTE: a churn arm still cannot COMPLETE replay until ledger #1's icreate tokenization lands (every churn slice carries ICREATE images; the enforce blanket ATOMIC-SKIPs them and refuses the slice — observed fln6_log_idle sbreason=2 nonbuf_taint=1). Full chain = (b) + (a) + icreate authority.
