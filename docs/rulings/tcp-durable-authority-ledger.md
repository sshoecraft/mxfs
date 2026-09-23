<!-- sess418 RULE-5 ruling -->
# sess418 GPT ruling #2 — TCP durable authority backend (supersedes the bare shape (a)+)

## Why (a)+ alone is not enough (session finding, GPT concurred)
hash%N mastering => ~1/N of a victim's held resources were mastered BY THE VICTIM; that shard dies
with it => UNKNOWN => refused; and the whole-slice rule (any refused txn => TORN-UNPUBLISHED ->
quarantine) makes recovery at N=32 essentially never succeed. Also today the TCP lock arm never fills
mxfs_grant_result (grant_epoch=0, lineage=0): every TCP image is "noepoch".

## Ruling: approve a durable, single-writer TCP authority ledger — with 4 mandatory changes to "L"
1. Authority identity must survive mastership changes: a STABLE per-resource authority location
   (= the CAW slot mapping by resource hash) rather than per-master ledgers, or a verifiable durable
   handoff chain (ACTIVE/FREE/TRANSFER_PREPARED/MOVED records). Stable slot is simpler.
2. Crash-atomic updates: in-place 4 KiB RMW + crc is NOT enough (a torn page => UNKNOWN => routine
   master crashes quarantine slices again). Use two shadow copies per page (write inactive copy, flush,
   highest valid committed seq wins, never overwrite the only valid copy) or a WAL+checkpoint. Capacity:
   65536x32 B already = 2 MiB; two copies + headers do not fit by subdividing the rman slot -> a
   second/larger envelope region (mkfs/chk/PROTO_GEN bump).
3. Fence-time seal must be a STABLE CUT: SEAL(V, inc, fence_id, config_epoch) barrier to every
   surviving authority; each serialises the seal with grant/release/transfer, drains transitions
   ordered before it, records a watermark, writes a fence-specific shard (COMPLETE/UNKNOWN), flushes,
   acks; the coordinator builds the dead master's shard from its durable ledger after proving it
   fenced; global manifest valid only when every authority range is a valid shard or explicit UNKNOWN.
   Post-seal reuse rule: no incompatible successor grant on R is delivered until V's replay verdict
   for R is fixed and publication complete.
4. Token: {master_node, u32 grant_gen} insufficient. grant_id = {authority_epoch, grant_seq64}, no
   wrap; record carries fs uuid, resource type + full id, owner node + INCARNATION, mode,
   authority node + incarnation, config epoch, authority epoch, grant_seq64, dir_epoch,
   transition_seq64; FREE records keep last_grant_seq64. Absence == FREE only with complete valid
   coverage of the range.

## Protocol
- Grant: durable record -> flush -> LOCK_GRANT (group commit across grants is sound: one flush per
  batch, deliver after durability). Release: durable supersession BEFORE the release is externally
  complete / before promoting a successor (coalesce release+successor grant into one transition;
  lazy tombstone reclamation only). Never ACK a release and keep the old ACTIVE as continuity proof.
- Master loss + remap (D-0287): FENCE(M) -> read M's valid durable state -> DURABLE_IMPORT at M2 ->
  ACTIVATE (config barrier) -> first grant. Missing/corrupt/ambiguous source => UNKNOWN, never FREE.
  Live handoff: freeze R -> drain -> TRANSFER_PREPARED -> dest imports INACTIVE -> commit config ->
  source MOVED -> dest activates -> grants. Never two active authorities; "neither" is allowed.
- Membership change: the unconditional global purge goes away; replaced by freeze/transfer-import/
  activate/post-barrier GC driven from v5_membership_cb. Purge is GC only, never the transition.
- Prefer reusing the CAW authority schema + manifest_collect/verdict code ("the CAW authority table
  with a single-writer WRITE backend") over a new ledger format, but NOT the CAW physical protocol:
  neighbouring entries share a crash unit, so shadow pages / log are required.

## 15 invariants (durable-before-deliver, -release-complete, -promote; single writer per resource+
epoch; no empty reconstruction; no ABA; crash-atomic; complete negative authority; ordered handoff;
handoff continuity; stable seal cut; replay/reuse exclusion; incarnation qualification; capacity
fail-closed; corruption fail-closed) and a ~35-row crash/ordering matrix (grant/release/regrant/
batched commit/master crash/dead-master import/live transfer/seal/manifest/slot reuse/gen exhaustion/
ledger full/index corruption/membership churn/PR failure/concurrent replay) — full text in the
ask_gpt reply of sess418 (docs/tcp-authority-ledger.md carries the build plan).
