<!-- sess418 RULE-5 ruling D-0288 (TCP foreign replay always refused): shape (a)+ = masters seal victim grants into per-victim manifest shards post-fence;… -->
# sess418 GPT ruling (gpt-5.6-sol) — D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-0288

## Finding that prompted it
0.29.0 first TCP lap (tests/evidence/20260828T043116Z_d0286tcp): 3/3 dead-node slices refused
(P227-FR-ATOMIC-SKIP every txn -> TORN-UNPUBLISHED -117 -> P240-QUAR-IMPORT), peers' reads EIO after
185 s (P240-QUAR-EIO-ABORT). Cause: the image-authority gate's evidence (lineage v3 + FENCED cert +
held MANIFEST grant + epoch) comes from the CAW slot table / fence-time manifest; TCP has neither ->
n_wapply=n_redund=0 -> never admissible. Same injected deaths on CAW replay in 70 s.

## Ruling: shape (a) as "A+" — never weaken the gate; give TCP equivalent durable evidence
- REJECT (b) (fence + lineage + di_changecount as authority): proves nothing about the commit->fence
  interval (release, regrant by another owner, home write of a newer image, then victim fenced ->
  replaying the old image tears). changecount is a stale-image detector, not authority.
- (c) victim-written grant list = a CLAIM, not authority, unless it becomes a master-authorized
  durable grant ledger (grant not usable until its durable record is acked) — bigger protocol change.
- (d) TCP unsupported = product decision (user's), not the session's. Until fixed, document that TCP
  cannot recover dirty deaths.

## What a TCP "held manifest grant" must certify
The victim incarnation held the required exclusive write grant for EXACTLY this resource under
tenure id G when the image committed; that tenure stayed continuously in force (no release/revoke/
convert/purge/regrant) until the victim was storage-fenced and its in-flight writes quiesced; and an
authoritative master snapshot taken AFTER the fence confirms it still held. Identity = {resource+
scope, mode, victim slot+incarnation, grant-tenure epoch/token, master incarnation or DLM config
generation, lineage version}; the txn image carries the same tenure id.

## Protocol (order is an invariant — never reorder)
effective fence/quiescence -> masters snapshot their victim-owned grants -> durable per-victim,
per-incarnation manifest SHARDS (checksummed, bound to fence cert + DLM generation + master
incarnation) -> durable shard completion marks -> BARRIER: header lists every expected master shard as
SEALED or UNKNOWN (absence != empty) -> only then purge/promotion/regrant -> replay through the
UNCHANGED gate (image admissible iff resource+tenure token match a positive entry in a SEALED shard;
unknown shard => refuse; atomic per-txn; quarantine stays).

## Invariants
1. Unique transport-neutral grant tenure token (new lineage version / abstract authority field:
   {resource, victim-inc, master-inc/config-gen, grant-epoch}); epoch allocation must survive master loss.
2. Commit-to-fence continuity: release/purge/convert/regrant terminates the token permanently.
3. Seal ordering (above). 4. Explicit completeness (dead/unsealed master = UNKNOWN, never empty).
5. No stale-master authority (partitioned/superseded master cannot seal or grant).
6. Fail closed on any corrupt/absent/ambiguous evidence. 7. Publication atomicity.

## D-0287 is part of the same fix
The membership-change table purge must become a LATE phase of the recovery state machine
(freeze -> fence -> seal/reconstruct -> barrier -> purge/rebuild); purging first destroys the only
TCP authority evidence; a replacement master must never read an empty table as "no prior grant".
Full recovery under simultaneous victim+master loss additionally needs replicated/durable master
grant state (grant unusable until its backup exists); without it A+ recovers only when the relevant
masters survive (their shards UNKNOWN otherwise, fail-closed).

## Verification (deterministic), 20 cases — key ones
single victim/all masters survive == CAW behaviour; grants across every master + shard count;
coordinator crash during sealing (idempotent resume); release/reacquire -> old token refused;
convert/downgrade before fence -> refused; stale victim/master inc, reused epoch, wrong gen -> refused;
valid changecount but no manifest grant -> refused; crash after EVERY durable transition (fence,
quiesce, freeze, each shard write, completion, barrier, purge, promotion, replay, publication) ->
only proven replay or fail-closed; victim+master die together -> that master's buckets UNKNOWN;
master dies after seal/before barrier -> shard usable; membership change at every seal point ->
purge never precedes seal/UNKNOWN; cross-master txn with one unknown shard -> whole txn skipped;
corrupt/truncated/duplicate manifest -> refuse; delayed victim writes around fencing -> replay waits
for the storage contract.
