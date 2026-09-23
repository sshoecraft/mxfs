<!-- sess421 RULE-5 rulings for tcp-authority-ledger step 3: page-aligned mastership, PENDING_DURABLE, release ACK, owner inc, blocker import, entry = CAW… -->
# sess421 GPT rulings — step 3 (master-side ledger) design

## Ruling 1 (design review) — approved with mandatory changes
1. Page-aligned mastership APPROVED: slot = hash%65536, page = slot/31, master = active_nodes[page % N];
   every routing/validation site must use it.  BUT page ownership must be FENCED across membership
   transitions: revoke old ownership generation, stop old commits/deliveries, drain or storage-fence
   the old node, then the new master loads (invalidate cache, reload both copies).  Every pending op
   carries the page-ownership/membership generation, rechecked before I/O and before delivery.
   Slot collision (two resources same slot): record carries full resource identity; mismatch => fail
   closed.
2. authority_epoch must be a non-reusable writer generation: {persistent membership epoch (bound to fs
   uuid / persistent monotonic gen, or proven non-reusing), page_master_node, page_master_inc}.
   Per-page persisted grant_seq_next in the checksummed page header; distinct seq per grant in a
   batch; exhaustion fails closed; takeover reloads highest valid copy first; never relabel existing
   ACTIVE records with the new master's epoch; page commit seq and grant_seq64 are distinct fields.
3. Grant path: explicit PENDING_DURABLE_GRANT table state (counts as holder for compat, not returned,
   not sent, blocks other transitions on the resource).  Sequence: decide+install pending under
   table_rwlock; unlock; page mutex; revalidate ownership gen; patch LATEST cached image under the
   mutex; page_write; on verified success update cached committed image; mark delivered; recheck gen;
   send/return.  Per-resource op serialization too (page mutex alone does not order grant/release/
   upgrade/reaffirm logically).  Failure: proven-not-committed => cancel+deny; UNCERTAIN => poison the
   page, reread both copies, reconcile before any further op; never rollback an uncertain ACTIVE to
   FREE in memory; a durable-but-undelivered grant is a ghost that stays a blocker until superseded.
   Group commit fine; nothing in the group is sent before the whole page transition verifies.
4. Release: ACK REQUIRED.  Validate releaser {node, inc, full grant_id}; install pending release
   keeping the old holder effective; successors pending; commit ONE page transition; then deliver
   successor grants + RELEASE_ACK (either order, neither before commit).  Releaser may stop using the
   lock but keeps pending-release/retry state and may not report release/unmount complete until ACK.
   Idempotent: duplicate release joins; release after supersession => ACK w/o clearing successor;
   stale release never removes a later grant (needs full grant_id on LOCK_RELEASE).
5. Owner incarnation on LOCK_REQ, persisted {node, mount_inc}; full grant_id on LOCK_GRANT,
   LOCK_RELEASE, RELEASE_ACK, upgrade, reaffirm/retry.
6. ACTIVE records found on page load MUST be honoured (ledger-backed blocker import) — may block
   until recovery proves fence+purge; never cleared because epoch old / owner absent / table purged.
   Blockers must survive the membership-change table purge (separate state or reload before any
   compat decision).  P-TAUTH-IMPORT-ACTIVE line accompanies, never replaces.
7. Keep per-commit readback verify.  Throughput via batching/one flush per batch only.
A. Multi-holder representation must be complete (=> ruling 2).  B. Activation barrier: no in-memory
   grants may coexist with EMPTY records (clean-cluster activation or freeze/drain + populate).
C. Cache authoritative only while owning the page in the current fenced gen, no uncertain write, no
   corruption; never synthesize EMPTY.  D. Requester op/request id for idempotent retries; a committed
   grant whose LOCK_GRANT send failed must be found and returned, not granted around.  E. Commit-then-
   ownership-change: old gen must not deliver; record stays and is imported; requester retries against
   the new master; requesters reject grants from obsolete master/gen.  F. No grant on an unread/invalid/
   colliding/exhausted slot.  G. fail closed on seq exhaustion, holder capacity, collision, no valid
   copy, inconsistent duplicates, unreconcilable uncertain write, unsupported version.

## Ruling 2 (multi-holder) — option (b) CHOSEN, layout frozen
- 128-byte CAW-style entry: 64-bit PR holders SLOT bitmap + shared mode + ONE explicit EX/PW holder
  {node, inc, grant_id} + resource lineage + full resource identity; per-page grant_seq_next.
- PR acquire/reaffirm/release carry {resource_lineage, slot, node_id, incarnation}; a PR release clears
  holders[slot] only if lineage matches, the CURRENT HB row for slot == {node_id, incarnation} (the
  message must CARRY the inc; never infer from the HB row), the request is in the current lock-service
  epoch / current in-memory PR grant (same-incarnation release/regrant ABA is the live protocol's job:
  grant handle/request seq + lock-service epoch; old-epoch messages rejected, holders reaffirm), and the
  bit is set.  Mismatch => stale, bitmap untouched; cleanup is recovery's job.  Reaffirm validates a set
  bit, never recreates a clear one.
- No per-holder grant_seq for PR (PR writes no images).  EX/PW keeps explicit {identity, mode, grant_id}.
- Seal: expand every set PR bit into {slot, node_id, incarnation, PR} from the HB table while slot
  reclamation is excluded; unresolved bit = seal failure (never omitted); record lineage, entry/page
  seq at snapshot, shared_mode, expanded list.
