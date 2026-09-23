<!-- sess422-425: tauth step3 landed, step4 ordered-handoff design ruling, ghost-grant + mount-barrier rulings, two DOUBLE-GRANT wedges (D-0341/D-0342) fo… -->
# TCP durable authority ledger (tauth): step 3 landing, step 4 design, and the two DOUBLE-GRANT wedges (sess422-425, 0.34.0-0.35.2)

Continuation of the tcp-authority-ledger campaign (docs/tcp-authority-ledger.md) past step 3.
Central failure mode across the whole arc: a page's ownership decision (grant/release/handoff)
can be made durable by the master while the *delivery* or *retirement* of that decision is lost,
deferred, or ignored — leaving either a double grant (two nodes think they hold the same page) or
a page stuck FROZEN forever. Every session below is one more class of this same hazard.

## sess422 — step 3 landed (0.34.0) `docs/history/docs/history/docs/history/compiled-tauth-step3-step4-campaign.md`

`dlm/tauth_ledger.{c,h}`: ledger layer over the shadow-page store (per-page cached image+mutex,
ensure/lookup/scan_active/commit/purge_owner, poison+reconcile, fail-closed refusals).
`dlm/dlm.c`: page-aligned mastership, `dlm_txn` commit/finalize/promote/grant machinery, every
grant PENDING_DURABLE -> ledger -> GRANTED -> deliver, every release PENDING_RELEASE -> one
transition with successors -> ACK, blocker import on prepare, membership purge KEEPS the purged
owner's own GRANTED/PENDING entries (D-0287). `dlm/v5_mount.c`: ledger open+attach at TCP slot
claim (open failure refuses mount), purge_owner wired at all 6 purge sites.

Two bugs the harness found and fixed before landing:
1. A PR grant must JOIN the record lineage, not overwrite it — overwriting caused an earlier PR
   holder's release to see -ESTALE and get stuck forever.
2. `ledger_gen` must be MONOTONIC (view_seq), not reset on view flap — an A->B->A view flap that
   reused the generation caused stale cached pages to be trusted.

52+11 test groups passed in usermode (`tests/tauth`) before the rig cycle. This step-3 landing is
the durable-grant/release/blocker-import baseline every later bug in this arc violates in some
edge.

## sess423 — step 4 design hole + RULE-5 ruling: ordered mastership handoff `docs/rulings/tauth-step4-ordered-handoff.md`

The hole step 3 leaves open: step 3's page_write readback only validates crc+seq. Old owner A
(lagging view) and new owner B can both read page P at seq s, both target the same shadow copy,
both write s+1; the loser's readback finds the WINNER's valid s+1 image and reports durable too —
**both deliver**, and nothing later detects it. Only the 20s EX settle gate stands in the way, and
PR is ungated entirely.

Ruling (14 items, binding shape for step 4):
- Durable per-page transfer state, not a RAM freeze: `ACTIVE(A) -> TRANSFER_PREPARED(target=B,
  config_id, nonce, prepared_seq) -> ACTIVE(B) at prepared_seq+1`. A closes admission, drains,
  writes PREPARED, exact-readback-verifies, THEN sends FROZEN naming {page, prepared_seq, target,
  config, nonce}. B must fresh-read (two-shadow, not cached) the exact PREPARED before consuming.
- View-hash equality is a live rendezvous check only, never an authority token; config id covers
  full member list + incarnations + a linearized transition number.
- Dead predecessor: readback alone does not stop sequential same-seq overwrite by two divergent
  successors. Needs an ordered departure certificate naming the UNIQUE immediate successor per
  page — mapped this session to the existing disklock recovery descriptor (single elected replayer
  with term + takeover-on-abandonment + fence certificate).
- Clean departure: M must durably PREPARE every owned page to its successor before GOODBYE.
- PR preempt-and-abort only counts as a fence when it is a VERIFIED certificate bound to LUN + old
  node/inc + key gen + config transition; else fail closed.
- Every timeout fails closed (parked-request expiry cancels, never grants; freeze/drain timeout
  makes the page non-serving + reconcile/poison, never thaws; PREPARED never clears on a timer).
- Reads: full 4KiB memcmp readback + a random/monotonic write_nonce (a stamp_ms is not unique);
  two shadows at equal seq with different content = conflicted -> poison, never pick one.
- Commit legal only when durable state is ACTIVE and authority == self{node,inc}; only exception
  writers are the named PREPARED target and a certified recovery successor.
- UNOWNED pages (mkfs state) activate only via the lowest LIVE heartbeat slot (shared-disk
  arbitration); everyone else gets them by live handoff.
- Do not land step 4 without: durable PREPARED->MOVED, immutable transfer cookies + stale
  rejection, a unique ordered successor for both clean and dead departures, precise freeze/drain/
  delivery barriers, fail-closed timeouts, and the expanded fault matrix (grant/release racing the
  barrier, crash at every phase, A->B->A / A->B->C stale messages, equal-seq divergent shadows,
  same node new incarnation, dead-owner double successor, etc).

## sess424 — step 4 usermode-green, v5 wiring owed; then the TCP rig wedges

Engine work: `docs/history/docs/history/docs/history/compiled-tauth-step3-step4-campaign.md` — `tests/tauth`
adapted to step-4 page authority (bootstrap activate, PREPARED->ACTIVE takeover from a dead
authority, idempotent-prepare/wrong-victim/wrong-seq/retarget-without-proof refusals), all green
in usermode. Engine facts learned: `dlm_page_acquire` parks a node's OWN old incarnation at
-EAGAIN forever until `mxfs_dlm_handoff_takeover` runs for it — v5 must self-takeover its own
previous incarnation at mount; REMASTER (status 12) retries a requester 10x then fails
"lock request failed after 10 retries"; `dlm_owner_purged()` retargets PREPAREDs aimed at dead
targets. v5_mount.c wiring (bootstrap_cb, node_inc_cb, PAGE_HANDOFF dispatch, handoff_tick in the
TCP death worker, handoff_takeover at all 6 purge sites + own prior incarnation, handoff_depart
before GOODBYE, set_config_id on view change) was left NOT done at session end.

Rig run of 0.34.0 (step-3-only) then 0.35.0 (ghost-grant fix + step-4 wiring) on 32-node TCP both
failed mount with root-inode EX refused for 125-208s -> shutdown -> "can't read superblock", with
`P-TAUTH-DOUBLE-GRANT` in the masters' logs.

**Ghost-grant root cause + ruling** `docs/rulings/ghost-grant-delivery-and-unresolved-pr-bits.md`:
`dlm_txn_finalize` refused delivery whenever `ctx->ledger_gen != txn->gen` **after a successful
durable commit**, freed the table entry, and answered REMASTER — the granted bit was never
retired, producing an unresolved PR holder (P-TAUTH-GHOST) that every later EX request timed out
against (-110). Ruling: (1) a successful authority commit is deliverable regardless of a later
gen change — gen is checked pre-commit and for routing only, never post-commit; (2) never
compensate a send failure with a release — X may already be using the grant; retransmit the same
idempotent grant or forward intent to the current authority instead; (3) an unresolved PR bit must
fail closed (block EX, allow compatible PR) until fencing/recovery proves the slot's incarnation
dead — never retire it on timeout+EMPTY; (4) long-term, a slot-indexed bitmap can't distinguish an
old holder from a new occupant — needs durable {node,incarnation} per shared holder.

**Mount barrier "resolved elsewhere" ruling** `docs/rulings/barrier-resolved-elsewhere.md`
(D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE): measured — A mounting holds the barrier, B dies, the
survivor (lowest live slot) completes B's recovery on the live path, but the barrier never retires
bit 31 because nothing retires a bit another node completed, so recovery_acquire loops -ENOENT and
mount aborts over an already-replay-complete slice. Ruling: completion proof must be POSITIVE and
incarnation-bound (only a valid ZERO sector, or a valid ACTIVE successor of a DIFFERENT
incarnation, ever retires a bit — "not holding the victim" is too weak); requires an
armed->resolved lineage (three-state UNSEEN/PENDING/RESOLVED), not just "marker not pending"; must
NOT suppress survivor election during a mount — either path may resolve it, the descriptor already
serializes the single replayer. Landed same session: `mxfs_disklock_slot_terminal_for`,
`mphase_dead_epoch[]`/`mphase_resolved_mask/node[]` in v5_recovered_cb,
`mxfs_v5_dlm_mount_resolved_elsewhere`, barrier drops resolved bits from cohort/drained.

**0.35.0 rig result** `docs/history/end-state-and-next.md`: ghost-grant fix built+deployed,
step-4 wiring in, but 32/tcp still failed 26/32 mounts — a NEW wedge. test1 (bootstrap) activated
page 1786 (ino 128's page) and PREPAREd it to test2 on view-change; test2 activated it, imported 3
PR holders, then hit DOUBLE-GRANT again (decided EX over an imported PR holder still in the
record); then 94x `P-TAUTH-FREEZE-DRAIN-TIMEOUT` on page 1786 — the page stayed FROZEN forever
because `dlm_page_freeze_drain` waits for `dlm_page_has_pending(page)==false`, and a PENDING_DURABLE
/PENDING_RELEASE entry belonging to a refused/abandoned txn never clears. Every later requester got
REMASTER fleet-wide (4381x) and 26 mounts aborted. Root cause deferred to sess425 (H2:
`dlm_page_has_pending` + every `dlm_txn_*` error path that can leave an entry PENDING; H3: why EX
was decided over an imported PR holder — was it dropped by the membership purge and not
re-imported because `page_import_gen` already matched?).

## sess425 — the two PENDING-entry wedges, ruled and fixed

**D-0341: concurrent-release DOUBLE-GRANT wedge** `docs/rulings/concurrent-release-fix-shape.md`.
Deterministic usermode repro (`tests/tauth/concurrent_release_test`) confirmed H2/H3:
`promote_waiters` ignored EVERY PENDING_RELEASE holder, so EX got decided over a sibling's still-
durable bit; the resulting bundle [REL, GRANT] was refused -EBUSY, stranding the release entry in
PENDING_RELEASE forever, and the releaser's retry got ACKed OK as a "duplicate" — so the page never
drained. Ruling: ignore a PENDING_RELEASE only when it is the exact entry/gen being released by the
txn under construction; every other PENDING_RELEASE and every PENDING_DURABLE blocks with its
durable mode. Governing invariant: **every terminal retirement (local, remote, bundled,
release-only fallback) removes the entry under the table write lock and THEN runs promotion** — the
last of concurrent finalizers sees all earlier removals, no lost wakeup. On a definitive
grant-attributable refusal the master re-commits the release alone and denies/rolls back the
grants; a retry that finds PENDING_RELEASE must attach/kick or say "still pending", never ACK OK
until durable retirement or supersession is proven. Landed 0.35.1: `promote_waiters(...,txn)` +
`dlm_txn_retires`, re-scan on `retired`, `ack_deferred` + `dlm_txn_recommit_releases` on a refused
bundle, `dlm_mark_release_stuck` + `dlm_release_redrive_tick`, `MXFS_ERR_LEDGER_BUSY`. Verified:
32/32 tcp mounts x2, sweeps clean, 32/caw board 28/28+policy.

**D-0342: partial ledger purge ignored** `docs/rulings/partial-ledger-purge-held-failure.md`.
All 6 `mxfs_dlm_ledger_purge_owner` callers (goodbye, fenced-slotless, node-death, recovered_cb,
clean_depart, recovery_complete2) plus one lazy caller ignored its return code — dropping imported
blockers and, at recovery_complete2, republishing the slot EMPTY over still-retained bits (rig:
`P-TAUTH-PURGE-PARTIAL rc=-5` during 0.34.0 formation). Ruling: a non-zero purge at
recovery-complete is a HELD failure exactly like the hb-purge failure at the same site — ladder
retries, keyed by the old occupant {node,inc/epoch} not slot number. A successful purge must be
durably committed BEFORE dropping blockers or publishing EMPTY. -ESTALE on a page during the purge
walk means the successor now owns the purge obligation and must apply the tombstone ON IMPORT
before the page is grantable, and the tombstone must survive the view change; -ESTALE stops the
walk but is not whole-operation success — restart/rescan against the current ownership set until a
complete pass returns 0, only then drop that master's blockers. Fix plan for 0.35.2: purge failure
adds {node,slot,inc} to a master-owned dedup purge-pending list and keeps blockers; the release
retry tick re-runs the purge until a full pass returns 0; recovery_complete2 sets
`V5_COMPLETE_HELD_FAIL` on rc!=0 before purge_node/takeover/disklock purge.

**sess425 end state** `docs/history/docs/history/docs/history/compiled-tauth-step3-step4-campaign.md`: 0.35.1 (D-0341 fix) verified
32/32 tcp + 28/28 board. 0.35.2 (D-0342/0343/0344) also landed: 32/32 tcp mounts clean, but token
verify and d0287 setup hit a NEW shape — D-0345 (AG EX remaster=60 tally, "failed after 10 retries")
— instrumentation added (`P-TAUTH-REMASTER-VIEW`/`-PARKED`/`-RX`, `P-TAUTH-HANDOFF-DEFER`,
membership `view=<hash>` logging) and a fresh rig cycle (s427, 0.35.3) launched to diagnose it. The
32/caw board also showed `fence_during_write` FAIL (mkdir ESTALE on a recreated shared dir,
D-0346) — filed as CAW-only and unrelated to this campaign's TCP changes.

## Net trajectory

step3 (grant/release/blocker durability) -> step4 design ruling (ordered handoff prevents dual
delivery on page transfer) -> two independent PENDING-entry bugs found only under 32-node TCP load
(ghost grant on gen-mismatch delivery refusal; PENDING_RELEASE starvation under promote_waiters) ->
both fixed and rig-verified -> a third distinct remaster-storm shape (D-0345) still open at sess425
close, instrumentation in flight. The recurring lesson: every point where a durable decision and
its delivery/retirement are two separate steps is a wedge candidate, and usermode tests alone did
not surface any of the three real bugs — all three needed the 32-node TCP rig under load.
