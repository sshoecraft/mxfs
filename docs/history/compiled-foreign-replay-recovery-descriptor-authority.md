<!-- sess49,63-67,102,161: durable recovery-descriptor design (GUARD stages, owner_term/recovery_gen split) + authority-token capture-at-first-dirty rulin… -->
# Foreign-replay recovery descriptor & authority-token design (sess49, sess63-67, sess102, sess161)

Central topic: making foreign/adopted journal-slice replay of a dead node's writes safe —
(a) a durable on-disk recovery descriptor that tracks recovery progress and ownership
across crashes/takeovers, and (b) per-buffer authority tokens that let replay tell which
logged images were actually authorized, so the blanket ATOMIC-SKIP gate can be replaced by
selective, transaction-atomic APPLY. The two threads converge: the descriptor governs
*when/who* replays a dead node's slice; the token governs *what* in that slice is safe to
apply.

## Token parser, step 3b — shipped first, proves the shape of the eventual gate

`docs/history/docs/history/docs/history/compiled-foreign-replay-recovery-descriptor-authority.md` (0.11.398): report-only
`mxfs_blf_parse_authority()` decodes the sess48 authority trailer during real foreign
replay, logging per-item/per-transaction tokens but deciding nothing (ATOMIC-SKIP and P223
stay byte-identical). Live 32-node proof: a 43-item transaction with all 3 buffer images
correctly tokened (AG 18, arithmetically verified against `chk_mxfs` geometry,
`owner_slot` == the dead node's disklock slot) was still ATOMIC-SKIPped, because the
taint scan trips on item *type*, not authority — exactly the case step 5 must convert to
APPLY. Caveat: the exercised workload left only 1 dirty foreign transaction with buffer
items — too thin to trust a gate's "verified" status; step 5's A/B needs a heavier
dirty-writer workload.

## Recovery descriptor design and build (sess63 → sess67)

`docs/rulings/intents-abandoned-and-gpt-item3-ruling.md`: proved a dead node's
journal intents and iunlink/AGI obligations are processed by **nobody** — the "next
claimer does full replay" premise in `mxfs_xlog_recover_foreign_slice()` is false because
the next claimer is *always* an adopted-slice mount, which shares every intent-skip with
foreign replay. Filed D-FOREIGN-SLICE-INTENTS-ABANDONED (critical). Also found: the
transaction-atomic taint gate applies almost nothing but pure-inode transactions (any
BUF/DQUOT/QUOTAOFF/ICREATE item taints), and MXFS's ro_compat is FINOBT-only (reflink/
rmapbt off) — GPT still refused to let that excuse ignoring BUI.

GPT's binding ruling from that session set the whole subsequent design:
- Milestone state machine, not a stage byte: `ACTIVE → GUARD{FENCED, IMAGES_REPLAYED,
  OBLIGATIONS_DONE, GRANTS_RELEASED} → CONSUMABLE` (zeroed), carrying victim identity +
  recovery generation + owner + slice identity + stage + crc. Never overwrite victim
  identity with the recovery holder's.
- CAS to GUARD(FENCED) must be durable **before** any CAW purge (the opposite order is a
  crash hole).
- The peer "slot no longer ACTIVE" broadcast predicate must split: victim-fenced vs.
  victim-grants-released are different facts, or the first GUARD transition tells peers
  to drop grants recovery is deliberately still freezing.
- A stale GUARD is a recovery lease, never a claimable member slot.
- Intent policy = complete directly from the recovery context (not re-log as our own) —
  no atomic commit exists between the HB descriptor and the live log, so either ordering
  of the re-log alternative creates a double-free or a lost obligation.
- Intent/done matching: admitted+done-admitted = cancel; admitted+done-absent = recover;
  intent-rejected = quarantine; **admitted+done-rejected = AMBIGUOUS, quarantine, never
  guess**.
- Late completion is EFI-only; RUI/CUI/BUI don't inherit the parked-extent argument —
  support BUI or quarantine the slice.
- AGI sweep: `nlink==0` does not prove no peer has the inode open — needs distributed
  inode authority, not a local `iget`.
- Purge-then-reacquire of victim AG grants is forbidden; needs atomic CAS transfer.
- Sequencing (load-bearing for everything after): descriptor+freeze → quarantine terminal
  state → report-only admission + intent/done inventory → authority transfer → intent
  completion → gate swap → final release. Step 5 (exact-match token gate) must NOT ship
  before intent completion — shipping it first admits more transactions with real pending
  obligations that still get finished by nobody, which is strictly worse.

`docs/history/docs/history/docs/history/compiled-foreign-replay-recovery-descriptor-authority.md` (0.11.408): wire format
for step 1 — `struct mxfs_recov_desc` (80 B) + `mxfs_recov_body`, encoding the sess63
rules. Placement: no on-disk growth needed — the descriptor is a union member overlaid on
the evict ring inside a GUARD record, which is dead space there (ring is produced only
into ACTIVE records and consumed only from peers' ACTIVE records). Stages: NONE 0, FENCED
1, IMAGES_REPLAYED 2, OBLIGATIONS_DONE 3, GRANTS_RELEASED 4; CONSUMABLE = absent record.
`MXFS_RECOV_F_QUARANTINED` is terminal. Found and fixed en route: `MXFS_BUILD_CHECK_HB()`
was referenced by nothing — the kernel-side layout guard had never run. Type-level only,
byte-identical runtime behavior, do-not-board.

`docs/history/docs/history/docs/history/compiled-foreign-replay-recovery-descriptor-authority.md` (0.11.409): the .c side —
three predicates of deliberately different strictness (`recov_desc_of` strict/interpret,
`recov_lease_covers` conservative/never-destroy-on-doubt, `recov_desc_names` strict
identity) — this distinction *is* the safety argument. Five ops (begin/advance/refresh/
read/takeover) go through `recov_cas_durable()`: CAS from the exact observed image, FUA
write + cache-piercing readback memcmp, `mxfs_pal_bdev_flush()`; a lost CAS returns
`-EAGAIN` and is never retried inside — caller must re-read and re-decide. `begin()`
preserves the victim record byte-for-byte except flags; `victim_epoch` argument is a
cross-check only, not a precondition (making it one would add a new permanent-failure
mode for recovery publication) — disagreement just logs P234-RECOV-EPOCH-DRIFT. Four
freeze sites landed: split broadcast predicate (`hb_still_dead_stamp`), `purge_node`
phase-0 HB-scan gate (refuses on unreadable descriptor/QUARANTINED/stage<GRANTS_RELEASED/
not-ours), `guard_slot`/`slot_unclaimed` refusal (a descriptor-bearing guard is never
takeable by the sess43 abandoned-guard sweep, even when stamp-abandoned), `find_node_slot`
disk-scan GUARD-with-descriptor match (without it, a peer that never witnessed the death
falls into "owns no slice → purge immediately" and destroys in-memory grants for a
mid-recovery slice). Honest gaps left open: `begin()` runs at recovery-**complete** time,
not fence time, so it doesn't cover the replay window itself; `refresh`/`takeover` have
zero callers yet.

`docs/rulings/recovery-coordinator-and-pending-is-volatile.md`: the
load-bearing fact that reframed the next increment — `mxfs_disklock_mark_recovery_pending`
does **no device I/O**, it's purely per-node volatile in-memory state (a stale comment
claiming otherwise was corrected). Consequence: the pre-descriptor reservation window is
protected only by the victim's own stale `ACTIVE` sector (a slot is claimable only when
NOT `ACTIVE`, however stale) — any future change letting a claimant reclaim an
"abandoned" ACTIVE slot removes the only protection this window has. GPT's ruling: move
`begin()` to fence time via a **dedicated coordinator thread** (not the HB monitor, not
the replay worker, not `system_unbound_wq`) — monitor only fences/notes/marks-pending/
schedules; coordinator revalidates and does `begin(FENCED)`. Once a descriptor exists it
is the authoritative owner election (lowest-live-slot is only for the initial claimant).
`takeover` is required now for liveness, but a stalled `owner_stamp_ms` alone never proves
the old owner can't resume — safe takeover requires the owner's session confirmed dead
**and** fenced from the LUN first. Refresh cadence 1000 ms, abandonment probe 6000 ms
(not the then-current 3000 ms, too aggressive for a correctness lease). Durable CAS+
readback+flush must stay off every monitor thread. Mount window must not acquire
ownership unless the local replay service is registered and capable. Requires a wire
change: `recovery_gen` must stay constant across takeover (identifies the recovery
transaction); a new `owner_term` field identifies current executing authority — without
the split there's an ABA hole (A→B→A within one session of A leaves `{owner_node,
owner_epoch}` unchanged, so a stale A worker looks current).

`docs/history/docs/history/compiled-foreign-replay-recovery-descriptor-authority.md` (0.11.410): the wire change
landed — `reserved` field repurposed as `owner_term`; `recovery_gen` now documented as
constant from `begin()` to final zero; new `struct mxfs_recov_auth` (victim identity +
recovery_gen + owner_term + slot + stage) issued by begin/takeover, demanded back by
advance/refresh (mismatch → new P234-RECOV-NOTOURS / -ESTALE); `MXFS_RECOV_ABANDON_MS`
6000 added, separate from the 1000 ms refresh cadence; takeover now sleeps the full
abandon window inside the call (so it can never run on the HB monitor thread) and
preserves `recovery_gen` while moving `owner_term`+`stage_seq`. Format was still free to
change (no rig build had ever written a descriptor). Coordinator thread itself designed
but not yet written: per-slot state array, 1 s pass doing (a) refresh every owned
nonterminal descriptor, (b) an acquisition sweep gated on replay-capability. Open hole
flagged for the same increment: the pending marker is per-node volatile (sess66), so if
every witness of a death reboots, nobody ever takes over an abandoned descriptor — fix is
a slower-cadence sweep of not-live/not-ours slots. 0.11.402–410 had never had a rig cycle
at this point.

## Authority-token capture point ruling (sess102)

`docs/rulings/capture-at-first-dirty-not-format.md`: RULE-5 ruling on
where the per-buffer authority proof must be captured for the replay-side token (the
step-5.3 blocker). Measured P239-OWNAUTH first (format-time authority lookup): 99.95%
durable on an rsync-heavy window, 92.49%/7.13%-none on a dir-heavy window, unpub/uncached
always 0 — but the ruling is that **this histogram does not license format-time
stamping**. Format-time lookup is unsound in both directions: a mutation under epoch E1,
released, reacquired under E2, then formatted, scores "durable" with a **false** token;
conversely a format-time NONE can just mean authority was released after a perfectly
authorized mutation. Binding fixes:
- Capture the proof at first protected dirty (the `xfs_trans_dirty_buf`/join seam, or
  first `xfs_trans_log_buf`), store it in the buf log item/transaction sidecar; the
  formatter only serializes what was already captured. Required invariants: proof
  immutable after first dirty; re-logging the same buffer in one transaction must match
  the same authority+epoch (assert on mismatch); authority can't be released before the
  transaction captured its proof; a buffer with changes from different authority
  objects/epochs can't be represented by one whole-buffer token.
- Producer-owned outcome enum (`mxfs_grant_outcome`: PROVED/OBS_SHARED/EX_NO_EPOCH/
  NO_TENURE/STALE/RELEASING/OTHER_REFUSAL) instead of ad hoc proof-field filling on
  refusal, plus a fixed structural bug this ruling uncovered: `mxfs_grant_result`'s two
  producers both correctly gate `valid==1` on mode∈{EX,PW}+epoch!=0, but the consumer
  tested `!valid` before mode — making the shared/no-epoch counters structurally
  unreachable, so "notvalid" numbers from sess101 could not distinguish benign shared
  grants from real plumbing holes.
- Every unproven image must resolve at capture time — "rare" is not a disposition.
- Replay gating must be **transaction-atomic**: applying authorized images while skipping
  unproven ones in the same transaction manufactures states no node ever created; the
  correct default for an unproven image is to fail the whole transaction closed (no
  skip-forward), preferably via a two-pass validate-then-replay design.
- DINO/inode-cluster buffers (many inodes per buffer) are a separate blocker — must never
  fall back to inventing a single-inode token.

## Release-site frontier map (sess161)

`docs/history/docs/history/docs/history/compiled-foreign-replay-recovery-descriptor-authority.md`: status snapshot
of D-FOREIGN-REPLAY-UNGATED-IMAGES at 0.11.457. `mxfs_inode_authority_begin_release_locked`
still has zero callers — a comment claiming "primary revoke happens at release-begin" was
stale/false (measured backstop=2486, release_begin=0); the *backstop* revoke inside
`mxfs_dlmtr_rec` (any mode-lowering with auth != NONE) is doing all the work. Full
release-site inventory in `xfs/xfs_mxfs_dlm.c`: `mxfs_dlm_bast_process` NL stores (lines
15527, 13969) already order mode-lowering before peer-visible publication, so
revoke-before-publication holds there — hook goes immediately before those stores.
**`mxfs_dlm_evict` (31226) is the actual gap**: it releases (31537/31542/31596) with
`i_dlm_mode` still EX/PR — no mode store, so the backstop never fires; violates the
"clear cert at reclaim/eviction begin" invariant. noino paths need no hook (no in-core
cert); ICLUSTER per-inode demotes are already covered via fan-out. One arm (EX→PR
demote-in-place) was still unlocated. Wiring plan: hook `begin_release_locked` at the NL
stores and at evict's release decision point; rework the backstop to distinguish
expected-cleanup (state==RELEASING at lowering) from a real late-revoke violation
(state==DURABLE_EX/UNPUBLISHED_EX at lowering); add assertions at every publication point.
Consumer-half status recap: producer+capture+serialize (the sess102 first-dirty design)
is complete and rig-verified clean 32/32 (sess110) — but the replay gate still
blanket-skips BUF/DQUOT/QUOTAOFF/ICREATE, and its "until records carry authority tokens"
comment is now false since they do. Remaining work: step 4 (recovery descriptor +
IMAGE_REPLAY_DONE + victim-slot freeze, overlapping D-FOREIGN-SLICE-INTENTS-ABANDONED from
sess63) and step 5 (the exact-match {resource,epoch} gate swap, transaction-atomic per
sess102). Note: `docs/history/docs/history/compiled-foreign-replay-authority-tokens.md` (an earlier compiled article)
is stale past sess48 — it predates the sess81-110 v2 token redesign and its "resume at 3b"
pointer is superseded by this chain.

## Net state as of sess161

Descriptor mechanism (wire format, ops, four freeze sites, owner_term/recovery_gen split)
is built and landed through 0.11.410 but never rig-cycled past 0.11.401, and the fence-time
coordinator thread that the sess66 ruling requires was still only designed, not written.
Authority-token producer side is complete and verified; the replay-side consumer (the
actual gate swap from blanket ATOMIC-SKIP to selective APPLY) remains open, gated on
finishing the begin_release_locked wiring (sess161) so that DURABLE-vs-RELEASING state is
trustworthy at capture time.
