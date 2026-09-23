# SCSI PR key lifecycle across departure and remount

Module coverage: `pal/linux/xfs_super.c` (put_super), `dlm/v5_mount.c`
(`mxfs_v5_dlm_slot_release_commit`, mount-time register),
`dlm/scsipr.c` (`mxfs_scsipr_register`), `pal/linux/kern.c` /
`pal/linux/user.c` (`mxfs_pal_scsi_pr_register`,
`mxfs_pal_scsi_pr_register_replace`, `mxfs_pal_scsi_pr_unregister_bdev`).

## Invariants

1. A PR registration belongs to an I_T nexus.  MXFS mints one key per
   incarnation (`key = node_id`, from a per-mount random UUID), so the key
   identifies the incarnation, not the host.
2. The ONLY proofs of exclusion a replayer accepts are a verified
   PREEMPT AND ABORT of a PRESENT key (fence kind 16) or the operator's
   `single_node_exclusive=1` assertion (kind 17).  KEY ABSENT proves
   nothing (kind 6, `KEY_ABSENT_UNPROVEN`): absence causality is
   unknowable (plain PREEMPT, CLEAR, target reset, PR loss).
3. Therefore an incarnation that departs WITHOUT a durably clean slice
   must leave its key registered as the fence target.  A successor on the
   same nexus cannot fence its predecessor (REGISTER AND IGNORE EXISTING
   KEY replaces the key; it aborts nothing and proves nothing).
4. Once an incarnation IS durably clean, its key MUST be retired and the
   retirement proven (READ KEYS post-condition, D-377): otherwise the
   host keeps write privilege on the LU after unmount.

## Departure (put_super) — 0.40.0

```
detach pr_late_key                 (mxfs_v5_dlm_detach_pr_key)
defer slot release                 (mxfs_v5_dlm_shutdown_defer_release)
xfs_unmountfs                      (unmount record PREFLUSH|FUA, or log shutdown)
flush_rc = blkdev_issue_flush      (whole-stack final flush, CHECKED)
released = slot_release_commit(&late, !log_shutdown && flush_rc == 0)
           -> true iff the CAS/FUA release write returned 0
if released: released = (blkdev_issue_flush == 0)     (release durability)
xfs_shutdown_devices
if released: unregister key + READ KEYS verify        (P301-* on failure)
else:        keep key, P302-PR-KEY-RETAINED-FENCE-TARGET
```

Cleanliness predicate = log not shut down AND final flush OK AND slot
release write completed AND post-release flush OK.  Any failure keeps the
heartbeat slot ACTIVE/WITHDRAWN and the key registered, so a survivor
fences (P&A, kind 16) and replays; a lone deployment uses
`single_node_exclusive=1`.

Before 0.40.0 the unregister was unconditional (D-379 arm B): a dirty
departer's key vanished, the survivors' fence stayed `KEY_ABSENT_UNPROVEN`
forever, the slice could never be replayed and every later mount was
refused at the admission barrier (D-379, D-0355 LUN arm).

## Registration at mount — 0.40.0

`mxfs_pal_scsi_pr_register` issues a PLAIN REGISTER (SA 0x00, reservation
key 0).  SPC-3 5.6.6: a nexus that already holds a registration answers
RESERVATION CONFLICT and nothing changes.  Linux `dm_pr_register`
(drivers/md/dm.c) runs the first pass with `fail_early` over EVERY path in
the table (dm-mpath `iterate_devices` visits failed paths too) and rolls
back the paths it did register with a plain REGISTER old=ours new=0, which
touches only registrations bearing our key.  The exact
`PR_STS_RESERVATION_CONFLICT` status — never a generic errno — maps to
`-EEXIST`.

`mxfs_scsipr_register(ctx, replace_predecessor)`:

| nexus state | replace=0 (default) | replace=1 (`single_node_exclusive=1`) |
|---|---|---|
| no registration | registered | registered |
| different key present | `P305-PR-PREDECESSOR-KEY-PRESENT`, mount refused, LU unchanged | `P305-PR-PREDECESSOR-KEY-REPLACED`, REGISTER AND IGNORE, fence kind 17 later |
| no PR support | proceeds (as before) | proceeds |

A present key on our nexus is one of: a dirty predecessor (P302), a clean
predecessor whose retirement failed (P301), or another consumer of the LU.
The refusal does not claim to know which; all three require either a peer's
P&A or the operator's assertion.  `tests/setup/prep_fs.sh` REGISTER-IGNORE
+ CLEARs the LU before every mkfs, so a new filesystem generation starts
with an empty table.

## Known boundaries (from the sess433 design-consult review)

- A path REMOVED from the dm table (not merely failed) is invisible to
  every PR operation, register included; a stale registration on such a
  path re-appears when the path is re-added.  Shared by all PR ops; not a
  regression.  Test family: stale key on path 1 / path 2 / both, path
  unavailable at mount and restored later.
- Clean slot release followed by a FAILED unregister leaves
  `slot=RELEASED, key=PRESENT`: an unattributed stale registrant with write
  privilege that no peer will fence (P301 only alerts).  Tracked as its own
  ledger entry (sess433).
- PR registrations have no safe TTL; nothing ages a retained key out.
  Operator visibility is the P302/P305 lines and `sg_persist --in
  --read-keys`.

## Tests

- `tests/lone_mount_create.sh <l> test1 32 remount_refused` — lone dirty
  departure, plain remount refused with P305-PRESENT (p302>=1, mrc2!=0).
- `tests/lone_mount_create.sh <l> test1 32 remount_snx` — same with
  `single_node_exclusive=1`: P305-REPLACED, replay, file present.
- `tests/d379b_dirty_depart_peer_fence.sh <l> test1 test2 32` — A departs
  dirty on a two-node cluster, B fences the RETAINED key (kind 16) and
  replays, A remounts plainly (no P305, file present).  D-379 item 4.

## History

- v0.11.74: unregister moved after the final log write (WE-RO bounce).
- sess43: unregister moved after `xfs_shutdown_devices` (flush conflict).
- sess192: slot release deferred until the unmount record is durable.
- sess377 (D-377): symmetric all-nexus unregister + READ KEYS verify.
- sess432: D-379(B)/D-0355 ruling — retention on dirty departure, no
  REGISTER-AND-IGNORE over a predecessor, no kind 18.
- sess433 (0.40.0): this document's design landed.
- sess502 (0.72.0): the sole-survivor exclusive-write gate (fence kind 20).

## 0.40.1 — on-disk grants survive a dirty departure (D-0357)

A POISONED session (force shutdown → `mxfs_v5_dlm_poison`; the same latch
that stamps the slot WITHDRAWN and retains the PR key) now refuses every
on-disk CAW release at the v5 chokepoints (`v5_caw_release_gate`:
`P306-CAW-RELEASE-POISONED`; AG unlock reports STILL_HELD).  Before this,
put_super's `mxfs_dlm_ag_force_release_all` / `mxfs_iclus_purge_all` ran
before `caw_stop` and CASed the grants away, so the survivor's fence
(kind 16, correct) sealed an empty manifest and refused every tokened image
`notheld`.  Recovery ordering is unchanged: P&A → manifest seal → replay →
out-of-closure purge frees the withdrawn incarnation's grants; a refused
replay keeps them frozen (quarantine).  The successor incarnation claims a
different heartbeat slot, so its node bit never aliases the predecessor's.

## Clean release + failed late unregister → WITHDRAWN re-stamp (0.58.0, sess449)

D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-LEAVES-UNFENCEABLE-STALE-REGISTRANT-0356
and phase (v) of the sess377 two-phase departure (D-PR-RETIREMENT-FAILURE-
NOT-FAIL-CLOSED-377).  `mxfs_v5_dlm_slot_release_commit` no longer destroys
the disklock; put_super keeps it (and its dev clone) alive across
`xfs_shutdown_devices` and the late `mxfs_pal_scsi_pr_unregister_bdev`.  When
that unregister returns anything but proven-retired (`P301-DEPARTURE-
INCOMPLETE`), `mxfs_v5_dlm_slot_restamp_unretired` →
`mxfs_disklock_restamp_withdrawn_after_release` CASes our RELEASED record
(identity + epoch kept, flags EMPTY) back to a WITHDRAWN record carrying the
PR key (`hb_ident_fill`) — `P303-RETIRE-PENDING-RESTAMPED rc=0`.  Peers take
the existing sess9 withdraw path on first sight (`P163-WITHDRAW-SEEN` →
PREEMPT AND ABORT → `P236-FENCE-CERTIFIED` → clean-slice replay → purge), so
the key is retired by authorized fencing and the host's next mount is not
locked out by `P305-PR-PREDECESSOR-KEY-PRESENT`.  If the released slot was
already claimed by a joiner the CAS refuses (`P303-RESTAMP-REFUSED`) and
put_super alerts `P303-DEPARTURE-INDETERMINATE` (operator remedy: preempt-
abort from a live peer).  `mxfs_v5_dlm_slot_release_finish` destroys the
disklock last, on both the unmount and the failed-mount path.  Test knob
`mxfs.dbg_pr_unregister_fail=1` (one-shot, the key really stays registered);
harness `tests/pr_unregister_fail_restamp.sh`.  Still owed for D-377: the
local fail-closed policy for the window before a peer fences (item 2),
serialization against re-registration (item 3), the authorized orphan reaper
(item 4).

## RETIRE_PENDING settlement made fail-closed (0.59.1, sess451)

0.59.0 (sess450) replaced the EMPTY release stamp with `RETIRE_PENDING`
(`docs/dlm-protocol.md` "Clean departure: RETIRE_PENDING"); the sess450
design-consult review ruled it STOP-SHIP.  0.59.1 closes the three blockers and the
P305 regression:

1. `mxfs_scsipr_key_state` (tri-state) replaces the bool for settlement:
   ABSENT only from a complete READ KEYS view under our own registration
   and the fencing reservation; everything else UNKNOWN, which never
   settles.  The disklock callback (`mxfs_disklock_key_state_fn`) adds OWN
   for the mount's own derived key (same-boot predecessor).
2. A lost settlement CAS re-reads the sector (`hb_retire_reread`) before
   the caller classifies anything; the dead-confirm arm treats CHANGED as
   "not a stale-dead sector" and never fires death on it.
3. `mxfs_disklock_get_recovery_pending_slots` reports RETIRE_PENDING (mask
   + `out_retire_mask`); `mxfs_v5_dlm_mount_pending_recovery` settles each
   one immediately via `mxfs_disklock_retire_settle_slot(immediate=true)`
   and holds the gate on anything not proven (`P-ADMIT-RETIRE-PENDING-
   HELD`).
4. The P305 scan (`v5_same_boot_scan`, every CAW mount) records this boot's
   RETIRE_PENDING record and `v5_p305_settle_retire_pending` settles it
   after the disklock is created and the key-state callback installed —
   before the claim, before the heartbeat.  Item 3 of the D-377 list
   (serialization against re-registration) is the host-wide departure lock
   in `v5_mount.h`, held by put_super's late phase and by the mount from
   REGISTER to the P305 settlement.

Verification: `tests/retire_pending_admission.sh <N> <victim> <joiner>
[probe] sameboot|joiner` — sameboot: victim departs with the unregister
failure + skipped re-stamp (record RETIRE_PENDING, key present) and remounts
inside the 30 s grace: `P305-PR-SAME-BOOT-RETIRE-PENDING`,
`P305-RETIRE-SETTLED`, no peer expiry/fence of that key, key count
unchanged, the remount writes; joiner: a third node mounts inside the same
window and mount(2) must not return before the victim's key is gone from
READ KEYS (`P304-RETIRE-EXPIRED-WITHDRAWN ... immediate=1` on the joiner,
then a certified fence).

## The settlement's proof made coherent, fresh and off the heartbeat (0.59.2, sess452)

The sess451 design-consult review ruled 0.59.1 STOP-SHIP a second time (`docs/rulings/0591-retire-settlement-stop-ship-2.md`) on
five blockers.  0.59.2 is those fixes:

1. **Coherent absence proof.**  `mxfs_scsipr_key_state` no longer reads a
   1 s cache of one READ KEYS + one READ RESERVATION.  A proof is a BRACKET —
   READ KEYS (A) → READ RESERVATION → READ KEYS (B) — accepted only when all
   three report the same PR generation, our key is in A and B, and the
   WE-AR reservation is in force; absence is judged from B.  A PROUT landing
   inside the bracket moves the generation (`P-PR-BRACKET-INCOHERENT`).
   Every local PROUT (`register`, `register_succeed`, `reserve`, `preempt`,
   `unregister`) and the reservation-conflict callback invalidate the
   snapshot (`mxfs_scsipr_snap_invalidate`); a bracket that started before an
   invalidation is discarded at commit (`P-PR-BRACKET-DISCARDED`).  PRESENT
   may be served up to 2 s; ABSENT only from a bracket ≤ 5 s old and at most
   ONCE per (key, bracket) — the destructive CAS never reuses a proof.
2. **PR work off the heartbeat.**  A per-context probe thread
   (`mxfs_scsipr_probe_start/stop`, `scsipr_probe_fn`) runs the brackets; the
   monitor's lookup (`mxfs_scsipr_key_state`) is a table read that kicks the
   thread and answers UNKNOWN when nothing fresh exists.  The mount thread
   alone uses `mxfs_scsipr_key_state_sync` (a bracket inline); the disklock
   selects it through `key_state_sync_fn` when `immediate` is set.
3. **OWN restricted to P305.**  The generic lookup answers PRESENT for our
   own key; `MXFS_DISKLOCK_KEY_OWN` is gone.  P305 enumerates EVERY
   RETIRE_PENDING record of this boot (`p305_retire_mask` + per-slot
   node/epoch/key; `P305-RETIRE-MULTI` when more than one) and settles a
   record naming our derived key only after
   `mxfs_scsipr_own_registration_proven` (a fresh bracket, `P-PR-OWN-PROOF`)
   through `mxfs_disklock_retire_settle_own` (`P305-RETIRE-SETTLED-OWN`;
   `P305-RETIRE-OWN-CHANGED` / `-CAS-LOST` → rescan).  Any other key goes
   through the ordinary immediate settlement.
4. **Key 0 is never ABSENT; no clustered self-clear.**  `hb_retire_settle`
   classifies a record naming key 0 UNKNOWN (`key0-invalid`).  put_super's
   `mxfs_v5_dlm_slot_retire_complete` runs only for a mount admitted under
   `single_node_exclusive` or `fence_capability_override`
   (`self_retire_ok` in `struct mxfs_v5_dlm_slot_release`); otherwise
   `P304-RETIRE-SELF-REFUSED-CLUSTERED` / `P304-RETIRE-SELF-WITHHELD` and
   the record stays RETIRE_PENDING.  P305 settles a key-0 record of this
   boot only under `single_node_exclusive` (`P305-RETIRE-KEY0-TOPOLOGY`),
   else refuses (`P305-RETIRE-KEY0-UNSETTLEABLE`).
5. **Quiescence asserted, not inferred.**  `m_mxfs_departure_stage`
   (MOUNTED → QUIESCING before `xfs_unmountfs` → FROZEN after the final
   flush), `m_mxfs_buf_io_inflight` (every `xfs_buf_submit_bio` counted per
   buffer, retired in `__xfs_buf_ioend`), `m_mxfs_io_after_freeze` (any
   submission after FROZEN: `P304-RETIRE-IO-AFTER-FREEZE`).  The release
   stamp is written only when `mxfs_departure_quiesced` reports
   `P304-RETIRE-QUIESCED` (buf inflight 0, dir-write inflight 0, nothing
   after the freeze); otherwise `P304-RETIRE-NOT-QUIESCED` and the
   departure is DIRTY.  Same in the failed-mount unwind.  *(0.61.0 replaced
   these three fields by the locked, refcounted accounting object — see
   "landing group 3" below; the stage names and probe lines are unchanged.)*

Debug knobs (`pal/linux/kern.c`): `dbg_pr_read_keys_fail=N`,
`dbg_pr_read_resv_fail=N`, `dbg_pr_read_keys_trunc` (one-shot),
`dbg_pr_read_keys_delay_ms`, `dbg_pr_bracket_fail=N`.

Verification: `tests/retire_pending_admission.sh` arms `unknown`,
`unknownresv`, `trunc`, `slowpr`, `joinerunk`, `race`, `genmove`,
`multipending` (header documents each invariant), driven by
`tests/sess452_chain71_retire_pending.sh`.

## Chain 71 on 0.59.2 — every mechanism held; the captures lied (sess452/453)

Chain 71 (`tests/evidence/sess452_chain71_retire_pending_s452a.log`,
sv 11A31CA5) printed FAIL on all twelve laps.  None of the failures was the
mechanism:

- **The last kernel line of every departure was invisible** (ledger
  D-0518).  `mxfs_pal_log` in the kernel PAL printed `"mxfs: %pV"` with no
  trailing newline; a printk whose text lacks `\n` is committed but not
  *finalized* in the ringbuffer, and dmesg cannot read it until the next
  printk on the system.  `P-DBG-RETIRE-SKIP-RESTAMP` was stamped 5 µs
  after the `xfs_alert` P301 line and surfaced only at the remount two
  seconds later, so eight crash-model arms read "crash knob did not fire
  (vacuous)" and the restamp lap read "no P303".  0.59.3 appends the
  newline at the chokepoint (`docs/log-levels.md`).
- `restore_victim` ran `prep_node.sh` without `MXFS_DEV`, i.e. on
  `/dev/sda`, which the multipath map claims: "victim did not remount" and
  a key-table count one short per arm (32 → 22 over the chain).
- The `trunc` ordering check grepped the sweep file's `MARK=count` header.
- `race` ordering B departed a victim that ordering A's teardown had
  already unmounted (umount rc=32; every B assertion vacuous).
- The restamp lap's "key present right after the departure" read is
  racy by design on 32 nodes: the WITHDRAWN re-stamp is fenced on a peer's
  next monitor lap (≤ 5 s), inside the read window (`FENCE-CERTIFIED`
  after 0 s).  The harness now accepts an absence that a certified fence
  explains; crash mode (30 s grace) keeps the strict check.

What 0.59.2 measured, with those removed: same-boot `SETTLED-OWN=1`,
mount rc=0 in 9 s, no peer expiry/fence; joiner `EXPIRED-immediate=1`,
key absent when `mount(2)` returned, fence certified; `unknown` /
`unknownresv` 29/28 peers `UNKNOWN-STALLED` with zero EMPTY, WITHDRAWN,
fence or heartbeat symptom over 40 s, then expiry + fence on clearing;
`trunc` exactly one EMPTY (12 truncations + 15 RESV failures seen);
`slowpr` completed with `HBFALSE/HB-SLOW/HB-MONSLOW/HB-STALL` all 0;
`joinerunk` mount HELD then ABORTED at 40 s (rc=32), nothing published
under the failed brackets, expiry + fence on clearing; `genmove`
`INCOHERENT=17`, remount still settled; `multipending` one `SETTLED-OWN`
per cycle, no `MULTI`; crash lap 20 peers saw the record, expiry at 35 s,
key gone after the fence.  Chain 72 (`s453a`, 0.59.3 sv 9727DA88) re-runs
the whole chain with the fixed harnesses; its verdict is the record's.

## design-consult review #3 of 0.59.2/0.59.3 — NO-GO (sess453)

Chain 72 on 0.59.3 passed 10 of 12 laps (the two exceptions are D-0519, a
recovery-latency defect outside this mechanism), so the review ran on rig
evidence.  Verdict (`docs/rulings/0593-retire-settlement-stop-ship-3.md`):
blocker 4 (PR work off the heartbeat) MET; 1, 2, 3 PARTIAL; 5 UNMET.
Conditions for GO, to be landed as 0.60.0:

1. No time-cached ABSENT at the EMPTY CAS — a single-use proof token
   validated adjacent to the CAS, revoked on every local PR mutation,
   reservation loss, detach and the late unregister (today detach abandons
   the `scsipr` context *before* put_super's late unregister, so that
   unregister cannot invalidate the snapshot).
2. Close the proof→CAS window, or document and test the fencing invariant
   that makes the residual interval safe.
3. A real departure I/O gate: FROZEN must reject mount-attributable
   submissions, and drain, gate and release publication must share one
   synchronisation (today `mxfs_departure_quiesced()` reads the counters
   once and a submitter can slip in after the read).
4. Prove `m_mxfs_buf_io_inflight` inc/dec on every path (the increment
   precedes the partial-inode early return; the underflow clamp hides
   corruption); fault-injection returning the counter to zero exactly once.
5. All teardown I/O — including `xfs_shutdown_devices`' raw flush — before
   the release point or inside the quiescence protocol.
6. Mechanically prohibit clustered no-PR admission (REGISTER, READ KEYS,
   READ RESERVATION, RESERVE, PREEMPT AND ABORT and a nonzero key);
   `fence_capability_override` must not authorise clustered self-retirement.
7. P305-only OWN: assert the departure mutex, replace the proof string with
   an opaque single-use token, define duplicate same-boot records.
8. Remove the CAW `-EOPNOTSUPP` plain-FUA-write fallback in both settlement
   paths (fail closed).
9. Tests: clustered no-PR rejection; simultaneous duplicate same-boot
   records; invalidation after unregister/preempt/reservation loss;
   P305-vs-peer CAS race in both orderings; counter error paths;
   freeze/check/submit race injection.

Also owed: `mxfs_scsipr_probe_stop` joins unconditionally (a hung PR IN hangs
teardown) and `probe_stop`/`probe_thread` are accessed without
`READ_ONCE`/`WRITE_ONCE` or a lifecycle lock.

## 0.60.0 — landing group 1: admission and settlement fail closed (sess453/454)

The design consult on the nine conditions (`docs/rulings/0600-design-d1-d9.md`, now folded into
`docs/history/docs/history/compiled-sess450-453-retire-pending.md`) ordered the landing in four groups,
each independently fail-closed and rig-verified.  Group 1 is conditions 6
and 8 (rulings D5 and D7) plus their tests:

**Admission (condition 6, D5).**
- `mxfs_scsipr_validate_admission` refuses a mount whose key was never
  REGISTERED and verified by READ KEYS on this nexus
  (`P303-FENCECAP-UNREGISTERED ... key=`).  A nonzero derived key was never
  enough: `mxfs_scsipr_register`'s `-EOPNOTSUPP` arm returns 0 without a
  registration, and the old check only tested the key.
- `fence_capability_override=1` alone no longer admits a clustered
  read-write mount (`P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED`).  A member
  that can neither fence nor be fenced is exactly the node whose death
  leaves an unrecoverable slice.  The override admits only together with
  `single_node_exclusive=1`, the operator's assertion that no second
  initiator exists, and that combination is also the only one in which the
  departure may complete its own retirement without PR evidence
  (`self_retire_ok = single_node_exclusive`, no longer `|| override`).
- The rig side of the same item (D-377 item 3, multipathd's own
  `reservation_key` re-registering after a fence): `tools/mxfs_admit_check.sh`
  refuses a device whose multipath map or configuration carries a
  reservation key, and `tests/setup/prep_node.sh` now runs it before every
  mount and fails the prep on refusal or on "cannot decide".

**Settlement (condition 8, D7 and its companion).**  Every exact-image
record write in `dlm/disklock.c` that used to fall back from a CAW
`-EOPNOTSUPP` to a plain FUA write (with or without a read-verify or
read-back) now fails closed and logs once per slot
(`P304-CAS-NOCAW slot= op=`): the RETIRE_PENDING settlements (EMPTY,
WITHDRAWN, own settle, self-complete, the departing re-stamp), the
RETIRE_PENDING release stamp, the heartbeat, the voluntary WITHDRAWN stamp,
the recovery milestones (`recov_cas_durable`) and the recovery guard
(lay, refresh, zero).  A clustered read-write mount is admitted only on a
device whose lock-slot CAS is operational (P311, D-0359) and the TCP
transport is refused for clustered RW at the durability-domain admission,
so these arms are reachable only on runtime CAW loss — and then the record
must stay byte-identical.  A heartbeat that cannot land lets the lease run
out and the peers fence the node on the ordinary stale window, which is the
outcome the ruling asks for.  `claim_slot_noncaw` keeps its blind write: it
targets an EMPTY sector before admission, and P311 then refuses the mount.

**Tests.**  `tests/fence_capability_admission.sh` arm 2 now expects the
refusal and a new arm 3 expects admission under override + exclusive;
`tests/vergate.sh noncaw_refuse` expects the earlier refusal.  Chain 74
(`tests/sess452_chain71_retire_pending.sh`) re-runs the settlement laps on
the built 0.60.0.

## 0.61.0 — landing group 2: the settle worker, the proof token, bounded threads (sess454)

Design rulings D1, D6 and D8 (conditions 1, 2, 7 and the two owed hazards).

**Where the ABSENT settlement runs (D1).**  The heartbeat monitor no longer
publishes a RETIRE_PENDING record EMPTY from a table answer.  For a record
naming a nonzero key that the async table does not show PRESENT, the
monitor calls the disklock's `settle_absent_fn` with `immediate=false`:
`v5_mount` enqueues {slot, key, image} and the **retire settle worker**
(`v5_retire_worker_fn`, one per mount) takes the host-wide departure mutex
(by trylock, so a stop is always honoured) and runs
`mxfs_scsipr_settle_absent()`: one fresh bracket under `probe_lock`, and,
if the bracket is a fencing-grade proof with the key absent, the exact-
image CAS to EMPTY *inside the same probe_lock section*.  The mount
thread's P305 / admission-barrier settlement (`immediate=true`) runs the
same function inline, inside its register→P305 departure-locked window.
The table's PRESENT keeps the grace → WITHDRAWN rule on the monitor.

**The departure mutex (D1(2)/(3)).**  It now lives in `scsipr`
(`mxfs_scsipr_departure_lock/unlock/trylock/held`), is re-entrant by owner
pid, and is taken by every local PROUT — `mxfs_scsipr_register`,
`_register_succeed`, `_reserve`, `_preempt`, `_unregister` are wrappers
that nest when the caller holds it and otherwise take it after logging
`P-PR-DEPARTURE-UNHELD` (the assertion, made self-correcting).
`mxfs_scsipr_settle_absent` refuses (`P-PR-SETTLE-UNHELD`, UNKNOWN) when
called without it.  Lock order: departure mutex → probe_lock → snap_lock →
disklock `ctx->lock`.  snap_lock is never held over the CAW.

**The single-use proof token (D6).**  `settle_absent` mints one token
{id, key, bracket seq, invalidation seq} inside scsipr and hands the CAS
callback only the id.  `mxfs_disklock_retire_cas_empty()` FUA-re-reads the
sector, requires it byte-identical to the image the proof was obtained for,
then calls `mxfs_scsipr_proof_consume()` immediately before the compare-
and-write: the token must be the live one, unused, and no local PROUT,
reservation conflict or newer bracket may have moved `snap_inval_seq` /
`snap_seq` since the mint (`P-PR-PROOF-REFUSED why=`).  A token is spent by
the attempt, whatever the CAS returned.  Identity and used-state never
leave `struct mxfs_scsipr_ctx`.

**Bounded threads and quarantine (D8).**  `probe_stop`, `probe_kick`,
`probe_exited`, `retire_stop`, `retire_kick` are read and written only
through `mxfs_pal_flag_get/set` (READ_ONCE/WRITE_ONCE).  Both the PR probe
thread and the retire worker are stopped with a 5 s bounded join
(`MXFS_SCSIPR_JOIN_MS`).  A join that times out — the thread is parked in
a SCSI command on a wedged path — QUARANTINES: the module is pinned, the
scsipr context goes on a list and is freed only by a later reaper after
the thread's own exit (`P-PR-PROBE-STUCK` / `P-PR-PROBE-REAPED`); a stuck
retire worker leaks the whole DLM context (disklock, scsipr, dev clone,
queue — `P304-RETIRE-WORKER-STUCK`, `P304-RETIRE-QUARANTINE`).  The
departure is then DIRTY (`mxfs_v5_dlm_detach_pr_key` reports it;
`P304-DEPARTURE-QUARANTINED`; no slot release, key retained as the fence
target), and no clustered mount is admitted on the host while a
quarantined thread has not exited (`P-PR-QUARANTINE-REFUSED`).

*0.63.0 (sess462, D-RETIRE-QUARANTINE-DOUBLE-ADD-SELF-LOOP-MOUNT-PANIC-0522):*
the retire-worker stop runs twice on every unmount (`detach_pr_key`, then
`shutdown`).  On 0.61.0-0.61.7 a stuck worker therefore timed out twice,
pinned the module twice and linked the context onto the quarantine list
twice — `quarantine_next` pointed at the context itself, and the next
mount's `v5_quarantine_reap` freed it and walked straight back into the
freed memory: kernel panic in `mount` on both chain-86 workerhang victims
(`stuck=2` in the harness = two `P304-RETIRE-WORKER-STUCK` lines).  Now
`v5_retire_worker_stop` returns immediately once quarantined
(`P304-RETIRE-QUARANTINE-AGAIN`) and `v5_quarantine_add` refuses a context
already on the list (`P304-RETIRE-QUARANTINE-DUP`); the scsipr probe stop
already had this guard.

**PAL additions.** `mxfs_pal_mutex_trylock`, `mxfs_pal_current_pid`,
`mxfs_pal_module_pin/unpin`, `mxfs_pal_flag_get/set`.

## 0.61.0 — landing group 3: the departure I/O gate (sess454)

Design rulings D2, D3 (as amended: the proposal was rejected, the ruled
order is what landed) and D4 — review-#3 conditions 3, 4 and 5.

**The accounting object (D2/D4).**  `struct mxfs_depart_acct`
(`xfs/xfs_mount.h`, `mp->m_mxfs_acct`, allocated before `mxfs_v5_dlm_init`
for every clustered mount) holds `stage`, `inflight`, `after_freeze`,
`corrupt`, telemetry (`submitted`, `rejected`), a wait queue and a
refcount, all under one spinlock.  `xfs_buf_submit_bio` calls
`mxfs_depart_token_take()`: under the lock, a mount at FROZEN **rejects**
the submission (`after_freeze`, `rejected++`, `P304-RETIRE-IO-AFTER-FREEZE
... REJECTED (-EIO)`), and the buffer is completed with `-EIO` through
`xfs_buf_bio_done` — the same tail a real bio's `end_io` uses, so every
waiter, the sync-credit accounting and `b_io_remaining` see exactly one
completion; otherwise `b_mxfs_io_tokens++`, `inflight++`, and the buffer
takes one reference on the object when its token count leaves zero.  Every
terminal completion (`__xfs_buf_ioend`, which the whole-buffer, partial-
inode, chokepoint-skip and rejected paths all reach) calls
`mxfs_depart_token_retire()`: token and inflight decrement under the lock,
`wake_up_all` on the transition to zero, the buffer's reference dropped when
its last token goes.  A retire without a token (`P304-IOCNT-UNDERFLOW`) and
a buffer freed with tokens outstanding (`xfs_buf_free` →
`mxfs_depart_buf_free`, `P304-IOCNT-ORPHAN`) set `corrupt`, which is never
repaired: every later departure of that mount is DIRTY.  The 255-token
overflow refuses the submission the same way.

**put_super order (D3, the ruled order).**  QUIESCING before
`xfs_unmountfs`; final device flush; `mxfs_departure_freeze_drain()` sets
FROZEN under the lock and then WAITS for the tokens admitted before the
transition.  *Then* `xfs_rtmount_freesb`, `xfs_freesb`, stats, percpu,
`xfs_destroy_mount_workqueues`, `xfs_shutdown_devices` (its raw flush
included) run **before** the release point; anything they submit through
`xfs_buf` is rejected and recorded.  Only then is the host-wide departure
mutex taken, `mxfs_departure_quiesced()` reads
inflight/rejected_pending/after_freeze/corrupt/stage under the lock
(`P304-RETIRE-QUIESCED` / `P304-RETIRE-NOT-QUIESCED`), and the release CAS
(cloned disklock handle), the post-release flush, the late unregister and
the re-stamp follow as before — the buftarg's `bt_bdev` stays valid until
`xfs_mount_free`, which drops the mount's reference on the accounting
object.  The failed-mount unwind takes the same path: freeze + drain at
`out_unmount`, the shared free chain, and the lock + assertion + release at
`out_shutdown_devices`.

### The sess455 implementation review (STOP-SHIP → 0.61.1)

The first landing (built once as 0.61.0, sv 923EB92D, for chain 77) had a
2 s **bounded** drain that went DIRTY and continued the teardown, retired
the token *before* the error/retry decision, let a rejected generation
retire an admitted generation's token, dropped the orphaned buffer's
reference, and tracked the injector through a singleton pointer.  The
review (`docs/rulings/g3-gate-impl-stop-ship-10-items.md`)
ruled all five unsafe on exactly the anomalous paths the gate exists for.
0.61.1 is the rework:

- **The drain is uncapped for real tokens.**  A token outstanding after
  `xfs_unmountfs` returned is itself a D4 violation (every buffer with I/O
  in flight holds `b_hold`; `xfs_buftarg_drain` waited for it), and tearing
  down the mount under it frees what the completion touches (`bp`, `mp`,
  `m_buf_workqueue`) — an accounting object's refcount pins none of those.
  So `mxfs_departure_freeze_drain()` waits in rounds of
  `MXFS_DEPARTURE_DRAIN_ROUND_MS` = 2000 ms (`P304-RETIRE-DRAIN`, one
  `P304-RETIRE-DRAIN-STALL` per round with the counts, `P304-RETIRE-DRAINED`),
  exactly as upstream's buftarg drain is uncapped.  The one exit is a
  CORRUPT account (under/overflow or an orphaned buffer: the count cannot be
  trusted and a freed buffer's completion can never come) — after one round
  `P304-RETIRE-DRAIN-ABANDONED`, departure DIRTY.
- **Take at the generation's start.**  The token is taken at the top of
  `xfs_buf_submit_ex` (not in `xfs_buf_submit_bio`): the dozen short-circuit
  completions between the two — the log-shutdown `xfs_buf_ioend_fail`, the
  stale-AG-write suppression, the chokepoint-skip emulations — now hold a
  token too, so their terminal retire balances.  A post-freeze generation is
  rejected there through `xfs_buf_ioend_fail`, the very path the
  log-shutdown case uses.  A terminal completion with neither a token nor a
  pending rejection is a generation that never entered `xfs_buf_submit_ex`
  (MXFS's direct `xfs_buf_ioend` callers); it retires nothing and is counted
  as `untokened` telemetry in the QUIESCED line.
- **Retire at the terminal point only.**  `mxfs_depart_token_retire()` runs
  at the end of `__xfs_buf_ioend` (every completion that reaches it: reads,
  writes not resubmitted, staled permanent failures, rejected generations)
  and at the transient-error release exit of `xfs_buf_ioend_handle_error`
  (the buffer is released; the AIL retries with a new submission).  The
  `resubmit:` label sets `b_mxfs_io_carry`, so the retry keeps the
  generation's token — no retire, no re-take — and its own terminal
  completion retires it; a retry rejected after the freeze retires the
  carried token at that rejection's completion.
- **Rejected generations are owned.**  Concurrent submissions of one buffer
  exist in this tree (the sync-credit machinery), so a post-freeze or
  overflow rejection increments `b_mxfs_io_rejected` and
  `acct->rejected_pending` instead of touching tokens, and the retire
  discounts a pending rejection *before* retiring a token.  With both
  counted per buffer and per account, `inflight` reaches zero only after
  every admitted generation has completed, whatever the completion order;
  the drain waits for `rejected_pending == 0` too, because a rejected
  completion may route through `m_buf_workqueue`.
- **Orphans keep their reference.**  `xfs_buf_free` with tokens (or a
  pending rejection) marks the account corrupt, logs `P304-IOCNT-ORPHAN`
  and leaves the buffer's reference in place: the object is never freed
  while it records outstanding tokens.  Account-level under/overflow is
  checked on every decrement/increment (`P304-IOCNT-OVERFLOW` at 255
  tokens rejects rather than saturating).
- **The departure mutex is taken after the workqueues are destroyed**, so
  no worker they flush can wait on the mutex every local PR OUT takes; the
  flush/freeze/drain need no serialisation (a same-boot remount cannot
  begin before put_super returns — the superblock and exclusive bdev holder
  are still ours).
- **A post-CAS flush failure is reported as an uncertain release**, not an
  undone one; the disposition (key retained, peers expire and fence the
  record) was already the safe one.

**The late-token test (D4, relabelled honestly).**  `dbg_depart_late_token_ms=N`
(one-shot, `pal/linux/kern.c`) makes the freeze take one extra token,
retired N ms later from `system_wq`; pending injectors sit on a list that
`exit_xfs_fs` cancels or runs (`mxfs_depart_late_token_exit`).  It proves
the drain **waits** (umount wall grows by N; STALL rounds; `DRAINED`; the
retire logged before the quiescence assertion) and that the departure then
completes clean — `tests/settle_token_arms.sh latewait`.  It is an
account-lifetime and wait-path test, not a post-teardown late-I/O test:
nothing is torn down while a token is outstanding, and a real buffer cannot
be made to complete after the freeze on a healthy unmount because
`xfs_unmountfs` waits for it first.  (The 0.61.0 `latecomp` arm asserted
the rejected bounded semantics and applies to build 923EB92D only.)

**D4 audit statement (for review #5).**  Tokens cover every `xfs_buf` bio
(data, log and rt buftargs alike: the submit chokepoint is one function).
Not covered, and not needing to be: log iclog writes and the unmount record
(`xlog_write_iclog`, synchronously drained by `xfs_log_unmount`), data
writeback (`xfs_unmountfs` → `xfs_unmount_flush_inodes`), discards
(`xfs_log_quiesce` waits for the discard workqueue), and raw
`blkdev_issue_flush` calls, which carry no data.  Workqueues destroyed
under no lock: `m_buf_workqueue` (buffer ioend — MXFS hooks there issue no
PR OUT; a shutdown they trigger queues `m_mxfs_withdraw_work`, already
cancelled with `m_mxfs_dlm` NULL), `m_unwritten_workqueue`,
`m_reclaim_workqueue`, `m_blockgc_wq`, `m_inodegc_wq`, `m_sync_workqueue`;
PR OUTs are issued only from the mount thread, put_super's late phase, the
heartbeat thread, the retire worker, the probe thread and the withdraw
work, all joined or cancelled before the freeze.  Lockdep/KCSAN are not
available on the rig kernel.

## design-consult review #5 of 0.61.1 — NO-GO (sess456)

Evidence: chain 78 on 0.61.1 (six settlement arms PASS, the twelve
RETIRE_PENDING laps 12/12 inside budget, the 32-node board at 26 PASS with
only the known crash_consistency pace row and the policy row), chain 77 on
0.61.0, the sections above.  Ruling (`docs/rulings/review5-0611-no-go-untokened-failclosed-6-conditions.md`):
review-#3 conditions 4 and 6 MET (fresh bracket, no table→EMPTY; the proof
token's image/invalidation/single-use properties, exercised by inval,
double and slowrace); 1, 2, 3, 5, 7, 9 PARTIAL; 8 UNMET.

**STOP-SHIP.**  `untokened` — a terminal completion with neither a token nor
a pending rejection — is provenance the gate could not establish, and it is
telemetry today: `mxfs_departure_quiesced()` does not reject on it.  Unknown
provenance must be corruption, not a counter: either every unclassified
untokened completion on a clustered mount marks the account corrupt, or the
intentionally tokenless software completions are audited and classified
explicitly and everything else corrupts.  Closing evidence: inject one
unclassified completion and observe the corruption report, NOT-QUIESCED, no
EMPTY, no unregister of the fence target, a dirty key-retained departure.

**Conditions for the next review.**
1. Deterministic G3 arms: a real post-freeze submission whose rejected
   completion is delayed on the workqueue (no release while pending,
   discount before any carried retire); a transient write error with a
   resubmit across the freeze (one token across both attempts, retired
   exactly once); an orphan with a token and one with a pending rejection
   (corrupt, reference retained, no release); the 255-token boundary and a
   forced invalid decrement; a submission during freesb / workqueue
   destruction / device shutdown that the FINAL assertion, not the drain,
   blocks.
2. A retire-worker hang: the 5 s bound, whole-context quarantine, no
   release stamp, key retained, host admission refused, eventual reap.
3. The release/unregister crash-cut state table: for each cut (before the
   release CAS; CAS done, flush not; flush done, unregister not; unregister
   failed; unregister done, re-stamp not; final EMPTY; PR capability lost)
   the decoded sector image, key, state, generation, READ KEYS, peer
   action, flush result and whether a later mount is admitted.  The
   decisive fact: the release CAS image must still name the key
   (RETIRE_PENDING carries it) until unregister is freshly proven.
4. Direct 0.61.x evidence for the G1 admission matrix and for runtime
   CAW-loss fail-closed behaviour per writer class (byte-identical sector
   before and after, no plain write, dirty and key retained).
5. Preferably a deterministic same-host PR OUT versus settlement
   interleaving in both orderings.

The uncapped drain was accepted as safety over availability: no capped
"assume drained" path may return; later operational additions (oldest-token
age in the stall line, a health state, an administrative fence/reset) are
not blockers.

## 0.61.5 — untokened completions fail closed (sess459)

The STOP-SHIP above, as landed.  Audit first (pal/linux/xfs_buf.c): every
direct `xfs_buf_ioend` caller inside `xfs_buf_submit_ex` /
`xfs_buf_submit_bio` / `mxfs_buf_read_fua` / `mxfs_submit_partial_inode_write`
runs AFTER the token take at the top of `xfs_buf_submit_ex`, so its terminal
completion retires a token (or a rejected generation) and is never
"untokened".  The only completions that reach `mxfs_depart_token_retire`
with neither are the pre-submission failure emulations — `xfs_buf_ioend_fail`
on a buffer that never issued I/O — and there are exactly three callers:
`xfs_buf_item_unpin` (remove after a log I/O error), and the two
`xfs_iflush_cluster` error exits in `xfs/xfs_inode.c`.  All three run only
after `xfs_force_shutdown`, so the departure they belong to is DIRTY on the
shutdown alone.  481 of 481 clean `put_super` departures in the evidence tree
printed `untokened=0`.

The rule now:

- `xfs_buf_ioend_fail_unsubmitted()` is the audited "no-I/O software
  completion" class: it marks `b_mxfs_io_soft` and completes; the retire
  counts it as `soft`, never as `untokened`.  Those three sites use it.  A
  fourth caller of the bare `xfs_buf_ioend_fail` outside the submit path is,
  by construction, unclassified.
- A terminal completion with no token, no pending rejection and no soft mark
  is `untokened`: reported once per event as `P304-IOCNT-UNTOKENED daddr= len=
  flags= ops= comm= stage=` (a stack for the first four), counted on the
  account, and **`mxfs_departure_quiesced()` refuses while `untokened != 0`**
  — `P304-RETIRE-NOT-QUIESCED ... untokened=N soft=M`, no release stamp, PR
  key retained as the fence target, peers fence and recover.  It does NOT
  mark the account CORRUPT: `corrupt` is the under/overflow/orphan class that
  makes the drain give up after one round, and an unclassified completion is
  evidence of unknown provenance, not of a count that can never reach zero —
  the drain keeps its uncapped wait for real tokens and the assertion fails
  the departure afterwards.  (The ruling offered either shape; this is the
  audited-class variant with the mandatory rejection.)
- Injector `dbg_depart_inject=1` (one-shot, pal/linux/kern.c; values 2-6 drive the post-teardown-submission, orphan-token, orphan-rejected, overflow and underflow arms): right
  after the freeze/drain in `put_super`, `mxfs_depart_dbg_untokened_inject()`
  completes an uncached buffer that never entered `xfs_buf_submit_ex`
  (`P-DBG-DEPART-UNTOKENED-INJECT`).  Arm `untokened` in
  tests/settle_token_arms.sh: injected once, reported, NOT-QUIESCED
  `untokened=1`, no QUIESCED, no release stamp, key retained, drain NOT
  abandoned, umount < 8 s, no kernel fault, peers fence + recover.
  Verification chain: tests/sess459_chain83_untokened_gate.sh.

### The condition-1 deterministic arms (0.61.5, sess459)

Same one-shot knob, values 2-7, consumed by put_super at the phase each arm
needs (`mxfs_depart_dbg_inject`, pal/linux/xfs_buf.c; every arm on an
uncached buffer of the departing mount):

| arm (`settle_token_arms.sh`) | inject | phase | expected |
|---|---|---|---|
| postteardown | 2 | after `xfs_shutdown_devices` | `P304-RETIRE-IO-AFTER-FREEZE`, NOT-QUIESCED `io_after_freeze=1`, no ABANDONED (the FINAL assertion, not the drain, blocks) |
| orphantoken | 3 | pre-freeze | `P304-IOCNT-ORPHAN tokens=1`, drain ABANDONED after one 2 s round, NOT-QUIESCED `corrupt=1`, account pinned |
| orphanrejected | 4 | post-freeze | `P304-IOCNT-ORPHAN rejected_pending=1`, NOT-QUIESCED `corrupt=1 io_after_freeze=1` |
| overflow | 5 | pre-freeze | 255 of 256 takes admitted, `P304-IOCNT-OVERFLOW`, NOT-QUIESCED `corrupt=1`, no orphan after the retires |
| underflow | 6 | pre-freeze | forced `inflight=0` then a retire: NOT-QUIESCED `corrupt=1`, no orphan |
| carryfreeze | 7 | pre-freeze, resubmit +3 s | `P304-TOKEN-CARRY ... REJECTED after the freeze` with `tokens=1 inflight=1`, DRAIN→DRAINED, NOT-QUIESCED `io_after_freeze=1 corrupt=0`, no orphan/untokened |
| carrylive | `buf_inject_write_eio_live=1` | live workload before a clean unmount | `P227-FR-INJECT-WRITE-EIO foreign=0` once, `P304-TOKEN-CARRY ... kept`, QUIESCED `carried>=1`, release stamp, key retired, peer settles EMPTY once |

All DIRTY arms: no QUIESCED, no release stamp, `P302` key retained, no
kernel fault, prompt umount, peers fence + recover.  `P304-TOKEN-CARRY`
(ratelimited) names every carried resubmit; `carried=` on the QUIESCED /
NOT-QUIESCED lines counts them.  Chain: tests/sess459_chain84_g3_arms.sh.
The arm 7 resubmit runs from delayed work; the uncapped drain of a
non-corrupt account guarantees put_super waits for it.

## 0.61.6 — the condition 2/3/4 injectors and arms (sess460)

Review-#5 conditions 2 (retire-worker hang), 3 (release/unregister
crash-cut state table) and 4 (G1 admission matrix + runtime CAW loss per
writer class on 0.61.x) each need a deterministic instrument the tree did not
have.  0.61.6 adds three, all default-off module parameters in
`pal/linux/kern.c`, read by production paths that see 0:

- **`dbg_depart_crash_cut=N`** (one-shot) + **`dbg_depart_crash_hold_ms`**
  (default 60000): `xfs_fs_put_super` parks at cut N
  (`mxfs_depart_dbg_crash_cut`, `P-DBG-DEPART-CUT cut= phase=`) — 1 before
  the release CAS, 2 after the CAS before its flush, 3 after the flush before
  the late unregister, 5 after a successful unregister before
  `release_finish`.  The harness `tests/depart_crash_cuts.sh <N> <victim>
  <probe> <cut>` virsh-destroys the VM while it is parked (the relmark crash
  model) after capturing the victim's kernel log, and records the decoded
  slot sector (flags/state, node, epoch, `ident.pr_key`, sha256 of the 512 B)
  and `chk_mxfs --pr-keys` before the umount, at the cut and after the peers
  acted, plus the peer action lines and whether the victim's fresh-boot
  remount is admitted.  Cut 4 ("unregister failed") stays
  `tests/pr_unregister_fail_restamp.sh restamp|crash`; cut 6 (final EMPTY)
  is the terminal state of cut 5; cut 7 (PR/CAW capability lost) is the
  `release` arm below.  The decisive assertion for cuts 2/3/5: the
  RETIRE_PENDING image at the cut still names the key
  (`ident.pr_key == victim key`).
- **`dbg_retire_hang_ms=M`** (one-shot): `v5_retire_worker_fn` ignores its
  stop for M ms at its loop top (`P-DBG-RETIRE-HANG`), the twin of
  `dbg_probe_hang_ms`.  Arm `workerhang` in `tests/settle_token_arms.sh`
  asserts the 5 s bounded join → `P304-RETIRE-WORKER-STUCK` →
  `P304-DEPARTURE-QUARANTINED` (no release stamp, P302 key retained), the
  immediate remount refused (`P-PR-QUARANTINE-REFUSED`), the reap at the next
  mount (`P304-RETIRE-WORKER-REAPED`), peers fence + recover.  Arm
  `workerhangheld` parks the worker INSIDE a settle instead (every peer
  `dbg_settle_pause_ms=30000`, `SETTLE_VICTIM2` supplies the record): the
  same quarantine, plus a MEASUREMENT of how long put_super's late phase
  waits on the departure mutex its own parked worker holds — the late phase
  takes that mutex after the bounded stop, and a worker truly wedged inside
  a PR IN would hold it for good.  What the measurement shows decides
  whether the late-phase lock needs a bound with a DIRTY disposition.
- **`dbg_cas_nocaw_ops=MASK`** (sticky bitmask): every exact-image record CAS
  in `dlm/disklock.c` now goes through `hb_caw(ctx, op, what, off, expect,
  want)`, and the named classes report `-EOPNOTSUPP` without issuing the
  COMPARE AND WRITE: 1 heartbeat, 2 release, 4 withdraw, 8 withdrawn
  (expiry), 16 restamp, 32 complete-self, 64 empty, 128 settle-own, 256
  recovery-milestone, 512 guard, 1024 guard-refresh, 2048 guard-zero.
  `tests/cas_nocaw_arms.sh <N> <victim> <probe> <arm>` drives heartbeat,
  release, restamp, empty (all peers), settleown, guard and milestone (all
  peers, victim destroyed): each asserts `P304-CAS-NOCAW op=` once per
  (node, slot), a byte-identical sector across the refusal window (sha256 of
  O_DIRECT reads from the probe — no plain write emulated the CAS), the
  class's fail-closed disposition (DIRTY departure + key retained; record
  left RETIRE_PENDING; mount refused; recovery not started), and that
  clearing the mask lets the ordinary CAS settle it.

Condition 4's admission matrix re-runs on 0.61.6 as-is:
`tests/vergate.sh noncaw_refuse`, `tests/fence_capability_admission.sh` (3
arms) and `tests/domain_admission_matrix.sh` (R8 = TCP refusal), all on the
spare node.  Chain: `tests/sess460_chain86_review6_conditions.sh` (gated on
chain 84 DONE; builds 0.61.6 production, then the arms above, then a prep).

## Departure with an attempt this node cannot certify

A node that owns a standing fencing attempt (durable intent, no certificate)
does not publish a consumable record while the attempt stands.  Two things
enforce that, and neither is a retry budget: `put_super` joins the node's own
workers (a prover parked inside the intent is joined, not abandoned), and the
release CAS runs only for a departure judged clean.  When the attempt CAN be
certified once the worker resumes — on the TCP transport a victim whose key
the target purged is fenced through the sole-survivor exclusive-write gate —
the departing node certifies, replays the victim's slice, publishes, restores
WE-AR and then releases RETIRE_PENDING (measured s53b, 0.87.14).  When it
cannot, its final superblock summary sync and root-inode acquire wait on the
grants the dead victim still holds until the recovery-blocked cutoff answers
EIO, the departure is judged DIRTY (no unmount record), and the ACTIVE record
and the PR key stay as the fence target with the attempt standing under this
node's tuple.  The returning victim is then the rescuer: it proves the
departer dead by heartbeat expiry, fences its present key by preempt-and-
abort, notes the incarnation dead, takes the attempt naming its own previous
incarnation over at the next term, certifies boot succession for it, replays
both slices and mounts (measured s53d, 0.87.14: lone mount 93 s, both
incarnations' synced witnesses readable, nothing left on the platter).  The
cost of that fail-safe is a fence of a node that left normally; the
alternative — handing the descriptor back UNOWNED before the release — is not
a safe substitution without a durable ownership transfer that preserves the
incarnation, stage and certificate and revokes the old prover first, and it
would not remove the admission dependency, so it is not done.  Test:
`tests/d0356_stranded_prover_return.sh`.

## 0.72.0 — the sole-survivor exclusive-write gate (sess502)

Fix for D-SESSION-PURGED-VICTIM-KEY-FENCE-NEVER-CERTIFIES-SURVIVOR-FROZEN-0904. Decided from the two SCSI-layer measurements recorded in
`docs/history/compiled-qnap-tcp-caw-d0904.md`; no design consult was taken.

### Shape
- `dlm/scsipr.h`: `MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE = 20` (on-disk certificate value; proves exclusion). `mxfs_fence_kind_resv_type_ok(kind, type)`: kind 16 needs a WE form that excludes non-registrants, kind 20 needs exactly `MXFS_PAL_PR_TYPE_WR_EX` (0x01, new define in pal/pal.h), others need nothing. `ctx->gate_held` on the scsipr ctx.
- `dlm/scsipr.c`: `mxfs_scsipr_gate_sole_survivor()` (observe: complete READ KEYS, own key on exactly ONE nexus else P-PR-GATE-MULTINEXUS ERROR/-ENOTUNIQ, victim key still absent else kind NONE, WE-AR held else NO_RESERVATION/WRONGTYPE; idempotent P-PR-GATE-ALREADY if WE(1) already ours with no other registrant; then arm_submit, PROUT P&A rk=own sark=0 type=1 via mxfs_pal_scsi_pr_preempt(dev, own, 0, true, WR_EX), verify keys=own only + READ RESERVATION type 1 key=own -> P-PR-GATE "EXCLUSION PROVED"). `mxfs_scsipr_gate_holds()` = replay-time recheck (type 1 held by own key + own key registered). `mxfs_scsipr_gate_restore()` = PREEMPT rk=own sark=own type=7 (plain form), verify WE-AR -> P-PR-GATE-RESTORED. Bracket resv_ok and check_reservation_health treat WE(1)-held-by-us as the fencing reservation while gate_held; since 0.85.1 so does `mxfs_scsipr_exclusion_holds()` — a non-gate certificate (PREEMPT_ABORT_DONE, BOOT_SUCCESSION_ABSENT) issued under WE-AR still holds under a WE(1) our key holds, which excludes strictly more (measured s614a: the successor re-proved the gate for a taken-over case and its own predecessor's kind-21 recheck then read the gate as NORESV 65 times until the barrier expired). WE(1) held by any OTHER key stays a lapse.
- PALs (`pal/linux/kern.c`, `pal/linux/user.c`): type 0x01 accepted ONLY as abort form with sark=0.
- `dlm/disklock.c`: both certificate resv-type checks now go through mxfs_fence_kind_resv_type_ok.
- `dlm/v5_mount.c`: after v5_self_succession_consume, if kind still KEY_ABSENT_UNPROVEN and `nlive == 1 && mxfs_disklock_lowest_live_slot(disklock, local_slot) < 0 && vkey && vkey != ctx->pr_key` -> P238-FENCE-GATE-TRY -> gate; kind NONE keeps the original verdict. Else P238-FENCE-GATE-NOTSOLE. mark_fenced includes kind 20. v5_exclusion_recheck branches on cert_kind 20 to gate_holds. v5_recovery_complete_ladder after P163-RECOVERY-COMPLETE calls v5_gate_restore("recovery-complete"); failure sets ctx->gate_restore_due and the PR worker (v5_fence_retry_worker_fn) re-drives it each 250 ms tick.

### Hazards ledgered (not closed by this)
- Multipath: refused (own key on >1 nexus). The mpatha rig never takes this path; on it the SCST target keeps keys anyway.
- While the gate is held joiners are refused at admission (P303-FENCECAP-WRONGTYPE) — fail closed until the restore lands.
- A survivor that unmounts before the restore: unregister releases the type-1 reservation (single holder) -> LUN unreserved; the next mount RESERVEs WE-AR as usual. The unreplayed slice then goes through mount-time recovery. Since 0.85.1 a taken-over kind-20 descriptor whose gate lapsed is re-proved by the successor when it is the only live member (`v5_gate_reprove`); before that the recheck lapsed for ever and the mount barrier timed out.
- A survivor that DIES holding the gate leaves WE(1) on the LUN until the target purges its nexus (the QNAP does, ~30-40 s; SCST never): a joiner arriving inside that window can REGISTER but not WRITE. Since 0.85.1 the TCP mount attributes the holder through the PR ledger, watches the heartbeat table for a full dead window, and preempts a provably dead holder with the all-registrants type before publishing (`v5_tcp_dead_gate_holder`, `mxfs_scsipr_preempt_dead_gate_holder`); a live holder still refuses the joiner at publish.
- The infinite PRECOMMAND retry (ledger item 4, RECOVERY_BLOCKED visible state) is still open; the gate removes the trigger on this target class only.

### Verify
tests/tcp_2node_death_chain.sh (oracle tests/tcp_death_replay.sh now asserts, when P-PR-GATE-ISSUE/ALREADY appears: kind=EXCLUSIVE_WRITE_GATE, zero gate failure probes, P163 published, P-PR-GATE-RESTORE, then sg_persist from W: 1 key + WE-AR). Lab build required: `make modules KCFLAGS=-DMXFS_TCP_TRANSPORT_READY=1` (full rebuild, minutes).

## What may lift the gate

There is one gate per LUN and more than one recovery can depend on it. A node
that returns alone recovers its own previous incarnation and fences the peer
that had been recovering it, and both certificates name the gate as their
exclusion. The gate is therefore never "the recovery's"; it is lifted only when
NOTHING owes it, and what owes it is answered from three sources, all read under
`ctx->gate_lock` in `v5_gate_restore`:

- **In flight** (`gate_pin_slots`): a victim slot is pinned *before*
  `mxfs_scsipr_gate_sole_survivor` is called for it, and unpinned only once the
  fence-prove call has returned and the platter holds a gate-kind certificate
  for that slot (`P-PR-GATE-UNPIN why=certificate-durable`) or no gate is held at
  all. The gate in force with no certificate on the platter keeps the pin
  (`P-PR-GATE-PIN-KEPT`); the fence retry or the operator resolves that, never a
  timer.
- **Running** (`gate_dep_slots`): a recovery registers when its exclusion
  re-check proves the gate is what it runs under, and releases when it publishes
  or when a terminal refusal is durable.
- **Owed** (the platter, `mxfs_disklock_gate_owed_sweep`): every heartbeat
  sector whose validated descriptor carries `fence_kind ==
  EXCLUSIVE_WRITE_GATE`, is below `GRANTS_RELEASED` and is not `QUARANTINED`.
  Unowned, claimed, taken over, certified by another incarnation, aged: none of
  those exempt a descriptor. A sector that cannot be read or validated refuses
  the restore exactly as an owed slot does, and a gate-kind descriptor below
  `SNAPSHOTTING` (the stage at which a certificate is written) is reported
  malformed and counted as owed.

- **Terminally refused** (the platter, the same sweep): a QUARANTINED
  gate-kind descriptor owes nothing — its refused images are never applied,
  its domain is quarantined cluster-wide and its slot stays frozen until
  operator action — so it does not hold the restore. But the gate was
  installed for that victim because its key was already absent from the
  target, and absence proves nothing about a revived incarnation that
  re-registers: WE(1) keeps such a registrant from writing, WE-AR would
  admit it at once. The sweep therefore reports every such descriptor with
  its certificate's victim key, and the restore re-checks each key with a
  fresh synchronous bracket and converts only on a proven ABSENT
  (`P-PR-GATE-RESTORE-VICTIM-PRESENT` otherwise; the PR worker re-drives).

What drives the restore is a recorded block: the recovery-complete
publication, and — since 0.87.12 — the terminal-refusal publication
(`v5_gate_terminal_release`, `P-PR-GATE-TERMINAL-RELEASE`), which marks the
restore due before attempting it inline so progress never depends on the
inline call. Before that a terminal verdict released the dependant and
nothing then called the restore; the gate stayed in force for the survivor's
lifetime and the returned victim was refused at its PR-ledger publish on
every mount. A joiner admitted under the restored WE-AR meets the terminal
verdict synchronously: the mount barrier imports it before the mount
completes and the registration-time outcome scan validates it again before
any filesystem operation is exposed, so the victim's domain is refused on the
joiner exactly as on the survivor.

The platter is the authority; the two in-memory sets close the windows it
cannot see (a command issued whose certificate has not landed; a recovery
between validation and publication). The refusal is logged once per distinct
set (`P-PR-GATE-RESTORE-HELD` for pins and dependants, `P-PR-GATE-RESTORE-OWED`
for the platter) and re-driven by the PR worker every 2 s, because each attempt
reads all 64 sectors.

Lock order: the scsipr departure mutex, then `gate_lock`. The restore takes
both (the conversion is a local PROUT and would take the departure mutex
anyway); pin and dependant updates take `gate_lock` alone and never wait for
the departure mutex while holding it. Holding `gate_lock` across the sweep and
the conversion is what closes admission: a reliance registered after the
restore has decided cannot exist, because registering it waits on the same
lock.

Retention is the safe direction and it says so in the log: joiners are refused
at admission while the gate is held (availability), whereas lifting it under a
recovery is the exclusion itself. There is deliberately no rule of the form
"this obligation has stood long enough".
