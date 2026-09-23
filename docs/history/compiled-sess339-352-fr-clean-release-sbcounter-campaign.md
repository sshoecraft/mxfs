<!-- sess339-352: #91 foreign-shadow-unwind (0.12.5-6), #92 clean-release-as-death + #93 mass-umount serialize (0.13.0), #94 SB-counter clean-skip (0.13.1… -->
# ccloop c7ee71c6 sess339-352: #91 foreign-shadow-unwind, #92 clean-release false-death, #93 mass-umount serialize, #94 SB-counter clean-skip

Four defects worked back-to-back on the c7ee71c6 loop, 0.12.5 → 0.13.1. Each
surfaced while verifying the previous one — #92 was found chasing #91's
verification harness, #94 was found chasing #92's own closure test package.

## #91 D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B

sess339 landed the sess337 GPT ruling: foreign (victim) buffers must not
trigger `xfs_force_shutdown` on the *survivor* mount during replay error
handling. Mechanism: `bool b_mxfs_foreign_recovery` on the buf (not a
`b_flags` bit), an early gate in `xfs_buf_ioend_handle_error` that routes
foreign buffers around the `_XBF_LOGRECOVERY` one-strike shutdown, a new
`xfs_buf_delwri_fail()` that fails a buffer without ever submitting it
(so iowait/complete stay balanced), and provenance threading through six
queue-site families in `xfs_log_recover.c` — the sixth (found by sess339's
own code sweep, not the sess338 audit) was the swapext owner-change path,
`xfs_btree.c` bbcoi, since INODE items (unlike buffer items) DO apply on
foreign replay. Adopted-slice recovery deliberately keeps the upstream
shutdown (that log is the mounting fs's own). Built 0.12.5, sv
E9421B6AA014B2B7C2F2547 — not reviewed, not deployed.
`docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess340 the design-consult rule review returned STOP-SHIP, 5 required items, all landed in
0.12.6 (sv FE2B7E1CF2A875536F20577):
1. Completion-side shutdown: `xfs_buf_item_done` still passed
   `SHUTDOWN_CORRUPT_INCORE` for foreign buffers lacking `_XBF_LOGRECOVERY`
   (the new owner-change family) — would suicide the survivor. Gated on
   `_XBF_LOGRECOVERY || b_mxfs_foreign_recovery`.
2. Blind provenance assignment before `xfs_buf_delwri_queue` was unsafe when
   the queue declined (already queued by the live owner). New
   `xfs_buf_delwri_queue_recovery()` assigns only on acquisition; a
   foreign-vs-live-owner conflict returns `-EBUSY` (refuses replay, TORN
   verdict — matches containment design) instead of misclassifying.
3. `xfs_buf_delwri_fail` fail-safe: an untagged buffer would still hit the
   one-strike shutdown. Added ASSERT + force-tag before the inline ioend.
   Plus `xfs_buf_delwri_cancel`/`xfs_bwrite` tail-clear provenance on
   no-I/O abandonment paths.
Ratified: the sess338 adopted-slice decision, and that the 6-family queue
audit is now complete.
`docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess341 deployed 0.12.6 to all 32 nodes and rig-verified #91: shape-4
(genuine mid-replay TORN injection) and shape-1-under-load both PASS with
zero shutdowns — replayer test1's own mount stayed alive under injection,
the actual property #91 exists to guarantee. Knob-off regression board went
green (24 PASS / 0 FAIL, 3 pre-existing FLAKY), lifting the fence-class board
suspension standing since sess320.
`docs/history/docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

## #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526 (+ #93)

sess342, continuing #91/#90 pre-rig checks, hit an unledgered defect during
a mass 31-node unmount: peers mass-declared still-unmounting LIVE nodes dead
at 62s and attempted to fence them (fence intents happened to no-op via
`P238-FENCE-NOINTENT rc=-116`, which was luck, not containment); the one node
not unmounting (test2) latched permanent phantom-recovery state for all 31
released slots, looping "re-elected after replayer death" with every foreign
replay refused ("no proven exclusion of the dead node"). Initial hypothesis
(heartbeat stops at umount entry) was written down but not yet proven.
`docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess343 disproved that hypothesis — hb threads kept posting fresh timestamps
until DLM shutdown — and root-caused the real mechanism:
`mxfs_disklock_release_slot` stamps `FLAG_EMPTY` on clean unmount but the
monitor loop (`dlm/disklock.c`) has arms for pending / WITHDRAWN / inactive /
ACTIVE-ts but **none for clean EMPTY**, so a released slot falls into the
inactive arm, ages past the 62s dead threshold, and fires death+fence on a
slot that was never abandoned. `hb_still_dead_stamp()` returns true for an
EMPTY-with-victim-stamp record, so the latch can never self-clear. Ledgered
as #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526. Also ledgered
#93 D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B: 31-way simultaneous unmount of
a quiescent fs serializes ~60s/node on root-inode EX handoff (the derived-budget rule
violation), and is the enabler that keeps slow nodes' monitors alive long
enough to false-fire #92.
`docs/history/docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess344 design-consult ruling approved a shared record classifier (ACTIVE /
EMPTY-clean-candidate / WITHDRAWN / GUARD / foreign / garbage) plus explicit
clean-departure arms ahead of the existing inactive-arm check, FUA-confirmed
against an exact stamp match before retiring a slot with no fence/recovery
side effects, and a pending-block EMPTY arm for slots that had already
started fencing. GPT rejected folding EMPTY into `hb_still_dead_stamp`'s
boolean and ruled the missed-EMPTY reuse race is NOT deferrable: a claimant
must carry **on-disk provenance** (32B `mxfs_hb_provenance`: prev_node,
prev_epoch, slot_seq, chain_len, crc32c) proving it consumed a clean EMPTY,
so a monitor that missed the EMPTY stamp can still recognize a clean lineage
via sequence/chain arithmetic instead of conservatively firing death. Ring
shrunk 25→23 entries to make room; layout change bumps `MXFS_PROTO_GEN` 4→5
(version-gates old nodes) → minor rev 0.13.0.
`docs/rulings/clean-release-monitor-fix.md`

sess348 completed and rig-verified the fix (0.13.0, sv
F191408004F380B726E4887, re-mkfs required for the proto-gen bump): a new
`v5_clean_depart_cb` (recovered_cb minus `note_dead`) clears the torn bit and
dead bit and requeues foreign-replay work only if a dead latch was actually
dropped. `clean_depart_mass_umount.sh` (new harness) — 31-way concurrent
unmount, zero false "no longer responding", zero phantom
`P163-RECOVERY-PENDING`, 31× `P163-CLEAN-DEPART` confirmed. Rejoin-after-
clean-departure and real-death regression (virsh destroy) both still correct
— death machinery untouched, clean path is additive. (#93's serialize is
still present — wall stayed ~122s — tracked separately.)
`docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess349 design-consult ruling refused to close #92 on the (a)-(d) runs alone and
specified a 7-race minimal closure package (deterministic pre-FUA gate knob
for races 1/3, a crafted-record `hb_forge` tool for race 4's wrong-stamp
table, a GUARD-CAS loser-path code audit + one mixed run for race 5, and two
lineage-arithmetic runs — single-cycle and multi-cycle reuse — for races
6/7). Established execution order: races 6/7 first on the already-green
0.13.0 fleet, then the mixed run, then the GUARD audit, then build the gate
knob (0.13.1) for races 1/3/4.
`docs/rulings/92-closure-test-package.md`

## #94 D-IDLE-SLICE-WSKIP-REFUSAL-AG-QUARANTINE-0130 (found chasing #92 race 6)

sess350's first race-6 attempt (suspend one node, unmount+remount another)
inadvertently fenced the idle suspended node — the P225 mount barrier is
authority-gated and the fresh remount's settle-verify held it in a 53s block,
pushing the suspend window past the 40s death threshold. That triggered a
**new, unledgered natural failure**: the elected replayer refused the
suspended node's idle slice — 2 committed txns, each a single lazy SB-counter
buffer image, tagged and valid — because `xlog_recover.c`'s "contains
untagged image(s)" message conflates `wskip` (deliberately-skipped, tagged)
with genuinely untagged. The refusal quarantined AG 0 **cluster-wide** off a
completely idle, healthy node's routine SB counter logging. Incidentally
validated the #92 lineage arm working correctly on both peers. Also fixed
the race-6/7 choreography: freshly unmount+remount the tracked node FIRST to
drop cached mount-time authority, so the later suspend doesn't hit the P225
barrier.
`docs/history/docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

sess351 got two design-consult rulings on the fix shape. First ruling: a txn may be
clean-skipped (not applied, not refusal-grade) only if every item is a
recognized primary-SB buffer image with a valid v3 `CLASS_SB` token and the
decoded image differs from the replay-local effective SB *only* in the
whitelist `sb_icount`/`sb_ifree`/`sb_fdblocks` (+`frextents` conditionally);
any other SB field mismatch (growfs, UUID, feature bits, quota) stays a hard
refusal. Also specified a producer-side authenticated `SB_COUNTER_ONLY`
subtype and a rebuild-before-unfreeze obligation.
`docs/rulings/sb-counter-clean-skip-design.md`

Second (follow-up) ruling replaced the rebuild-write plan with a lighter
shape after establishing that MXFS has no live consumer of on-disk SB
counters in multi-node mode: **never rebuild-write**, since a non-quiesced AG
scan isn't point-in-time coherent and a later clean mount would wrongly
trust a plausible-but-wrong value. Instead mounts unconditionally distrust
on-disk SB counters — force `xfs_initialize_perag_data` on every mxfs mount,
clean or not, subsuming the need for any durable marker. Comparison baseline
is the replay-local effective SB (walked in victim LSN order), never a
moving on-disk home SB, because `xfs_log_sb` logs the whole SB buffer so a
dirty-mask alone can't isolate counter fields — the masked content compare
is the only real gate.
`docs/rulings/2-sb-cleanskip-lighter-shape.md`

sess352 landed and GPT-reviewed the implementation, built 0.13.1 (sv
F6C2522B7DBEDE27757C0AB), not yet deployed: `mxfs_sb_counter_only_txn()`
classifies every replay txn (verdict codes 0-8) requiring exact primary-SB
`LI_BUF` framing, `ST_UNPROVEN` class, and a masked memcmp against a
per-replay-session SB baseline snapshotted once under `m_sb_lock`; a clean
verdict increments `l_mxfs_sbclean_skips` and returns 0 instead of refusing.
The terminal (quarantine) predicate is unchanged — still `untagged_skips>0`
only, so counter clean-skips never contribute to a quarantine decision. Mount
distrust wired via `xfs_check_summary_counts() || mp->m_mxfs_dlm` (DLM init
precedes mountfs, verified). GPT review: design sound, Q3/Q4 confirmed, one
open caveat — differing per-node quota state would still false-refuse
(fails closed; untested, rig carries no quota).
`docs/history/docs/history/compiled-sess339-352-fr-clean-release-sbcounter-campaign.md`

## Recurring lessons across the arc

- **A false-death/quarantine chain is rarely single-cause.** #92 (monitor
  had no clean-departure arm) and #93 (mass-unmount serialize keeps slow
  nodes' monitors exposed to false-fire) are independent defects that
  compound; #94 was found purely as a side effect of trying to reproduce
  #92 races 6/7 under load.
- **the design-consult rule (GPT) review caught real stop-ships every single time it was
  used in this arc** — sess340's review found 5 required items in a
  self-tested landing, sess344/349/351 each added correctness the
  implementer had not derived alone (provenance/lineage requirement, the
  7-race closure bar, the reject-rebuild-write ruling).
- **On-disk layout changes bump `MXFS_PROTO_GEN`** and force a minor
  version + re-mkfs (0.12.6→0.13.0 for the provenance ring).
- **"Untagged" in refusal messages is overloaded** — `wskip` (deliberately
  skipped, tagged) got conflated with genuinely untagged, which is what let
  an idle-node's lazy SB counters read as torn evidence (#94). The sess352
  fix reserves "untagged" strictly for missing-token cases and adds a
  dedicated accounting split (hard_refused / missing_token / invalid_token /
  authority_refused / class_refused / clean_skipped_sb_counters) so future
  refusal-grade decisions never derive from a conflated counter again.
