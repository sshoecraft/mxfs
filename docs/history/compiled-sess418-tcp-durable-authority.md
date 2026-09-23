<!-- sess418: D-0286 departure-state-machine landing+STOP-SHIP review, TCP rig trap, D-0287/D-0288 filed, GPT durable TCP authority ledger design. -->
## sess418: TCP transport durable-authority campaign (D-0286/D-0287/D-0288)

Single session (2026-08-28, wrapper c7ee71c6, VERSION 0.29.0) that landed the departure state
machine for D-0286, got it STOP-SHIP reviewed, then proved on real TCP hardware that the
transport has no durable-authority mechanism at all — two new critical defects, one GPT design
for the fix.

### Start state
Prior two sessions had died on "out of usage credits" (08-24 08:38Z) mid-board.
`tests/sess416_board_0286.sh` was relaunched on 0.28.7 (sv 05B52D987, setsid+nohup, log
`tests/evidence/sess416_board_0286.log`); all rows PASS except `open_defects` (policy red — see
the zero-defect bar). `docs/history/docs/history/docs/history/compiled-sess418-tcp-durable-authority.md`

### D-0286 departure state machine — landed in 0.29.0, unbuilt until the 0.28.7 board finished
(never rebuild `mxfs.ko` while a rig run is in flight — separate trap). Contents:
- `pal/pal.h`: `mxfs_atomic32_cmpxchg` / `mxfs_atomic32_xchg` (kernel + userspace).
- `dlm/v5_mount.c`: `enum MXFS_V5_DEPART_{ACTIVE,CLEAN_LEAVE,POISONED}`; `ctx.depart_state`;
  `withdraw_once` (atomic TAS); new `member_lock` (created first in init, destroyed at all 3 free
  sites); `mxfs_v5_dlm_poison(ctx, why)` = cmpxchg ACTIVE→POISONED + `WRITE_ONCE(withdrawn)`,
  never overwrites CLEAN_LEAVE (logs `P-POISON-AFTER-CLEAN-LEAVE`); called **synchronously** from
  the XFS shutdown hook (`mxfs_dlm_shutdown_withdraw`, via `xfs_do_force_shutdown`) before
  `schedule_work`; teardown does cmpxchg ACTIVE→CLEAN_LEAVE right after `depart_clean` is computed
  (`P-DEPART-POISON-WINS` on failure); `NODE_LEAVE` RX under `member_lock` ignores a dead/
  recovery-pending sender (`P-GOODBYE-DEAD-IGNORED`); `v5_tcp_declare_dead` no longer purges a
  slot-owning victim immediately — recovery completion purges instead (`P-TCPDEATH-DEFERRED`);
  `v5_tcp_release_gate` returns `-ESHUTDOWN` (`P-TCP-RELEASE-POISONED`) on
  inode_unlock_open/iclus_unlock_gen/release_unconditional/ag_unlock TCP arms; the msg callback
  drops everything but `NODE_LEAVE` once `!ctx->mounted` (`P-TEARDOWN-MSG-DROP`).
- Lock order fixed: monitor releases disklock `ctx->lock` before `expire_cb`; `recovery_is_pending`
  is lockless; `member_lock` → `mphase_lock` / disklock lock, never reversed.
- `docs/dlm-protocol.md` gained a "Departure state machine" section.

Key code fact learned while landing this: on TCP, `mxfs_dlm_release_all` frees only the **local**
lock table — nothing goes on the wire. The goodbye message is the *only* wire-visible release.
TCP membership change is a **global lock-table purge on every node** + epoch advance + a no-op
`v5_membership_cb_tcp`; the only guards are a 20s EX settle gate and a phantom-EX probe at the next
ilock. That gap → **D-TCP-MEMBERSHIP-CHANGE-PURGES-HELD-GRANTS-NO-RECONSTRUCTION-0287** (critical,
filed as a closure dependency of D-0286; needs its own the instrument-first loop measurement: a holder mid-tenure
>20s across a membership change, peer acquires after the settle window).
`docs/history/docs/history/docs/history/compiled-sess418-tcp-durable-authority.md`

### GPT STOP-SHIP review of the 0.29.0 D-0286 landing
9 mandatory closure conditions, none optional:
1. Clean-leave/poison need real serialized linearization, not a bare CAS — poison can land after
   the CAS but before/during the goodbye send. Either commit+enqueue the goodbye under a lock
   (poison cancels an uncommitted goodbye; a committed one is irrevocable), or prove no poison
   source can execute after the commit. Poison must never overwrite CLEAN_LEAVE.
2. RX TOCTOU: the dead/pending check vs. the death-thread marking must be serialized under one
   per-node state machine (LIVE→CLEAN_PURGING vs LIVE→DEAD_PENDING, exactly one wins).
3. Messages must be incarnation-qualified (delayed old NODE_LEAVE vs. same node-id new
   incarnation) — tree fact found in review: sess11 P164's dead-set retires a node id forever at
   the receiver, including clean departers, which answers this by construction; record the
   evidence rather than re-deriving it.
4. Global poison must gate *all* wire-visible relinquishment (e.g. a non-wedged inode's RELEASE
   after poison), race-safe against in-flight ops.
5. TCP death must directly enter the certified disk-recovery machine (durable intent → fence →
   cert → pending → elect → replay → purge), never "bare fence then hope the monitor notices";
   slot match must be incarnation-qualified, not just `find_node_slot>=0`.
6. A timeout may never fall back to uncertified purge — retry/re-elect/withdraw/freeze/operator
   only.
7. `withdraw_done` was racy (two callers both observe false) → needs atomic test-and-set;
   `depart_state` reads need proper ordering, not plain bools.
8. **Master-failover reconstruction — independently STOP-SHIP.** Mastership = `hash %
   active_nodes`. When the master of resource R dies, its in-memory table dies with it; once
   recovery completes and the dead master leaves `active_nodes`, R remaps to a survivor C that has
   no record of another survivor B's grant → "no record ⇒ free" ⇒ a conflicting grant is issued.
   Needs a rebuild protocol: survivors report held locks to new masters under a generation-fenced
   barrier before admission. This is what later becomes the durable authority ledger design.
9. Deterministic tests required: sender-race injection (5 points around CAS/enqueue/send/
   slot-release), RX race, delayed-old-incarnation messages, release-after-poison of a second
   resource, in-flight-request teardown, TCP-dead/disk-alive matrix, master-loss reconstruction,
   concurrent shutdown callers, replayer crash matrix.

Two session-side arguments GPT accepted: syncing poison from shutdown context is the correct
direction (check `mxfs_pal_log` can't sleep, check ctx lifetime); and after a bare PREEMPT the
victim's own HB writes start conflicting → HB stops → stale ACTIVE sector → any survivor's monitor
rediscovers the obligation (durable via the victim's own sector, per sess66) — this is the argument
for why "purge on timeout" must stay banned everywhere.
`docs/rulings/0286-implementation-stop-ship.md`

### Rig trap hit while trying to exercise TCP on the current fleet
`./run.sh 32 tcp prep_cluster` fails: `run.sh`'s `tcp` condition (condition 1) targets the old LIO
tcm_loop rig with the shared LUN wired as `/dev/sda`; the current fleet is the dm-multipath rig
(`caw` = condition 4, `/dev/mapper/mpatha`, dual SCST portal), so `/dev/sda` is claimed by `dm-1`
and prep fails with `FS_PREP_FAIL`. The 32/tcp board's existing 20 PASS cells are stale, from the
old rig. Fix: `MXFS_DEV=/dev/mapper/mpatha MXFS_CRIT=/src/mxfs/criteria.tcpmp.json ./run.sh 32 tcp
prep_cluster` — `MXFS_DEV` overrides the per-condition device, `MXFS_CRIT` keeps results off the
primary board (cells are keyed `<N>/<dlm>` with no rig dimension, so running a condition on a
different rig silently overwrites the column in place — `run.sh:103-107` documents this). The
transport gate the D-0286/0287 test scripts read
(`/sys/module/mxfs/parameters/force_transport==1`) is transport-scoped, not rig-scoped, so it's
still satisfied on the multipath rig. [[trap-32-tcp-condition-device-is-xml-sda-use-mxfs-dev-mpatha-and-mxfs-crit]]

### 0.29.0 built (sv D53719AC258E46283E1C254), deployed, TCP lap run
`tests/d0286_tcp_wedge.sh` s418a on 32/tcp-over-mpatha: all containment asserts PASS (3 wedged
holders hit `P-SESSION-POISON`, zero goodbyes sent, zero `P-GOODBYE-RX`, clean-umount goodbye
still intact). But the RECOVERY leg failed: EIO after 185s because **every** TCP slice replay was
refused. Root cause traced to the image-authority gate: its evidence (lineage v3 + FENCED cert +
held MANIFEST grant + epoch) is sourced from the CAW slot table / fence-time manifest, and TCP has
neither — `n_wapply=n_redund=0`, so nothing is ever admissible. Same injected deaths recover in 70s
on CAW. Filed **D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-0288** (critical).
`docs/history/docs/history/docs/history/compiled-sess418-tcp-durable-authority.md`

### GPT ruling on D-0288 — shape "(a)+"
Rejected two cheaper alternatives before approving the real fix:
- (b) fence + lineage + `di_changecount` as authority — rejected: proves nothing about the
  commit→fence interval (release, regrant by another owner, a newer image's home write, *then*
  fence — replaying the old image tears). changecount detects staleness, it isn't authority.
- (c) victim-written grant list as authority — rejected as-is: it's a claim, not authority, unless
  promoted to a master-authorized durable grant ledger (a bigger protocol change — this is what
  ruling #2 below builds).
- (d) "TCP unsupported" is a product decision, not the session's to make.

Approved design ("A+"): a TCP "held manifest grant" must certify that the victim incarnation held
the exclusive write grant for exactly this resource under tenure id G when the image committed,
that the tenure stayed continuously in force (no release/revoke/convert/purge/regrant) until the
victim was storage-fenced and its in-flight writes quiesced, and that an authoritative master
snapshot taken *after* the fence confirms it still held. Protocol order (invariant, never
reordered): fence/quiescence → masters snapshot victim-owned grants → durable per-victim,
per-incarnation manifest shards (checksummed, bound to fence cert + DLM generation + master
incarnation) → durable shard completion marks → barrier (every expected master shard is SEALED or
UNKNOWN; absence ≠ empty) → only then purge/promotion/regrant → replay through the unchanged gate
(admissible iff resource+tenure token matches a positive entry in a SEALED shard; unknown shard ⇒
refuse; atomic per-txn; quarantine unchanged). 7 invariants, incl. fail-closed on any
corrupt/absent/ambiguous evidence and no stale-master sealing/granting. Ties D-0287 into the same
fix: the membership-change table purge must become a *late* phase of a
freeze→fence→seal/reconstruct→barrier→purge/rebuild state machine — purging first destroys the
only TCP authority evidence. Full recovery under simultaneous victim+master loss additionally needs
replicated/durable master grant state; without it, A+ only recovers when the relevant masters
survive (otherwise their shards are UNKNOWN, fail-closed). 20 deterministic verification cases
specified (crash after every durable transition, victim+master die together, cross-master txn with
one unknown shard, corrupt/truncated/duplicate manifest, etc).
`docs/rulings/tcp-replay-authority-shape-a-plus.md`

### GPT ruling #2 — durable authority ledger design (supersedes bare shape (a)+)
Session finding, GPT concurred: `hash%N` mastering means ~1/N of a victim's held resources were
mastered *by the victim itself* — that shard dies with it, so it's UNKNOWN, refused, and the
whole-slice rule (any refused txn ⇒ TORN-UNPUBLISHED ⇒ quarantine) makes N=32 recovery essentially
never succeed. Also: today's TCP lock arm never fills `mxfs_grant_result` (`grant_epoch=0,
lineage=0`) — every TCP image is "noepoch". Ruling approves a durable, single-writer TCP authority
ledger with 4 mandatory changes over the plain (a)+ shape:
1. **Authority identity survives mastership changes**: a stable per-resource authority location
   (CAW slot mapping by resource hash) rather than per-master ledgers — chosen over a verifiable
   durable handoff chain (ACTIVE/FREE/TRANSFER_PREPARED/MOVED) as simpler.
2. **Crash-atomic updates**: in-place 4KiB RMW+CRC is insufficient (a torn page ⇒ UNKNOWN ⇒ routine
   master crashes quarantine slices again). Use two shadow copies per page (write inactive copy,
   flush, highest valid committed seq wins, never overwrite the only valid copy) or WAL+checkpoint.
   Capacity: 65536×32B is already 2MiB; two copies + headers don't fit by subdividing the rman slot
   — needs a second/larger envelope region (mkfs/chk/PROTO_GEN bump).
3. **Fence-time seal as a stable cut**: `SEAL(V, inc, fence_id, config_epoch)` barrier to every
   surviving authority; each authority serializes the seal with grant/release/transfer, drains
   ordered transitions before it, records a watermark, writes a fence-specific shard
   (COMPLETE/UNKNOWN), flushes, acks; the coordinator builds the dead master's shard from its
   durable ledger after proving it fenced; the global manifest is valid only when every authority
   range is a valid shard or explicit UNKNOWN. Post-seal reuse rule: no incompatible successor
   grant on R is delivered until V's replay verdict for R is fixed and publication is complete.
4. **Token widened**: `{master_node, u32 grant_gen}` is insufficient. New
   `grant_id = {authority_epoch, grant_seq64}` (no wrap); record carries fs uuid, resource type +
   full id, owner node + incarnation, mode, authority node + incarnation, config epoch, authority
   epoch, `grant_seq64`, dir_epoch, transition_seq64; FREE records keep `last_grant_seq64`. Absence
   == FREE only with complete valid coverage of the range.

Protocol: grant = durable record → flush → LOCK_GRANT (group commit sound: one flush per batch,
deliver after durability); release = durable supersession *before* the release is externally
complete / before promoting a successor (coalesce release+successor-grant into one transition, only
lazy tombstone reclamation) — never ACK a release while keeping the old record ACTIVE as
"continuity proof". Master loss + remap (D-0287): FENCE(M) → read M's valid durable state →
DURABLE_IMPORT at M2 → ACTIVATE (config barrier) → first grant; missing/corrupt/ambiguous source ⇒
UNKNOWN, never FREE. Live handoff: freeze R → drain → TRANSFER_PREPARED → dest imports INACTIVE →
commit config → source MOVED → dest activates → grants; never two active authorities, "neither" is
allowed. Membership change: the unconditional global purge is replaced by
freeze/transfer-import/activate/post-barrier-GC driven from `v5_membership_cb`; purge becomes GC
only, never the transition itself. Prefer reusing the CAW authority schema +
manifest_collect/verdict code (the CAW authority table with a single-writer WRITE backend) over a
new ledger format — but not the CAW physical protocol, since neighbouring entries share a crash
unit there and shadow pages/log are required here. 15 invariants total (durable-before-deliver/
-release-complete/-promote; single writer per resource+epoch; no empty reconstruction; no ABA;
crash-atomic; complete negative authority; ordered handoff; handoff continuity; stable seal cut;
replay/reuse exclusion; incarnation qualification; capacity fail-closed; corruption fail-closed)
and a ~35-row crash/ordering verification matrix. Full text in the ask_gpt reply;
`docs/tcp-authority-ledger.md` carries the build plan (6-step build order).
`docs/rulings/tcp-durable-authority-ledger.md`

### End state / handoff
0.28.7 board finished clean except `open_defects` policy-red (expected — the zero-defect bar gate). 56 open
defects → 57 after this session's filings (D-0287, D-0288), ledger 144 records. D-0285 CLOSED
FIXED AND VERIFIED. D-0286 containment (poison/session-wedge behavior) verified PASS on both
transports; its remaining closure dependencies are the 9 GPT stop-ship items plus D-0287/D-0288.
D-0287 measurement harness (`tests/d0287_remaster_measure.sh`) run twice, both inconclusive — the
death trigger can't reach the purge on TCP because D-0288 blocks recovery completion first; harness
now defaults `MODE=umount` (clean-departure trigger) and needs a rerun. In flight at the relay when
this note was written (may have died with the session): `tests/d0286_depart_race.sh` p=1..5 on
32/caw, then a full 0.29.0 board via `tests/sess416_board_0286.sh` — check for a live `run.sh` via
`tools/mxfs_pgrep.sh` before relaunching (setsid+nohup) if the log shows no DONE. the ledger-date rule tooling
added this session: `tools/ledger_set.py` (set/prepend/close/add/show) and
`tools/ledger_session_dates.py` (backfilled 24 records from this run's ccmemory note mtimes; 10
holes remain with no in-record evidence). Next in order: read the race-lap + 0.29.0 board evidence;
if clean, D-0286 keeps only the 0287/0288 dependencies open; run
`tests/d0287_remaster_measure.sh` s418c (MODE=umount) on 32/tcp as the first the instrument-first loop measurement of
D-0287; then return to the D-FOREIGN-REPLAY-UNGATED-IMAGES ledger top (gate items 1,2,4,5,6,7 +
sess197 steps 7-10) — the TCP authority-ledger backend is a separate, now-documented campaign.
`docs/history/docs/history/docs/history/compiled-sess418-tcp-durable-authority.md`
