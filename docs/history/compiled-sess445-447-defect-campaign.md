<!-- sess445-447: D-0512 authority-token retype, D-0514 replay deadlock, D-0515 quarantine gate, D-0450/D-0510/D-0511 closures, default-on token-enforce f… -->
# sess445-447 campaign: D-0512 authority-token retype, D-0514 second-victim replay deadlock, D-0515 quarantine namespace gate, default-on token-enforce flip

Continuous chain-driven campaign, tree 0.51.0 -> 0.54.0. Session checkpoints (chronological
spine): `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`,
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`.

## D-0512: dir sf->block re-type voids the buffer authority token

Root (sess445, chain 35 point 13 on 0.51.0): a takeover owner refused a victim slot on one
class=NONE/st=INCOMPLETE dir-block image inside the create txn -> terminal -> bootstrap
REFUSED. Cause: `xfs_dir2_sf_to_block` calls `xfs_dir3_data_init` (sets DIR_DATA_BUF, logs =
capture instant, `mba_blft=DIR_DATA`) then `xfs_dir3_block_init` re-types to DIR_BLOCK_BUF;
the existing serialize void arm in `pal/linux/xfs_buf_item.c` (~1446, `cap->mba_blft !=
current blft`) fires and voids the buffer's authority to class NONE/INCOMPLETE, so a foreign
replay can never prove it. Same shape at `xfs_dir2_leaf_to_block`, `xfs_dir2_block_to_leaf`,
`xfs_dir2_node.c:909/924`. `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

Producer-side proof (chain 38, 0.52.0): a 32-node x 4-create burst into one shared dir hit
`P-AUTHCAP-VOID why=blftchg` x3 (all three re-type sites: sf->block, block->leaf, leaf->block
during harness cleanup), all on the same dir block (`blkno=59308112`), class_cap=3 (INODE),
st_cap=1 (VALID) voided to outcome=8.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

GPT ruling (RULE-5): fix must be A' (witness reclassify at the *next* protected dirty), not A
(synchronous classify inside `xfs_trans_buf_set_type` — header/owner may be uninitialized for
the new format at that point). On blft change with an existing capture, mark
AUTH_BLFT_PENDING + record the new blft; classify at the next dirty with the current blft; if
VALID and the full authority identity (class/resource/epoch/lineage/owner_ino/auth_gen)
matches the original capture -> accept (update only `mba_blft`); different authority -> MIXED;
cannot prove -> INCOMPLETE/UNPROVEN, never keep the stale proof. No subsequent dirty after a
type change -> stays void (existing blft-compare backstop kept). STOP-SHIP list: classify in
set_type, pending cleared without a post-transition classify, serialize consuming a stale
capture while pending, comparing only class/resource, trusting unchecked transitional-header
offsets, no negative MIXED/no-dirty tests.
`docs/rulings/d0512-blft-retype-authority-void-aprime.md`

Implementation plan (A', shipped as 0.53.0): `struct mxfs_bli_auth.mba_retype_pending` (renamed
from `mba_pad`); `mxfs_bli_auth_note_retype()` in `pal/linux/xfs_buf_item.c` called from
`xfs_trans_buf_set_type` after `xfs_blft_to_flags` — marks pending, never classifies there;
capture-time branch classifies at the next dirty (retype_ok / MIXED / retype_unproven,
`P-AUTHCAP-VOID why=retype_unproven` on the unprovable case); serialize gets a new
`retype_pending` void arm (class NONE/INCOMPLETE, `why=retype_nodirty`) ahead of the existing
blft-compare backstop; test-only knob `mxfs.authcap_inject` (1 = force MIXED after a successful
reclassify, 2 = ignore the pending reclassify) for negative arms.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

Verification arc: chain 39 built 0.53.0 (sv BB5DD70F) and reran the same burst -> VOID=0,
`P-AUTHCAP-RETYPE-OK` x3
(`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`). Chain 42's
first negative-arm run was itself an artifact: both "fix COMPLETE" and "inject1 COMPLETE" never
actually carried the re-typed image, because the replay slice only ever holds a node's last
2-4 transactions (see trap below) — harness fixed to stop at the converting create; the
corrected inject2 then produced a VALID negative (`VOID why=retype_nodirty`, survivor REFUSED,
`classless=1`, `P227-TOKEN class=0 st=6`).
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md` Closed FIXED AND
VERIFIED sess446 (chain 47: converting create visible, `classless=0`, inject1 REFUSED, inject2
REFUSED; chain 44 point 13 fails=0, 31/31).
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

## Harness trap: a crash slice holds only the victim's last 2-4 transactions

`mxfs_destage_kick_fn` (xfs/xfs_mxfs_dlm.c ~2341) issues an async log force + full AIL push on
every create/unlink debounce window, so the on-disk log tail tracks the workload within
milliseconds — per-file fsync holds nothing in the journal. Measured: 200 fsync'd creates left
`buf=8 txn=2` identical across nodes and laps (an earlier-carved chunk's ICREATE was already
gone); a 24-create dir-conversion probe replayed a slice missing the actual sf->block
transaction, so both "fix" and "inject1" arms showed false COMPLETE. Consequence for every
crash/replay harness: the transaction under test must be the victim's *literal last*
transaction — create one entry at a time and stop the instant the target fact fires (dmesg
probe count, or `stat -c %i` hitting a chunk boundary), never `sync`/`syncfs` before killing the
node. Also: `/proc/sys/fs/mxfs/` and `/proc/sys/fs/xfs/` do not exist on the nodes
(`xfs_sysctl.o` excluded, Kbuild:157) — writing to them is a silent no-op, not a log-covering
knob. `P133-ICLUSTER-SYNCINIT` only prints for the first 20 carves per module lifetime, so it
cannot signal a later carve. Fixed in `tests/bootstrap_full_restart.sh` and
`tests/d0512_sf_to_block_replay.sh` (stop-at-boundary payload capture).
[[trap-mxfs-slice-holds-only-last-txns-destage-kick-crash-tests-need-target-txn-last]]

## D-0514: second victim's replay never starts (foreign-replay work-item serialization)

Found sess446: board `node_death_replay` single lap on 0.53.0 — slot 24 fenced+sealed but its
replay never started in 95s, journal lost. Scout: election is local-lowest-live-slot in
`v5_dispatch_slice_recovery` (dlm/v5_mount.c:6723); a node already inside
`recovery_pending[slot]` does not re-elect; the work fn loops
`for_each_set_bit(m_mxfs_foreign_dead_slots)` (xfs_mxfs_dlm.c:52143).
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

H1 hypothesis + instrumentation (sess447, 0.53.2): the replay work item's own inline tail sweep
of victim A blocks on victim B's dead-but-undetected grant; B's notify then `queue_work()`s the
*same* work_struct, so B's replay can never start while A's callback is parked in the sweep.
Lap-1 trail confirmed: `RECOVERY-COMPLETE slot 29` and `P97-SWEEP-START slot=29` in the same
millisecond, no `SWEEP-DONE`; slot 31 detected 0.743s later, elected, then silence. Lap 2
(no forced hold) passed — both replays completed before any sweep ran, showing no invariant
requires A's sweep to precede B's replay.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

GPT ruling: H1 ranked well above the alternative (`queue_work` returning false is not
sufficient — a running-but-blocked callback cannot be reissued while parked, and "the running
instance will pick up the new slot" is not an invariant once its dead-slot pass has already
finished). Fix is *subtractive*: the replay work fn must claim/replay/publish/purge/mark
`sweep_pending`/kick the reap worker/return — never run inline maintenance that can block on
grants serialized through the same callback. Hazard flagged for follow-up: separating the work
items removes work_struct serialization but not a possible local-lock cycle (sweep holding
ILOCK/AG lock while waiting on B's purge); proposed hardening is a dead-generation counter so a
sweep's DLM waiters can detect a newer dead-slot notify and retry (`-EAGAIN`, sweep restart
must be idempotent). `docs/rulings/d0514-inline-sweep-deadlock.md`

Landed as 0.53.3 (remove the inline sweep from `mxfs_dlm_foreign_replay_work_fn`'s tail;
`mxfs_reap_worker` already sweeps under the bitmap-empty guard). Closed FIXED AND VERIFIED
sess447 (chain 53: 3/3 rows; chain 54: lap F' shows a 2ms lease grant during the parked sweep
window). `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

## D-0515: quarantined-dir namespace ops proceed lock-less

Found sess446 (chain 48, `tests/umount_under_quarantine.sh`): forcing an in-closure refusal
(root dir quarantined via `ag_mask 0x1`) produced `P240-QUAR-REFUSE ino=128` on both test nodes
for a `touch`, yet the create committed on both anyway — test1's rc=1 came only from the OPEN
gate, not from namespace refusal. Fixed as 0.53.1: `mxfs_quar_gate_op()`
(`xfs/xfs_inode.h`) called at every namespace entry point in `pal/linux/xfs_iops.c`
(create/tmpfile, lookup, ci_lookup, link, unlink, symlink, all 4 rename inodes, readlink,
setattr, update_time), plus clean-txn backstops in `xfs/xfs_trans.c` and `xfs/xfs_inode.c`
(cancel+unlock+return before the transaction dirties anything, both in `xfs_create` and
`xfs_rename`). `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md` Verified
sess447 (chain 51, 0.53.2, expanded 4-op namespace probe — create/mkdir/unlink/rename — refused
on both hosts with `P240-QUAR-NSOP-REFUSE`); closed FIXED AND VERIFIED alongside D-356.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

## Other defects closed/filed in the same arc

- **D-BOOTSTRAP-OWNER-LIVENESS-CROSS-NODE-CLOCK-0450**: closed FIXED AND VERIFIED sess446 —
  live-owner probe refuses a contender in 5s (`P-BOOT-CONTENDER-OWNER-ALIVE`, no takeover) while
  the same code correctly takes over a genuinely destroyed owner (264s).
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510**: negative-arm laps repeatedly missed
  their target — lap 2/3 corruption hit the inode-item verifier first
  (`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`) or produced no
  ICREATE at all in the slice (harness fixed per the last-txns trap above); lap 4 finally hit
  `P-ICREATE-VERIFY-FAIL why=magic` -> REFUSE, sector untouched, closed FIXED AND VERIFIED sess446.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-0511 (purge/restart performance)**: purge batch fix cut scan cost from 8.5s to 175ms p50
  (whole-cluster restart 545s -> 298s -> 203s across builds); a snapshot-prefetch ring (depth 3,
  `fr_stab_prefetch`) was added after discovering the original prefetch barrier armed only k+1
  and dropped the single entry before use.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md` Even
  after the ring landed, NDR row walls (404/393/365s on 0.53.3) were not improving over the
  343s baseline — left as an open per-lap cost question (churn/detect/replay/wait/umount/chk
  breakdown owed). `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md` Closed
  FIXED AND VERIFIED sess447 once row-wall variance was attributed to lap setup (victim VM
  restart+remount), not purge.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE**: closed FIXED AND VERIFIED sess447 (`no_survivor`
  lap 2, fails=0, self-succession + 32 replays).
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-356 (umount escalation)**: measured clean on the quarantine harness (31 clean umounts in
  1s, zero DLM-unrecoverable/shutdown/withdraw signals); disposition folded into the D-0515
  closure once the 4-op probe reran clean on the fixed build.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516** (critical, filed sess447): the mount-time domain
  validator's `fua_disable=0` (crash-durable) branch admits unconditionally with no
  stable-media qualification — filed as a gap the scoped coherence-only flip does not close.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
- **D-401 / D-32NODE-SHARED-DIR-CREATE-PACE**: crash_consistency board face recurs across
  builds (all ranks reach barrier-written ~83-90s, watchdog ~85-88s, zero fault probes — a
  performance ceiling, not a correctness fault) and stays the board's chronic red cell.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md` Pace attribution
  work refuted the lost-nudge hypothesis (every ticket wake=1, zero backstop/swallowed) and
  found transfer-tail latency was a multi-hop artifact, not a single stuck taker; only 72/379
  handoff hops even reach the ticket-sighting path.
  `docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

## Default-on campaign: `foreign_replay_token_enforce` flip (D-FOREIGN-REPLAY-UNGATED-IMAGES)

GPT ruling (sess447) settled two long-open sequencing questions. Q1: the sess197
`replay_gate_enforce` (F1/F3/F4) work is release-gate (may a tenure release with obligations)
and is **not** a prerequisite for the token-gate default (may a fenced foreign image be
applied) — manifest snapshot + v3 lineage + RELMARK + `di_changecount` already supersede the
F1/F3/F4 release predicates for APPLY; do not tie the flip to them, do not arm
`replay_gate_enforce`, do not flip `f4_gate`. Stop-ship proviso carried forward regardless: an
unlinearized F4 release must never forge a permissive RELMARK. Q2: ship as a *scoped
coherence-only* flip — `foreign_replay_token_enforce=1`, `release_proof_enforce=1`,
`target_cache_protected=0` by default, with a new **mount-time** validator (not setter-only)
that refuses `fua_disable=1 && tcp=0`, `icluster_dlm=1`, and prohibited mixed versions before
any clustered RW admission; `fua_disable=0` (full crash-durable) stays gated behind a separate
stable-media qualification campaign. Q3 laid out 6 phases ending in a >=10-lap production-default
regression streak across NDR/unlinker_death/rman/vergate/whole-cluster-restart before general
release. `docs/rulings/default-on-scoped-coherence-only-flip.md`

Landed as 0.54.0 (UNBUILT then built in place by chain 55):
`mxfs_foreign_replay_token_enforce` default flipped to 1; new
`mxfs_durability_domain_admit(mp)` in `pal/linux/xfs_super.c`, called after
`m_mxfs_proto_admitted` in `xfs_fs_fill_super` and on ro->rw reconfigure — refuses
`icluster_dlm=1`, `enforce=0`, `release_proof_enforce=0`, `(fua_disable=1 && tcp=0)`, and bare
`fua_disable=0` (the D-0516 gap), admitting only `(fua=1,tcp=1)` as coherence-only
(`P-DOMAIN-ADMITTED`); RO mounts ungated. Added `mxfs_f4_census_dump` (per-open-F4-record
trylock probe -> `P285-F4-REC truth=...`) to answer the F4 proviso directly: RELMARK is
published on every walked-clean dir release regardless of `f4_open` when `f4_gate=0`, and
P285 fired 1718x in evidence, so withholding the marker blindly would cause quarantine storms.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

Harness/rig changes to match production defaults: `tests/setup/prep_node.sh` now declares
`target_cache_protected=1` (the production configuration) and prints effective knobs;
`tests/death/node_death_replay.sh` dropped its `ARM` override (no harness-side enforcement,
production relies on prep's declaration); new `tests/domain_admission_matrix.sh` drives 7
mount-time rows (R1-R5 must refuse with the correct reason and no admission/replay, R6
`(1,1)` must admit, R7 read-only must be ungated) — first run hit a harness bug (`grep -o
MOUNT_RC=` matched `UMOUNT_RC=`), fixed by anchoring the match; corrected run got all 5 refusal
rows right and R6 admitted (`P-DOMAIN-ADMITTED`, 7s wall).
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

Final production-default 32/caw board (0.54.0, run `20260829T135413Z`): 21 PASS, 1 FAIL
(`crash_consistency` — the chronic D-401 barrier-pace face, zero checksum failures), 7 rows
PENDING due to an undersized 900s wrapper bound (chain 57 re-runs them at 660s). Board wrapper
budget for a full 32/caw run now exceeds 900s (~509s summed walls + 12s x 28 tests +
preflight) and needs re-deriving from `./showstat.sh 32 caw` after chain 57 completes.
`docs/history/docs/history/docs/history/compiled-sess445-447-defect-campaign.md`

## Harness trap: never edit a running bash script

bash reads a script by file offset as it executes; already-parsed function bodies are safe, but
every top-level statement after the currently-executing line is re-read from the saved offset,
so inserting/deleting bytes above that point makes the live process execute mid-line garbage.
Hit while `run.sh` was mid-board and its top-level tail (`.last_run.json` write, `=== done`
echo) still had to run past the edited region — rule: never edit a script any chain currently
has in flight; queue the edit for after DONE, or revert byte-identically if it already landed.
Same session also fixed `run.sh:1358`'s `.ccph` capture: `pkill -f '$script'` on the remote
node matched the killing shell's own `bash -c` command line (which carries the script path) and
killed itself before the phase capture could run — every `testN.ccph` came back as a single
blank line. Fix: bracket the first character of the pattern (`pkill -f -- '[x]est...'`) so it
cannot match its own invocation text.
[[trap-never-edit-a-bash-script-while-it-is-running-run-sh-offset-shift]]
