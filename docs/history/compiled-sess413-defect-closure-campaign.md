<!-- sess413: D-529/D-498/D-FR-PUB-AS-RECOV/D-532 closed F&V, D-526 closed, D-512/D-526(b) rulings banked, 0.27.5-0.27.7, setsid relay-survival fix. -->
# sess413 (ccloop c7ee71c6) defect-closure campaign: foreign-replay/recovery-lease family

Single-session (2026-08-24) arc closing five defects across builds 0.27.5→0.27.7,
banking two the design-consult rule GPT designs for the next campaigns, and fixing a rig-ops trap
that had silently killed the prior session's board run.

## 0.27.5: D-529 whole-txn verdict fix

Build = sess412's D-529 fix (classify each replayed txn once, in
`xlog_recover_commit_trans`, via a cached `r_mxfs_verdict` consumed per batch —
this substrate is reused by later ledger #1 tokenization work) + new
`dbg_fr_taint_items_over` module knob (`xfs_mxfs_dlm.c` ~43756, extern in
`xfs_log_recover.c:39`): forces the ATOMIC-SKIP arm (`goto refuse`,
`P-DBG-FR-TAINT-INJECT` probe) for txns with more items than the knob, simulating
an unauthorized image landing in a later batch — the ledger step-2 reproducer for
D-529. `docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

**Trap found while launching the verify chain**: sess412's board
(`run.sh 32 caw`, run_id 20260824T004012Z) died at 00:43:26Z — the *exact* relay
teardown moment, 3 minutes into a ~17-minute run, no criteria.json row, chained
second job never started. Root cause: a harness launched as a plain Bash child
of the claude process (foreground OR `run_in_background`, direct or via a
rig-runner agent) dies when the session tears down at a relay boundary. Fix:
launch long rig work with `setsid nohup sh -c '...' &` — detaches from the
session's process group so relay teardown can't kill it — and append per-stage
`STAGE <name> rc=N` lines to an evidence chain-log under `tests/evidence/`
(never scratchpad — host reboots wipe /tmp) so the next session's harvest is
trivial. At session start, before any rig work (especially rebuilds — srcversion
split risk), check for a live orphan with `tools/mxfs_pgrep.sh` and confirm
`/proc/<pid>` still exists before treating a pid as live; the tool's output is a
point-in-time snapshot with no liveness guarantee.
[[trap-harness-survives-session-exit-check-mxfs-pgrep-before-rig-work]]

D-529 closed FIXED AND VERIFIED on 0.27.5 (sv 9088A5B7BEBB86D41DB4CD8), via
`tests/d529_whole_txn_verify.sh` arms A+B: Arm A (churn fence regression, knob
off) — 5 replayed txns all >100 items, each classified once with the real count,
the 0.27.4 split signature (ADMIT items=100 + items=31 same lsn) gone. Arm B
(`dbg_fr_taint_items_over=100`) — 25 txns items=126-145 all whole-txn skipped
(paired INJECT+ATOMIC-SKIP, identical counts), zero ADMIT lines, zero overlap,
replay ended POLICY-REFUSED rc=-117 refused=25 with terminal publish + AG-mask
quarantine + purge rc=0, no cascade, no BUG on 32 nodes. -117 on a REFUSED
replay is the *designed* errno (POLICY-REFUSED), distinct from the dead
false-TORN family. Two harness traps recorded: P227 classification lines carry
the probe name in *trailing* parens (`... items=N ... (P227-FR-ENFORCE-ADMIT
n=1)`) — a regex anchoring name-then-fields silently drops them, cost one false
arm-A FAIL and a chain stop, so the verify script now extracts name/lsn/items
independently; and only the elected REPLAYER logs classification lines, so a
32-node sweep legitimately sees content on exactly one node.
`docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

## Board midpoint: D-529 + D-498 closed, node_death_replay row added

D-498 (fenced-victim containment) closed FIXED AND VERIFIED on the full
injection matrix: churn (fln9/0.27.4 + d529-armA/0.27.5), idle (sess413, +81s
P-WITHDRAW-QUEUE, 1 conflict, slot released +1s), preempt (sess409), logioerr
(D-409). Ledger 56 open / 137.

Board on 0.27.5 (sv 9088A5B7BEBB86D41DB4CD8): 26 PASS + open_defects (POLICY)
+ crash_consistency FAIL 90/90 BUDGET_EXHAUSTED=32 at hostload 31.9 — this is
D-401's known fresh-prep/shared-dir-create face at the budget edge (standalone
re-run same build/cluster: PASS 19s/90 at hostload 17.6, 204/204); recorded as
recurrence of D-401 / symptom of D-32NODE-SHARED-DIR-CREATE-PACE, budget NOT
widened per the derived-budget rule.

New board criterion `node_death_replay` (gate item 3 of ledger #1's default-on
gate): `coord=host` class added to `run.sh` (`run_host`, `MXFS_RUNLOCK_OWNER`
re-entrant lock), new terminal `death` category in `criteria.json`,
`tests/death/node_death_replay.sh` runs 2 armed tck laps. First PASS 343s/470
(shared 111s/4 replays, single 231s/2 replays, chk clean both). Board is now 29
applicable rows at 32/caw. `docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

## 0.27.6: dbg_fr_fail_replay knob, D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED closed, D-532 found

In tree for 0.27.6: `xfs/xfs_log.c` `dbg_fr_fail_replay` module knob
(>0 = every `mxfs_xlog_recover_foreign_slice` fails -EIO before any work,
`P-DBG-FR-FAIL-REPLAY` alert, verdict reason stays NONE) + new
`tests/fr_mount_barrier_fail.sh`: knob on fleet → joiner umounts → victim
virsh-killed → survivors must refuse+re-arm with zero publish lines → joiner
mounts into the failure (barrier "stays unpublished" reason-NONE alert
asserted) → knob cleared → retry must replay+publish (slice never lost) →
victim VM restarted. Targets the mount-barrier arm of
D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED (live path already verified
sess234). `docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED closed FIXED AND VERIFIED on
0.27.6 (sv F5CB4164740E4BA16B14FD1), both call sites exercised via
`dbg_fr_fail_replay`: live path (frmb1, 32/caw) — 3 refusals @30s cadence, 0
publishes in window, retry after clear replayed+published exactly once,
joiner mount failed CLOSED during the window; mount barrier (frmb2 --cold2,
2/caw sole-survivor cold start) — error branch fired 4x ("replay FAILED (-5) —
the slot stays unpublished..."), 0 publishes, mount aborted fail-closed.

**New critical defect found**: D-MOUNT-RECOV-LEASE-STRANDED-BY-DEPARTED-OWNER-
UNMOUNTABLE-532 — the aborted cold mount's clean teardown released its own
member slot but left the victim's recovery descriptor owned by the retired
incarnation, so every later mount loops `P238-RECOV-OWNED` ("NOT proved it
dead") and aborts at 30s: **filesystem unmountable until re-mkfs.**

Harness traps: fence-family 32-node arms can never exercise the mount-barrier
error branch (a survivor always holds the recovery lease; the joiner only
waits) — cold2 (2-node sole-survivor) is the only deterministic route.
`fr_mount_barrier_fail.sh` live32 sweep counters returned empty files on the
real run but worked in isolation (unexplained; timelines harvested manually;
needs a fix to write per-node raw+rc into $OUT). d385 stepwise `arm_lap` runs
rowwise by default: per-lap bound must be `sum(row budget+42) ≈ 640s`, NOT the
295s chunk bound — a 330s bound orphaned a lock-holding `run.sh` (timeout
kills only the direct child) and burned a whole 6-lap protocol (sess413_d385_
0275 invalid, laps 2-6 all rc=3 lock refusals, verdict 0 heads).
`docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

## D-532 fix design and landing (0.27.7)

design-consult ruling on D-532, hierarchical: **(a) MANDATORY** — crash-safe mount-abort
give-back, strictly ordered: close recovery submission gate (serialized with
every submit path) → quiesce/join workers + drain all bios incl. SCSI-EH
resolution + cache/order barrier → durable conditional CAS of every descriptor
owned by (node,inc,term) back to UNOWNED, preserving pending stage (anti-ABA) →
verify none owned → only then durably release own member slot → only then
discard incarnation/PR key. **Critical failure rule**: if quiesce/drain/give-back
can't be proven, do NOT write the clean member-slot release — an owned
descriptor with a fenceable owner is recoverable (HB expiry + fence); an
unfenceable orphan owner is not. **(b) backstop** (deferred): clean-departure
takeover proof needs member release upgraded to an incarnation-specific durable
CLEAN-QUIESCE CERTIFICATE — bare RELEASED bit never sufficient (late in-flight
bios can land after the release write); takeover rule becomes fenced-dead OR
certified-clean-quiesced. No standalone TTL takeover (expiry proves renewal
stopped, not writes stopped) — wedged-owner path stays progress-timeout →
unhealthy → existing PR fence → takeover. Crash-cut safety enumerated: crash
before give-back falls back to existing HB-expiry+fence; crash after give-back
before member release leaves the descriptor UNOWNED and safely claimable;
member-release-before-give-back is prohibited under (a).
`docs/rulings/d532-lease-giveback-design.md`

D-532 fix shape (a) landed in tree (build as 0.27.7): `dlm/disklock.c` new
`mxfs_disklock_recovery_relinquish_owned(ctx)` walks all 64 HB slots, CASes
every recovery descriptor owned by (ctx->local_node, ctx->epoch) durably to
UNOWNED (owner fields zeroed, stage_seq+1, stage+certificate preserved, reseal)
with one -EAGAIN re-read retry; any read failure or failed give-back returns
-EIO (probes P236-RECOV-RELINQUISH / -RELINQ-READFAIL / -RELINQ-FAIL /
-RELINQ-SUMMARY). `mxfs_disklock_release_slot`, after the running-EBUSY guard,
calls relinquish_owned; nonzero → `P236-RELEASE-DEFERRED-OWNED-RECOVERY` and
returns WITHOUT clearing the member record (identity stays fenceable — the
ruling's critical rule); all 4 `v5_mount.c` callers (5064/5452/5937/6049)
already tolerate a failed release by leaving the slot. Verification via
`tests/fr_mount_barrier_fail.sh frmbN --cold2`: after the aborted first mount,
dmesg must show P236-RECOV-RELINQUISH before "released heartbeat slot 0 (clean
teardown)"; the second mount must claim immediately (no P238-RECOV-OWNED
loop), replay slot 1, publish once, MOUNT2_RC=0.
`docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

D-532 closed FOUND AND FIXED AND VERIFIED this session (frmb5 PASS), landed in
0.27.7. `docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

## D-526 clean-departure ruling (approved, builds after 0.27.7)

design-consult ruling on D-526: EMPTY must be a durable TERMINAL state for one exact
slot incarnation. Chain (D-532 give-back already enforces the prerequisite):
durable clean-unmount record → durable lease give-back → exact-image CAS to
EMPTY; a concurrent recovery/fence guard beats the CAS and the release is
refused. **(a) monitor clean-departure arm, approved with conditions**: on a
monitored slot, valid record + FLAG_EMPTY + exact match (slot, node_id,
epoch/incarnation, generation) → FUA re-read confirm → tokenized local close
under the state lock, revalidating the monitor still binds that incarnation,
then reset dead-confirm/evict/fence state and cancel queued work (workers must
revalidate the incarnation token before declaring death/fencing/latching/
electing); ABA guarded via compare-and-close against the monitor binding.
**(b) recovery-pending latch clear, approved**: matching EMPTY (exact victim
tuple + op token) closes the pending instance as CLEAN-DEPARTED without a
re-read, must also invalidate queued election/replay work, block late fence
completions from re-latching, and relinquish any phantom recovery descriptor
via exact-owner CAS. **(c) hb_still_dead_stamp, approved, prefer tri/quad-state**:
STILL_DEAD / NOT_DEAD_OR_ADVANCED / CLEAN_DEPARTED / FOREIGN_OR_INVALID —
matching EMPTY is always CLEAN_DEPARTED, never "still dead". Fence path: at
fence-intent, exact-incarnation FUA validation; matching EMPTY publishes
CLEAN_DEPARTED/NO_FENCE_NEEDED (distinct from FENCED, suppresses recovery but
never authorizes replay) — no SCSI-PR issued, never rely on NOINTENT-by-luck.
Verify arm: `tests/d513_lone_mount_torn.sh` step-1 mass unmount asserting zero
"no longer responding" for released slots and zero surviving
P163-RECOVERY-PENDING latches. Build order fixed: 0.27.7 = D-532 give-back
(verify cold2 first), 0.27.8 = this design.
`docs/rulings/d526-clean-departure-monitor-arm.md`

D-526 itself closed FIXED AND VERIFIED this session — sess346's existing
machinery verified via `d526_mass_unmount_verify.sh`: 31-node mass unmount, 31x
P163-CLEAN-DEPART, zero deaths/fences/latches, chk clean.
`docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`

## D-512 ruling (banked, large campaign, not yet built)

design-consult ruling on D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512, fix shape (c):
invariant — after `MXFS_IF_INCARN_STALE` publishes, no operation may obtain
data, submit IO, dirty/fault a page, or successfully return that inode as
current; retirement (liveness) and gates (safety) are both required; lookup
must never fall through to the poisoned shell (remove the 4-retry-then-
fallthrough — blocked retirement returns -ESTALE). Six mandatory components:
(1) I_DONTCACHE on the whole poisoned inode + alias pruning, retry-iget only
after actual reclaim, blocked references → -ESTALE (no spin); (2) full gate
set — not just open+iomap_begin, which misses cached reads/resident PTEs/
writeback — covering open/read_iter/write_iter/mmap/fault/page_mkwrite/fsync
(-ESTALE, never stale durability)/splice_read/direct-IO/buffered+readahead
mapping/writeback (no dirty-G1 submission post-poison)/fallocate/punch/zero/
copy_file_range/reflink/FIEMAP/ioctls/io_uring, vm_fault → SIGBUS after
revocation, with shared/exclusive incarnation-transition sync (per-inode
rwsem or XFS io/mmap/layout-lock integration) since a plain test_bit races;
(3) poison-time revocation ordering — block new ops → publish → unmap_mapping_
range all mappings + TLB → drain in-flight → invalidate_inode_pages2 (both
PTE-zap and pagecache-invalidate required, neither alone sufficient) → later
faults SIGBUS; (4) dirty-G1 hazard — eviction/writeback must never flush G1
into G2 blocks, full ordering: ref-hold → exclusive lock + XFS exclusion →
validate mismatch → publish poison → DONTCACHE → block new IO → drain gated
ops → unmap → cancel/discard queued G1 writeback → invalidate → prune → drop
ref → reclaim; (5) `MXFS_IF_INCARN_STALE` cleared only in the serialized
IRECLAIM/fresh-init path with full state reset before I_NEW release, never
re-enabled in place on a false positive (retire+reconstruct instead); (6)
cluster reuse barrier — no ino/extent reuse until every node holding the old
incarnation is revoked and G1 IO drained; unrevoked G1 writeback discovered
post-reuse means quarantine/fence/shutdown, never silent continuation
(interacts with the existing publication-durability gate F1-F4). Verification
beyond the existing zsl/inew/md5 checks needs a long-lived-ref matrix (open
r/w fd, dio fd, ro/rw mmap, resident+dirty pages, in-flight buffered/dio,
queued writeback held across reuse) plus race arms (poison between
gate-check and submit / during fault / during writeback, elevated i_count
forever, crash during revocation). Scheduled as its own build series after
the current closure wave.
`docs/rulings/d512-incarn-stale-full-gate-design.md`

## Relay-final state

0.27.7 (sv 423E597D960F3668314F975) deployed, fleet 32/caw prepped
03:16-03:22Z. Five defects closed this session: D-529, D-498,
D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED, D-532, D-526. Ledger: 55 open
/ 139 (40 critical); also newly ledgered D-SLICEINIT-531 (high, from the
sess412 twin-hole ruling, scheduled as 0.28.0).

Orphan chain2 (setsid, survives relay, launched 03:16:17Z) left running at
relay: `agifc` stage (`tests/rman_matrix.sh base_shared x3`, D-408 step-1
repro attempt — note the 3 same-name arms overwrite each other's evidence dir,
so if `am>0` on a non-final run it must be rerun single-shot for capture) and
`board` stage (`MXFS_FORCE_PREP=1 ./run.sh 32 caw`, the d385 verdict's "full
28-row board" closure requirement).

Pending dispositions handed to the next session: D-AGI-UNLINKED-CROSSNODE-
RECOVERY-SHUTDOWN — d385 TREATMENT already passed (heads=208 joint_ok=208
SPLIT=0, all laps green, 32/32 harvest) plus both tck inj=20 shapes plus the
neg-mismatch arm (sess402) — close it and its symptom
D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361 together once the board result
lands. D-408 (AGIFC divergence): 3x base_shared verdicts clean so far — `am>0`
means capture+diagnose, 3x clean means it stays OPEN (cannot-reproduce is not
a disposition), next step is a higher-rep sweep or instrumented wait. Board
crash_consistency: a repeat 90/90 FAIL is D-401's face again — do not widen.
Next queue after harvest: close D-AGI-UNLINKED + D-361 on the board result,
then the D-512 campaign or ledger #1's remaining gates (F2 domain knob
binding, knob=1 capture campaign), then D-531 SLICEINIT as 0.28.0. New
harnesses added this session (all in `tests/`):
`d529_whole_txn_verify.sh`, `fr_mount_barrier_fail.sh` (live32 + --cold2),
`d526_mass_unmount_verify.sh`, `death/node_death_replay.sh`.
`docs/history/docs/history/docs/history/compiled-sess413-defect-closure-campaign.md`
