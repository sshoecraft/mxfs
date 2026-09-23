<!-- D-488 AG-DLM livelock: 6 faces (allocator/EFI/truncate/preacq/dialloc/relock) found+fixed sess253-283, 0.11.490-500, plus false-death incident. -->
# D-488 AG-DLM livelock/deadlock campaign (ccloop c7ee71c6, sess253-283, 0.11.490-0.11.500)

One defect, six distinct "faces" of the same underlying rule violation, found
serially by fixing each wedge and re-running the board until the next one
surfaced. Interleaved with the unrelated step-5 F3 keyed-release-proof work
(sess253/258) which sess259 used to deploy the board that first reproduced
D-488, and with the sess276 false-death/foreign-replay incident that
D-488's own fix chain exposed underneath it.

## Step-5 F3 keyed release proof (context, not D-488 itself)
`docs/rulings/step5-f3-iclus-ticket-shape.md`: GPT ruling
on ICLUS write-accounting shape — keyed per-{daddr} inflight/generation
tracking (not device-wide), proof = settle→keyed-inflight-0→generation-capture→
real-flush→verify-unchanged, ticket_status enum, F3_COMPLETION_PROOF_READY
stays 0 until step-6 blocks release on it (telemetry-implemented ≠ ready).
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` landed all 8
edits, built 0.11.490 (sv B8A561D0), not yet rig-verified. Build trap: a
forward struct decl before the header include that defines it creates a
prototype-scoped type — use a bare forward tag.

## Face 0: first repro (sess259)
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` deployed
.490, board chunks A+B green, but `scaling_curve` FAILed 3/3 with
NO_TERMINAL_RECORD. Live probe showed one AG holder (test27) stuck 90s+ with
`holders=0 cached=1 sched=1`, page_ms still climbing after the harness killed
the owning dd — read at the time as "pin outlives process death." That read
was wrong (see sess260).

## Face 1: iomap allocator blocks AG acquire while holding ILOCK+txn (sess260)
`docs/rulings/488-mechanism-proven-gpt-ruling-restart-protocol.md`
proved by direct instrumentation: a dd holds ILOCK(EX) + an open, inode-joined
transaction; that inode's AIL item is the only flushable item in its home AG
but iflush needs ILOCK_SHARED, held write-exclusive by the same dd, which is
itself blocked acquiring a *different* AG inside the inline pre-CAW demote
scan. Distributed hold-and-wait (Coffman cycle), not lost tracking — the
dd was alive and spinning until killed, correcting sess259's misread.
GPT ruling: core invariant — **an operation may never block for a cluster AG
grant while holding ILOCK / a dirty txn / any resource an AG drain can
require.** Fix shape: NOQUEUE/trylock-only AG acquire in lock-bearing
allocator context; on would-block, unwind (cancel clean txn, drop ILOCK),
block for the grant in a lock-neutral context, relock, revalidate, restart
the whole allocation. Rejected: escrowed release, prefer-own-AG,
deadlock-detection/priority-inheritance (no legal rollback once dirty).
This invariant recurs as the root of faces 3, 4 and 6 below.

## Face 2: cross-AG ABBA in the EFI-finish (truncate) path (sess263)
`docs/rulings/488-release-before-block.md`: a 3-node ring
(test1→ag7, test23→ag8, test6→ag5, ~17 more trailing) all blocked in
`xfs_bunmapi_range → xfs_defer_finish → __xfs_free_extent → mxfs_ag_dlm_lock`,
holding retained grants across defer rolls with no acquisition ordering.
GPT ruling: release-before-block is safe — a durable EFI doesn't need
continuous AG ownership (its extent isn't in the freespace btrees yet).
Fix: tri-state defer-safety flag (NOTDEFER/SAFE/UNSAFE, SAFE after each
defer roll, UNSAFE after each finish_item) instead of the unconditional
XFS_TRANS_DIRTY bit; when UNSAFE and would-block with retained grants,
return -EAGAIN to the defer framework instead of blocking.

## Dead-holder leak, then a fourth face masquerading as the same bug (sess265/266)
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` found a
distinct leak: `xfs_alloc_vextent_iterate_ags` on an error *after* a
successful `prepare_ag` dropped `args->pag` without unlocking the AG DLM
holder — a permanent stranded holder=1, immune to `ag_strand_repair` (which
requires holders==0).
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`
landed the fix in 0.11.493 (register deferred unlock before dropping `pag`,
gated on `args->agbp` — proven the correct discriminant by auditing every
sibling error path). First run after: a *new* face — two nodes cross-held
AGs with `holders=0 cached=1 sched=1`, i.e. the BAST worker was scheduled and
fully releasable yet never completed for 330s+ — distinct from both the
dead-holder shape and the earlier orphan shape.

## Face 3: truncate ILOCK poisons its own home-AG drain (sess267/268)
`docs/rulings/488-third-face-proven-gpt-ruling-seam-handoff.md`
proved the sess266 face: truncate holds ILOCK_EXCL across the free-extent
defer chain while blocked on a *foreign* AG; its own committed log item is
the only AIL item in its *home* AG, and iflush needs the ILOCK it holds —
cross-node Coffman cycle again, this time via the truncate path rather than
direct allocation. GPT ruling: **contended-only post-roll ILOCK handoff** —
on trylock failure in a defer context, return -EAGAIN; at the next clean
defer-roll seam, detach the clean joined inode items, `ihold`, drop ILOCK,
block for the AG grant holding nothing, pregrant-release back to cached
(not held across relock — alloc-side invariant not yet global), relock in
ascending-ino order, revalidate, rejoin, resume.
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` landed
this as 0.11.494; `scaling_curve` went 0/32→3/3 PASS, verified no regression.
Immediately opened face 4: `rsync_paired` wedged in `xfs_rename →
mxfs_trans_preacquire_inode_ags → mxfs_ag_dlm_lock` — the same handoff need,
un-implemented on the rename preacquire path.

## Face 4: rename preacquire, then dialloc/buf (sess269)
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`
extracted the handoff into `mxfs_trans_agwait_handoff` and applied it to
`mxfs_trans_preacquire_inode_ags` (bounded 8-handoff budget, then -EAGAIN up
to the caller; `xfs_rename`/`xfs_remove` retry with jittered backoff, capped
exhaustion → -ETIMEDOUT — this cap itself becomes a bug in sess282). Landed
0.11.495, `rsync_paired` run1 went 0/32→32/32. Run2 exposed face 5: a
different node wedged in `xfs_create → xfs_dialloc → mxfs_ag_dlm_lock`
(blocking, not the trylock-only wrapper) with the drain stuck on an
IFLUSHING *buffer*, not an ILOCK (`ilocked=0`) — a genuinely new poison
shape, not yet root-caused this session.

## Face 5: own-bit orphan / silent unlock (sess270-273)
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`:
narrowed to a node (test28) that legitimately held ag=3 EX, went through a
rapid readopt-storm (~500 acquire/demote/unlock cycles/s), then went
*permanently silent* on ag=3 — its own bit stayed EX on the platter with no
in-core tenure and no further local BAST traffic. Two open hypotheses: a
silently-swallowed unlock-CAS failure that drops in-core tenure without
proof of an actual on-disk clear, or a stuck sched/demoting latch that makes
the RX handler deaf. Node then died and the resulting foreign-replay refusal
(#1, D-FOREIGN-REPLAY-UNGATED-IMAGES territory) froze the strand permanently
— self-repair can only reclaim a *dead* node's bit via lease purge, itself
blocked by the refusal.
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`
eliminated several known silent-failure paths and found 3 more inside
`caw_unlock_gen_body` that discard rc (find_slot -ENOENT, find_slot other
err, CAS non-EAGAIN hard err) — all folded into a `void`-returning wrapper
that the AG resource type never gets a wall-clock unlock deadline for
(unlike INODE/ICLUSTER, fixed in sess6). Also flagged apparent BAST-send
starvation (no ag=3 multicast for 20+ minutes despite a live retrying
waiter).
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`
**refuted the starvation with tcpdump**: sends and receives were both
healthy; the earlier "silence" was a false read of a shared-callsite
`pr_warn_ratelimited` starved by unrelated traffic on other AGs.
**Lesson: never infer BAST absence from a ratelimited print going quiet —
capture the wire.** The real reason the strand never self-heals: readopt
strand-repair can only reclaim a node's *own* bit, and this bit's owner is
dead, so recovery depends entirely on lease purge, which the torn-replay
refusal blocks — permanence is (silent-strand birth) + (dead owner) +
(replay freeze blocking purge), not a BAST-path defect.
`docs/rulings/488-tristate-unlock-verify.md`: GPT ruling
for the birth fix — tri-state unlock outcome (RELEASED / STILL_HELD /
UNKNOWN, not errno), with an authoritative read-back verify before trusting
STILL_HELD, re-minting a genuinely fresh epoch (never restoring the
surrendered one) on proven STILL_HELD, quarantining on UNKNOWN, adding a
wall-clock deadline to AG unlocks (removing the INODE/ICLUSTER-only type
gate), an RX stuck-latch watchdog, acquire-side own-bit reconciliation, and
— architecturally — that fence-confirmed dead-holder purge must be
decoupled from torn-replay progress (a node can legitimately die holding a
bit; unfenced override never ships).

## Tri-state unlock landed; new panic; both resolved (sess274-276)
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` landed the
enum + `caw_unlock_gen_body` classification of every exit path + AG
wall-clock deadline + `mxfs_v5_dlm_ag_unlock` returning the real outcome
(0.11.496), not yet wired into the worker.
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` wired the
worker state machine (RELEASED normal; UNKNOWN→bounded re-verify;
STILL_HELD→re-mint+re-arm; still-UNKNOWN→quarantine), the RX stuck-latch
watchdog (fired for real in verification, requeued correctly), and loud
non-RELEASED logging (0.11.497). `ag_strand_repair` went 32/32 clean —
injected silent-strand recovery now works. But this run also hit a NEW
crash: a kernel panic in `iput` from `mxfs_defer_agwait`'s `ihold`/`xfs_irele`
pair when the joined inode was mid-`evict` (I_FREEING, i_count==0) —
`ihold` from 0 is a VFS violation and the paired `xfs_irele` re-enters
`iput_final` inside `evict` itself. Root: the handoff's ihold/irele was
never necessary — the ILOCK-holding caller's own frame already spans the
joined inode's lifetime (evict itself, in the inactivation path).
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md`: fix
(delete the ihold/irele pair) verified — 3× rsync_paired + 3× scaling_curve
+ board chunk through zero_silent_loss all PASS, dozens of SEAM/PREACQ
handoffs fired fleet-wide with zero WARN/BUG (0.11.498).
`docs/rulings/fence-withdraw-refusal-terminal.md` is the
GPT ruling for a *separate* incident captured live in the same session: a
30s `dlm_fairness` budget under heavy dir-lock contention produced a mass
false-death fence (D-482) whose victim never withdrew — it stayed mounted,
spun `P15-REL-ABORT` at ~1ms cadence, and flooded the fleet with BASTs
because its on-disk PR key was gone but nothing checked. Combined with the
#1 foreign-replay refusal (a torn, untagged slice → refusal → purge blocked
→ writeback frozen fleet-wide), this is the "no forward path after refusal"
scenario #1 was theoretical about. Ruling: (A) fenced-but-alive victim must
self-withdraw, checked via PERSISTENT RESERVE IN/READ FULL STATUS (not READ
KEYS — ambiguous under key reuse), and withdraw must be hard (block all
writes, no clean bit, no final flush) since a racing survivor is only safe
if stale DLM messages are epoch-rejected; (B) BAST re-arm needs coalescing
to one outstanding notification per holder/epoch plus exponential backoff
on repeated aborts with unchanged holder generation; (C) refusal converts to
an explicit TERMINAL recovery state (no partial "unaffected" writeback —
isolation boundary is unprovable) rather than a silent forever-hang; (D)
D-482's HB-writer stall itself still needs 7-point timestamping
(thread/bio/blk-mq/mpath/SCSI/SCST/initiator) to discriminate wedge vs
starvation vs fabric vs target — unbuilt as of this ruling.

## Face 6 and the preacq-exhaustion regression (sess282/283)
`docs/rulings/preacq-exhaustion-shape-b.md`: the
sess269 preacq exhaustion cap (bounded retries → -ETIMEDOUT) itself became a
defect under a 32-way same-dir rename storm — spurious ETIMEDOUT on live,
healthy nodes. GPT ruling picked shape B: keep the inner 8-handoff budget as
a telemetry/batching boundary only, but make the *outer* operation retry
unbounded with capped randomized backoff on exhaustion — contention -EAGAIN
must never escape as -ETIMEDOUT, and no safety-valve error either (same
defect, rarer). Rejected: a BAST-deferral pregrant window (shape C) —
semantically an AG hold across ILOCK reacquisition, recreating the exact
forbidden AG-then-ILOCK ordering inversion the face-1/3/4 fixes exist to
prevent.
`docs/history/docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` root-caused
the `dlm_fairness` NO_TERMINAL_RECORD failure as a sixth face of the same
family, one layer up: `mxfs_trans_agwait_handoff`'s *relock* loop
(post-handoff, after the AG grant is back) uses a plain blocking
`xfs_ilock` per inode — so it holds inode[i-1]'s rwsem across inode[i]'s
unbounded cross-node DLM wait (480s here), violating the sess16 FIX-L3
invariant (cross-node DLM waits only with zero rwsems held). One node's
poisoned drain (ag=6, held by an inode blocked exactly this way) starves
~30 other nodes into D-state sync, and the run only ever terminates via the
480s disk-lock liveness cap. Fix shape: split the relock into a
grants-only phase (ascending-ino, no rwsems) and a nowait rwsem phase, same
pattern as `xfs_lock_inodes`.

## Recurring invariant and technique lessons across all six faces
- The one rule every face restates: an AG-DLM grant may never be requested
  while holding ILOCK, an inode rwsem, or a dirty transaction — any resource
  an AG drain can require. Every "new face" found sess260-283 was another
  call site that still violated it (allocator, EFI-finish, truncate,
  rename/remove preacquire, dialloc, and finally the preacquire *relock*
  loop itself).
- `P12-AGBAST-RX holders=0 cached=1 sched=1` with climbing `page_ms` means
  "scheduled but stuck," not "released" — the absence of a completion print
  after `P12-WORK ... COMMIT` is *normal success*, not evidence of a wedged
  worker (misread in sess266, corrected sess271).
- Never infer a BAST-path failure (starvation, missing send/receive) from a
  ratelimited print going quiet — one callsite is shared across all AGs and
  gets starved by unrelated traffic. Capture the wire (tcpdump on the CAW
  multicast port) before concluding the transport is broken.
- `ag_strand_repair` and readopt-based repair can only reclaim a node's own
  bit; a dead node's stranded bit requires fence-confirmed purge, which must
  be architecturally decoupled from foreign-replay/torn-slice progress or a
  single refused replay freezes recovery fleet-wide forever.
- Diagnostic toolkit that worked repeatedly: `caw_slotdump`/
  `caw_slot_dump.py` for on-disk lock-word ground truth, `/proc/<pid>/stack`
  sweeps for live blocked-thread evidence (never `pgrep -f`/`ps aux` — RULE
  2c mmap_lock wedge risk), tcpdump on the CAW multicast port for wire
  truth, and treating a `run.sh` "sync-wedged" precheck hit as a live
  specimen to inspect *before* re-prepping the cluster.
