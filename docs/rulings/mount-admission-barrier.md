<!-- sess189 RULE-5 ruling: mount barrier = ADMISSION barrier. Shape A (top-of-round mphase drain) + B (pending-descriptor fold) + gate-until-complete; pe… -->
# sess189 GPT ruling — mount recovery barrier is an ADMISSION barrier

Defect: D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE remount arm.

## Measured root (sess189, from sess188 run log)
- Remount: P274 skip keeps WITHDRAWN slot 0; monitor consumes it during DLM
  init (WITHDRAW-SEEN 1102.427 → fence cert overwrites the hb sector →
  P233-MPHASE-DEATH 1102.499 records mphase_dead_mask=0x1).
- Step-6.5 withdrawn scan (~1102.50) finds nothing — sector no longer WITHDRAWN.
- Barrier loop is `for (round=0; todo && round<4)` with todo=cohort=0 →
  loop never runs → take_late_deaths NEVER CALLED despite the record being
  34ms old. Replay went async (settle dispatch) after mount live → stale
  in-core root hides replayed marker.

## Ruling (gpt-5.6-sol)
Shape A alone insufficient. Required:
1. **A**: drain mphase_dead_mask at TOP of round 0 and every round; zero
   cohort must not bypass the drain. (sess62 6B already implies this.)
2. **B**: sweep durable recovery-pending descriptors, fold unowned pending
   slices into the barrier rounds (recovery_acquire + inline replay).
   -EBUSY (owned elsewhere) is EXPECTED, not alert-worthy.
3. **Admission gate**: ownership/progress != completion. If ANY applicable
   pending descriptor remains (any pending slice whose journal could touch
   shared metadata = all of them, incl. root inode), the mount must stay
   admission-blocked: wait/poll bounded for the owner to complete (then
   invalidate cached views again before opening), else FAIL the mount.
   The 4-round cap bounds inline replay discovery, NOT permission to go
   live with leftovers.
4. **T1-T2 protocol fix**: fence pipeline must durably publish
   recovery-pending BEFORE replacing the WITHDRAWN stamp (or make the cert
   discoverable as requiring-recovery); final admission check must be a
   stable cut serialized with pending producers.
5. Accounting: take() = atomic transfer (settle must not double-dispatch);
   EBUSY attempt must not suppress later completion checks; separate
   attempted from replay-complete; publish-failure keeps descriptor pending
   and keeps admission closed; slot accounting should carry incarnation.

Invariant for the code comment: "Before a mount may read shared metadata or
transition to LIVE it must establish a stable recovery cut and ensure every
applicable dirty/dead slice preceding the cut is replay-complete. Pending /
claimed / in-progress does not satisfy this."

## Implementation notes
- Gate loop after rounds: sweep (WITHDRAWN-flag OR pending) non-local
  slots minus published; try acquire+replay; poll; RULE-0 bounded; timeout
  → fail mount (same spirit as the (b2) residue gate).
- Verify/reorder producer: where does fire_dead write the cert vs mark
  pending durable? (disklock.c fire_dead pipeline).

## The bound is elapsed time, and the wait is cancellable (D-0980, Astra 2026-09-19)

The admission wait's bound is a deadline on the monotonic clock taken at the
start of the wait loop, never a count of the loop's own poll sleeps. What a
round does between two polls — per-slot sector reads, PR commands, the 6 s
abandonment observation inside every recovery or fence-attempt takeover, a
slice stability proof of up to 45 s, the replay, the ledger-page takeover
scan — counts against the bound like the sleeps do. Counting sleeps alone let
a 122-poll extension hold mount(2) in the kernel for as long as 122 rounds
took, and a joiner's mount outlived its 300 s `timeout` by more than a
minute.

- **Where the deadline is judged**: before a round starts (including the four
  inline rounds), before every slice inside a round, and after every poll
  sleep. These are the recovery-safe boundaries: no lease is being claimed
  and no slice is mid-replay. A deadline cannot preempt a slice already being
  replayed, so the guaranteed property is that no new work is started past
  the bound; the exit line (`P-BARRIER-CLOCK`) names the overrun, and an
  overrun larger than the last round is a defect.
- **Budget exhaustion is an availability refusal, -EBUSY**, exactly as
  before. Recovery progress already published stays published; what was not
  replayed stays frozen and durably pending on the platter for the next mount
  or a survivor. It is never permission to admit with incomplete recovery.
- **The ghost extension is a cap, granted once.** While the monitor still
  watches frozen foreign records it has not declared dead, the bound is the
  ordinary wait plus the dead window plus a fence-and-replay allowance
  (30 + 62 + 30 s). It is derived from the loop's start, once: a second ghost
  appearing mid-wait buys no fresh window, and the bound is deliberately kept
  after every death is declared, so the replay that becomes possible at the
  declaration has its allowance instead of expiring the mount at the moment
  it could proceed.
- **A takeover is not started when it cannot finish.** The barrier hands the
  acquire what remains of the bound; an arm that must pay the 6 s
  abandonment observation before it can take a descriptor over is refused up
  front (`P238-TAKEOVER-NOBUDGET`) when the interval plus its bounded
  continuation (the CAS, the new PREEMPT AND ABORT, its certification and
  seal — 2 s measured, 3 s budgeted) would not fit. Deadline arithmetic
  decides whether to attempt the proof; it never replaces the proof.
- **Cancellation.** The poll sleep is killable, so a fatal signal on the
  mount task (a `timeout` terminating it) ends it at once; the same boundaries
  that judge the deadline judge `fatal_signal_pending`, and the mount is
  refused with **-EINTR, never -EBUSY** — cancellation is not contention. The
  abandonment observation inside a takeover is likewise abandoned, never
  shortened and never certified, when a fatal signal is pending; a worker
  thread has no signals and pays it in full. An interruptible sleep that
  wakes early for any other reason re-sleeps until the full interval has
  elapsed.
- **What a cancelled or refused mount leaves behind** is what any failed
  mount leaves: un-replayed late deaths handed back to the mount-phase record,
  every unpublished slice frozen and pending on the platter, and any recovery
  lease it claimed naming an incarnation that ended with it, which a later
  owner takes over through the lease protocol after its own observation.
  Pre-cut recovery debt never becomes post-mount work on a successful
  admission.

Harness: `tests/d0980_barrier_killable.sh` (a SIGTERM into a barrier holding
on a frozen record; the control mount's overrun against its last round; the
retry after cancellation).

## A death after admission: the barrier runs again (0.90.6)

A clean cut says nothing about the next minute. A peer that is still
heartbeating when the barrier looks — or was power-cut a second earlier, so
its record has not yet stopped advancing as far as this node's monitor can
tell — leaves the cut clean, and the mount is admitted. Its death is then
declared during the rest of `xfs_mountfs` (the dead window is 31 × 2 s), fenced,
and only **recorded** in the mount-phase death record, because the
slice-replay hook is registered after `xfs_mountfs` returns. Nothing on this
node can replay that slice until then, so any grant the dead peer held stays
frozen, and the mount's first acquire of it can never complete. Measured on
the Ubuntu pair: the root inode's acquire burned three 120 s budgets and then
shut the filesystem down.

- **Who may give up.** Only a fallible boundary: the mount's root lookup
  (nothing dirty, no transaction, nothing published). When its acquire's
  budget ends while the mount-phase record holds a death, it stops retrying
  and fails with `-EAGAIN` (`P-MPHASE-ACQ-GIVEUP`; the AG acquire inside the
  untrusted iget, `P-MPHASE-AGLOCK-GIVEUP`, fails the lookup with `-EIO`). A
  caller that cannot be failed is not changed by this.
- **What the mount does then.** It runs the barrier again
  (`P-MPHASE-REBARRIER`): the late-death drain, the platter sweep, the replay
  rounds and the admission gate, exactly as the first pass would have handled
  a death that landed inside it. The re-run skips the step-6.5 cohort and its
  residue gate (the first pass resolved and judged them; confirming them again
  would pay the dead window twice for a verdict already made) and the own-slot
  reclaim (the first pass closed the adopt window; every bit of ours set since
  is a tracked grant of this incarnation). The cached-view invalidation around
  each replay is legal for the reason it is legal in the first pass: nothing on
  this mount is dirty, and the failed lookup released what it held.
- **Then the lookup is retried**, at most four re-runs. A re-run that cannot
  replay the slice refuses the mount the way the first pass would have; it
  never shuts the filesystem down, and it never admits over an unreplayed
  slice.

Harness: `tests/mount_postbarrier_peer_death_2n.sh` (a one-shot hold right
after admission, `mxfs.dbg_barrier_admit_hold_ms`; the peer holding the root
inode is destroyed during it).
