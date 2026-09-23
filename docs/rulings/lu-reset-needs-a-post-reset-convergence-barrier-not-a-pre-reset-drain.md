# The LU-reset barrier is a POST-reset convergence barrier, not a pre-reset drain and not a completion filter

Design consult, 0.89.31, on the fourth step of the witnessed LOGICAL UNIT RESET
route. What the issuing node must do about its OWN in-flight I/O across a reset
it issues itself.

## What was brought to the consult

- The witnessed reset exists and is measured: nonce-bound report, WITNESSED only
  when the command boundary was crossed, the ioctl returned 0 and the transport
  incarnation was unchanged; whole upcall 79 ms.
- The sole-initiator admission gate exists and is measured: target-enforced
  (reservation type excludes non-registrant writes, a COMPLETE registration
  table holding exactly one descriptor carrying our key, a matching-type RESERVE
  completing GOOD as proof the descriptor is on OUR nexus rather than a re-use
  of our key value, and the census bracketed with an unchanged PR generation).
- An LU reset strands only the tasks the target held at that instant; the
  stranded command is rescued by the initiator's own error handler. Worst
  measured stall 538 s (three expiries of the 180 s device command timeout plus
  the abort), zero application errors, no data lost.
- Read from the code: XFS buffer and iclog ownership mean no sector whose write
  is outstanding is rewritten until that write completes, and the cluster's own
  non-XFS writes (heartbeat records, recovery descriptors) go through a
  synchronous single-outstanding primitive. So a retried pre-reset write cannot
  carry stale bytes for a sector that has since been rewritten.

## The ruling

**A stale-overwrite ordering barrier is not the content of this step.** The
same-sector part of the invariant is already held by write ownership. What is
NOT yet proved is the cross-sector part: "one outstanding write per sector" does
not show that a commit record on sector B cannot become visible while an older
prerequisite write to sector A is still unresolved, and a synchronous thread
preserves only its OWN A-then-B order, not order against another thread or
against a separate recovery state machine. That inventory is owed: buffered
writeback, direct I/O, mmap writeback, unwritten-extent conversion, COW, raw
block users, DISCARD/WRITE ZEROES (whose retry is not "write the same bytes
again"), split requests, and multipath retry on a different nexus.

**Rejected: a device-level generation counter that refuses completions
belonging to pre-reset submissions.** A pre-reset command may have COMPLETED
SUCCESSFULLY after an EH retry; discarding that completion does not produce a
safe filesystem retry, it produces an I/O error and a shutdown. Generation
membership describes submission time, not whether the command executed before or
after the reset, and the SCSI layer owns timeout, abort, retry and completion
resolution. Generation tracking is an observation and gating mechanism only.

**Rejected: manufacturing apparent liveness across the reset.** The real hazard
is that the reset can strand the issuing node's OWN heartbeat write, block that
thread in the synchronous primitive for far longer than the 30 s authority
lease, and leave the node continuing a recovery whose authority has silently
disappeared. Neither fix by assertion works:

- *Pre-extending the lease* turns a local storage stall, plus a possible death
  of the issuer, into a long interval in which every other node must still treat
  an unreachable node as authoritative. A private extension is not enough; it
  would have to be protocol-visible, durable before the reset, strictly bounded,
  folded into every fencing and takeover calculation, and safe if the issuer
  dies immediately after creating it.
- *Tolerating one stalled heartbeat locally* splits the view: the issuer
  believes its lease is live while peers see an expired heartbeat and may take
  over. Sound only if the tolerance is part of the shared protocol with the same
  reset epoch and deadline on every node — at which point it IS an explicit
  extension.

Do not size either from the observed 538 s. That number is not a maximum: EH can
also take transport recovery, path loss, repeated reconnects and target
unavailability.

## The shape to build

1. Persist the reset intent with its nonce and epoch, on the same "the command
   may have been submitted" boundary the key preempt already uses.
2. Close a local submission generation for recovery-sensitive and
   cluster-control I/O — WITHOUT waiting for existing I/O to drain. The gate must
   not be able to block the reset itself, an abort, an EH retry, transport
   recovery, or the final completion of the old generation; a broad block-layer
   freeze is the wrong instrument.
3. Issue and witness the reset.
4. Let SCSI EH resolve the pre-reset commands normally. Record their final
   completions; never reject one because of its generation.
5. Hold off replay and every recovery-commit write until the old generation has
   CONVERGED.
6. Consume the expected reset UNIT ATTENTIONs in a bounded loop, on every nexus
   that may later carry recovery I/O, and treat an unrelated UA as a new state
   change rather than reset fallout. The first post-reset command must be a
   controlled probe — never the heartbeat renewal, a replay write or the
   recovery commit. A successful TUR or PR IN proves the command path, not
   writable media semantics.
7. Re-check the transport incarnation and the whole PR admission assertion set:
   reservation type and scope, the registration census, own-key proof rather
   than key-value equality, and an unchanged or explainable PR generation. A
   reservation that survived the reset can still disappear afterwards if EH
   reconnects the session and the target purges registrations with it — which
   this target does. Fail closed on any discrepancy.
8. Renew or reacquire authority. If the lease expired, STOP: write no more
   replay or recovery-commit bytes, and leave the durable intent resumable by a
   later authority holder rather than pretending the lease survived.
9. Only then continue replay and commit.

Availability is lower this way. Simultaneous authority is what it buys against.

## The architectural alternative worth recording

Put the authority heartbeat on a control device or failure domain that an LU
reset of the DATA logical unit cannot touch. That separates "resetting the data
LU" from "proving the coordinator is still alive", and it removes this whole
class rather than bounding it.

## Crash points the verification owes

After the durable intent and before the reset; while the ioctl is active; after
the reset succeeded but before the witness is persisted; during UA clearing;
while pre-reset local I/O is still unresolved; after the lease expired; after
authority was reacquired but before the PR re-validation; and after replay began
but before the recovery commit. Another node must be able to tell "the reset may
have been submitted" from "the reset was witnessed" from "local convergence was
never established" from "recovery committed", without trusting any volatile
state on the issuer.
