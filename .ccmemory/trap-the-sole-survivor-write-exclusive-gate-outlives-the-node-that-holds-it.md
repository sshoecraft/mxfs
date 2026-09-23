---
name: trap-the-sole-survivor-write-exclusive-gate-outlives-the-node-that-holds-it
description: TRAP (sess613/614, D-FOREIGN-SLICE-INTENTS-ABANDONED custodian-kill): the kind-20 gate is a per-LUN WE(1) reservation; when its holder dies a joiner…
metadata:
  type: feedback
tags: [fencing, scsipr, gate, takeover, tcp, 2node, trap]
---

# The sole-survivor exclusive-write gate outlives the node that holds it

## What was measured (s613c, tests/evidence/20260913T033243Z_intents2tcp_s613c)
Two-node TCP. V died with an open EFI; W became the sole survivor, installed the
gate (PROUT PREEMPT AND ABORT rk=own sark=0 type=WE(1); certificate kind 20 on
V's slot), replayed, published the OPEN obligation case, and was virsh-destroyed
inside the completion engine.

- V remounted 23 s after W's death: `P304-PREOBSERVE held=1 type=0x1 (WE)
  holder_key=<dead W>`; REGISTER succeeded (2 keys) but the PR-ledger publish is
  a WRITE and WE(1) admits only the holder → `P-PRKEY-PUBLISHED rc=-52
  UNATTRIBUTED` → "TCP SCSI PR register failed — aborting mount" in 2.7 s.
  The QNAP target purged W's key and reservation ~20 s later (W's remount saw
  held=0) — the failure is a race against the target's nexus purge, and on a
  target that keeps registrations (SCST) it is permanent.
- W remounted 43 s after its own death: fenced its predecessor (slot 0,
  BOOT_SUCCESSION_ABSENT — no gate), replayed and published slot 0, then took
  over slot 1's descriptor (certificate kind 20 written by old W).  The kind-20
  exclusion recheck asks "is WE(1) held by OUR key?" → NO_RESERVATION →
  `P239-GATE-LAPSED` / `P239-EXCL-LAPSED` once a second for 70 s until the
  mount barrier budget (122 s) expired; the mount failed EBUSY.  The gate is
  only ever installed on the fence path (`P238-FENCE-GATE-TRY`), which a
  taken-over, already-certified descriptor never revisits.

Net: a two-node cluster in which the survivor dies within the recovery window
of the first death can never mount again without operator action.

## The rules
1. A per-LUN reservation is not a per-recovery fact.  Any certificate whose
   exclusion IS a reservation held by a specific key (kind 20) becomes
   unprovable the moment that key's holder dies; a successor must re-prove
   the exclusion under its own key (same sole-live predicate, victim key still
   absent, pinned then dependency-registered) or stay lapsed.
2. Under a single-holder WE(1) a joiner can REGISTER but cannot WRITE.  Every
   "refuse at publish" path that writes to the LUN before membership exists
   must first decide whether the holder is dead — read-only, from the
   heartbeat table over a full dead window (the bootstrap survivor scan) plus
   the PR ledger's key attribution — and then PREEMPT AND ABORT the holder's
   key with the all-registrants type (NOT type 1, which the PAL accepts only
   for the gate's own sark=0 form) so the resulting reservation is WE-AR.
3. On the TCP transport there is NO whole-cluster bootstrap term
   (`P-BOOT-TCP-NOT-GATED`): a total outage is recovered slot by slot by the
   ordinary mount path of whoever mounts first.  Do not assume the CAW
   bootstrap's fence-everything phase runs here.
4. `docs/pr-fencing-departure.md` had ledgered exactly this hole in 0.72.0
   ("the mount-time path has NO gate arm yet") and it sat there through 13
   minor versions.  A "hazards ledgered (not closed by this)" list in a design
   doc is a defect queue entry that nobody's tool sees; file it in the queue.

## Fix shape (0.85.1)
`v5_gate_reprove` in the kind-20 arm of `v5_exclusion_recheck` (dlm/v5_mount.c)
and `v5_tcp_dead_gate_holder` + `mxfs_scsipr_preempt_dead_gate_holder` in the
TCP mount's PR step.  Probe tags: P239-GATE-REPROVE-*, P-PR-DEADGATE-*.
