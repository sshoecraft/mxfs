---
name: trap-a-per-slot-marker-keyed-on-a-per-case-sequence-aliases-the-slots-next-victim
description: TRAP (sess612/613, D-FOREIGN-SLICE-INTENTS-ABANDONED): "already retired for pub_seq N" matched the NEXT victim in the same slot (seq restarts at 1 pe…
metadata:
  type: feedback
tags: [D-FOREIGN-SLICE-INTENTS-ABANDONED, recovery, tcp, trap, slot-reuse]
---

# A per-slot marker keyed on a per-case sequence aliases the slot's next occupant

## What happened
The 0.85.0 OPEN-obligation branch kept `obl_retired_seq[slot]` = the pub_seq for which
the dead node's grants had been retired, so the engine's retries did not repeat the
remaster/ledger-purge/handoff trio (~2.4 s).  The obligation list's `seq` counts from 1
**per recovery case**.  Lap s612b (victim in slot 1, seq 1) primed the marker on the
survivor's mount; lap s612c's victim reoccupied slot 1, published seq 1 again, the
marker matched, the retirement was skipped, and the dead node's AG 1 EX stayed in the
TCP master table.  The custodian's first acquire queued behind a dead holder for the
whole 61 s budget, four times (`P1-AGCONFLICT holder=<dead> hstate=2`,
`P-LKTIMEOUT-HOLDER held_ms` climbing to 452 s, `P-OBL-ENGINE-EXTENT-FAIL rc=-110`),
while ordinary mkdirs parked "until a verdict".  The proof was the timeline: lap b had
`P-OBLF-INSTALL` → `P-TAUTH-PURGE` → `P-COMPLETE-RETIRE-TIMING why=obligations-open` →
`P-OBL-OPEN` 2.4 s apart; lap c had INSTALL → OPEN 26 µs apart with neither.

## The rule
Any per-slot state that says "already done for this case" must be keyed on the victim
INCARNATION (epoch) as well as the case's own counter, and cleared when the case
publishes.  A heartbeat slot is reused by the next node that claims it, and every
per-case counter (pub_seq, recovery_gen-relative seqs) restarts.  The oblf freeze table
already keyed on (epoch, seq); the retirement marker did not.

## How it hid
A single lap on a fresh mount can never show it: the first case in a slot always
retires.  It appears only on the SECOND death into the same slot on the same surviving
mount — exactly what consecutive harness laps without a re-prep produce.  Consecutive
laps on one mount are therefore also the cheapest reproducer for any per-slot aliasing.
