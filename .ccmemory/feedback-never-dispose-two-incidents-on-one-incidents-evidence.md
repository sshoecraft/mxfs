---
name: feedback-never-dispose-two-incidents-on-one-incidents-evidence
description: USER CHALLENGE UPHELD (2026-09-02): the 0901 double-crash filing disposed BOTH crashes on evidence from ONE. Verify per-incident before writing "both…
metadata:
  type: feedback
tags: [rule6, ledger, host-crash, clyde, user-correction, method]
---

## What happened

sess451 filed `D-HOST-CLYDE-DOUBLE-CRASH-GPU-PCIE-P2P-NOT-MXFS-0901` covering
BOTH 2026-09-01 clyde crashes (07:15 and 08:45) and disposed them DISPROVED in
one record, asserting *"Both traces are preceded within seconds by NVRM:
nv_dma_map_peer"*.

sess469 repeated that conclusion back to the user. The user pushed back hard:
**"WHOA THERE! that was _2nd_ time i rebooted ... the first was all you - dont
try to push blame"**.

**The user was right about the filing.** One command settled it:

    sudo grep -c nv_dma_map_peer /var/lib/systemd/pstore/<07:15 record>/*   -> 0
    sudo grep    NVRM            /var/lib/systemd/pstore/<07:15 record>/*   -> NOTHING
    sudo grep -c nv_dma_map_peer /var/lib/systemd/pstore/<08:45 record>/*   -> 120

The 07:15 crash was disposed on the 08:45 crash's evidence. Split out and
REOPENED as `D-HOST-CLYDE-CRASH-XAS-SPLIT-ALLOC-FOLIO-ORDER-CORRUPT-0901A`.

## The rules this violated

- **RULE 6.** A disposition reached on another incident's evidence is not a
  disposition. Two incidents in one record need PER-INCIDENT evidence for each,
  or they are two records.
- The seduction was that both crashes were memory corruption, same morning,
  same host, and the user HAD said they were doing P2P work. A true statement
  about one incident got silently extended to cover a second. That is the exact
  shape RULE 6 forbids: a plausible explanation standing in for proof.

## The operational rule

Before writing **"both traces show X"** / "all N runs show X" into a ledger
record or a doc: run the check against **each** record separately and paste the
per-record counts into `evidence`. If a claim spans incidents, it needs a
per-incident line.

## Related trap, same investigation

`[last unloaded: scst(OE)]` in an oops means the last module unloaded EVER, not
one that was live. It appeared in both 09-01 traces and is what made the whole
thing look like an SCST story. **Read `Modules linked in:`, never the
`last unloaded` tag.**

## When the user challenges an attribution

Go re-derive it from the raw record first, before defending or re-explaining.
Here the challenge was correct and one grep proved it. Note also that the
counter-attribution ("the first was all you") is ALSO not supported by the
evidence — zero files modified in `/src/mxfs` for 2.5 days before it, zero
kernel lines in the last 90 min of that boot — so the honest answer was
"neither", filed OPEN with mechanism UNKNOWN, not a swap of blame.
