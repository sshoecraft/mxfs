---
name: trap-banked-lap-evidence-stops-describing-the-build-when-an-intervening-change-withdraws-the-mechanism-the-lap-depended-on
description: TRAP (s86): the crash matrix's banked 12/12 PASS was measured on 0.89.10; 0.89.16 withdrew the retirement basis those laps recovered through, and cut…
metadata:
  type: feedback
tags: [evidence, regression, fencing, ledger]
---

# Banked passes expire when the mechanism under them is withdrawn

**What happened.** `D-FENCE-CRASH-MATRIX-UNTESTED` carried, as its measured
state, "the six prover cuts are measured on BOTH victim arms — 12/12 laps PASS
with every per-class PR prediction met". That sweep ran on 0.89.10. In 0.89.16
the deployment clause that supplied a RETIREMENT basis for an absent victim
registration was withdrawn in code, leaving a completed target operation as the
only accepted basis.

Every one of those laps recovered a node whose registration the appliance had
already purged. The withdrawal removed the only thing that let them do it. Re-run
on 0.89.19, **cut 1 — the simplest cut in the matrix — fails**: the successor
cannot certify the dead node (`P238-BOOTSUCC-NO-RETIRE-BASIS`,
`P238-GATE-NO-RETIRE-BASIS`, both `obs=no-mxfs-successor-observed`), and both
the peer's mount and the dead node's own next boot return 32.

**The trap is not "old evidence goes stale".** It is that the ledger entry read
as a *current* statement of measured state, in a record that was being worked
on daily, and nothing in it pointed at the version the measurement came from as
a dependency. The next step was planned from it. The version was written down —
"MEASURED STATE (0.89.10 ...)" — and that was not enough, because a version
string does not say *what the lap depended on*.

**What to do instead.** When a change WITHDRAWS or REVOKES a mechanism rather
than adding one, sweep the ledger for entries whose banked evidence ran through
that mechanism, and mark them as needing re-measurement in the same version that
withdrew it. The question to ask is not "is this record about the thing I
changed" — the crash-matrix record is about crash points, not about retirement
bases — but **"could any banked lap in this queue only have passed because the
withdrawn path existed?"**

**The second half, which cost more.** Because every cut in that matrix destroys
the prover, and a destroyed prover's registration is purged before anyone can
name it, the ENTIRE remaining matrix is now unrunnable on this rig until a
retirement route exists. A high-severity record's whole work queue turned out to
sit behind a record classified as not blocking the release. Check for that
dependency before planning a record's next step, not after building the lap.
