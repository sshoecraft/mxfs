---
name: design-a-fence-certificate-needs-admission-and-retirement-and-they-are-separate-facts
description: DESIGN (Astra s75 ruling): a fence certificate must establish ADMISSION (victim can't get permission to write) AND RETIREMENT (writes the target alre…
metadata:
  type: project
tags: [fencing, scsi-pr, design-ruling, integrity]
---

# A fence certificate rests on two facts, and MXFS witnesses only one

Design-consult ruling, session 75, banked in full at
`docs/rulings/fence-ambiguous-drain-and-proof-resume.md`.

**ADMISSION** — the dead incarnation cannot obtain permission for a new write.
A Write Exclusive reservation held by our key gives this, and so does the
victim's registration being gone.

**RETIREMENT** — the writes the target has *already accepted* from that
incarnation can no longer take effect.

They are separate, and a certificate authorises foreign-slice replay, so a
command accepted from the old nexus that executes after the certificate lands
*under* the replay: an unordered logical write into metadata the replay is
rewriting. Every fence kind in this tree proves admission. None witnesses
retirement.

## The specific traps

- **The sole-survivor exclusive-write gate does not supply retirement.** Its
  PREEMPT AND ABORT carries `sark=0`, so it aborts the task sets of *the
  registrants it removes*. A victim whose registration an earlier command
  already removed is not among them. Confirmed in SCST's source:
  `scst_pr_abort_reg` aborts through `scst_rx_mgmt_fn_lun(sess,
  SCST_PR_ABORT_ALL, ...)` for that registrant's own session and LUN, and
  `__scst_abort_task_set` walks only that session's list filtered by
  `tgt_dev` — one I_T_L nexus.
- **Key absence is not a drain certificate.** A key goes away by a PREEMPT AND
  ABORT, by a voluntary REGISTER-with-zero (which retires nothing), or by
  nexus-loss cleanup. READ KEYS cannot tell them apart, and the middle case
  alone defeats the general implication.
- **A reservation re-check when a queued task executes is not portable.**
  Nothing guarantees a re-check before backend submission or media
  modification. There is no universal "BIO boundary" in SPC or SAM. The very
  existence of the PREEMPT / PREEMPT AND ABORT distinction is the argument.
- **A host reboot is not by itself an observed drain.** It ends the
  incarnation; it does not witness that the target finished retiring the old
  nexus's commands. Full iSCSI *session reinstatement* terminates the old
  session's tasks, but connection recovery/reinstatement and task reassignment
  *preserve* them, and a new session with a different ISID need not replace the
  old one at all. No successful login is a barrier by assumption.
- **The PR generation is not a retirement witness either**, and neither is the
  successor's own registration appearing.

## What does supply it

Only a target-enforced drain with the right scope, or a qualified target
contract. LOGICAL UNIT RESET has the scope — SCST's `scst_process_reset` walks
`dev->dev_tgt_dev_list`, every nexus bound to the device, with no reference to
the registrant list — and an ordinary conforming LU reset preserves persistent
reservations. Its cost is that it also aborts the survivor's own metadata
writes, it needs a quiesce that must not wait on the already-blocked journal,
and there is no supported in-kernel TMF API.

A succession proof, if one is used instead, must show four things: actual
incarnation succession linked to *that* victim incarnation (two differing boot
ids carry no ordering); complete nexus coverage; a completed target-side
retirement boundary; and publication of the durable successor witness *after*
that boundary.
