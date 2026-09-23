---
name: trap-a-cause-reproduced-outside-its-timing-window-lands-in-the-second-defence-and-reads-as-unreachable
description: TRAP (sess582, D-0945): the control reproduced the ungated release 2.65 s after the shutdown; the fence sealed at 2.4 s, so the master's sealed-owner…
metadata:
  type: feedback
tags: [trap, d0945, poison-gate, control, timing]
---

# A cause reproduced outside its timing window is answered by the next line of defence

**What happened (sess582, D-0945 positive control, 2-node TCP).** The control
disabled the victim-side poison gate and primed a deferred-free inode so the
reclaim after the shutdown would release its grant while poisoned. It did:
the choke point named the caller. But the survivor's replay was clean and
its manifest held the grant anyway — the release had reached the master
0.2 s AFTER the fence sealed, and `mxfs_dlm_process_remote_release` refuses a
release from a sealed owner (`P-TAUTH-SEALED-RELEASE-REFUSED`). Read naively,
"gate off, no harm" says the gate is unnecessary.

**The window.** A withdrawal is explicit, so the survivor fences at once: the
seal lands ~2.4 s after the victim's log shutdown on this rig. The periodic
reclaim came at 2.65 s. In the natural laps it came at 1.2 s, inside the
window, and the master accepted it — that is the defect. Forcing the reclaim
(`echo 2 > /proc/sys/vm/drop_caches` immediately after the trigger) put the
release inside the window: sealed-owner refusals 0, and the manifest sealed
with 3 entries instead of 4.

**The lesson.** When a defect has more than one line of defence, a control
that reproduces the CAUSE at the wrong TIME is caught by the next line and
reads as "unreachable" or "already covered". Before scoring a control:

1. Measure the window the primary defence exists to close (here: poison to
   seal). Timestamps on both nodes, not one.
2. Put the actor inside it deliberately (force the reclaim, do not wait for a
   30 s worker) and prove it landed there with a second-line counter of zero
   (`sealed_owner_refusals=0`) plus a direct effect (manifest entry count).
3. Report which line answered, per arm. A pass with the second line answering
   proves nothing about the first.

Evidence: tests/evidence/20260911T193709Z_d0945ctl_s582a (periodic reclaim,
seal first), tests/evidence/20260911T194213Z_d0945ctl_s582b (forced reclaim,
entries 4 vs 3).
