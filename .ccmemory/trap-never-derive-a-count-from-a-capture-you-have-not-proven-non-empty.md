---
name: trap-never-derive-a-count-from-a-capture-you-have-not-proven-non-empty
description: TRAP (sess580): an ssh helper that sends remote stderr to /dev/null turns a failed command into an EMPTY capture, which a grep -c then reports as a c…
metadata:
  type: feedback
tags: [harness, measurement, evidence, shell]
---

## The mechanism

A harness helper of this extremely common shape:

    rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

discards the REMOTE command's stderr. A caller writing `rs 60 node "cmd" > out.txt 2>&1` gets nothing useful from that `2>&1` — the error was already thrown away inside `rs`. If `cmd` fails outright, `out.txt` is **zero bytes**.

Then:

    desc_left=$(grep -ac 'desc v' out.txt)     # = 0
    ckge "a descriptor is still standing" "$desc_left" 1   # FAIL / VACUOUS

The verdict is now a statement about the system, derived from a file nothing was ever written to.

## What it cost

`tests/d0932_owner_depart_takeover.sh` s580f, 2026-09-11. The lap reached its intended state perfectly — the recovery owner claimed the recovery, ran the ladder 3→4→6 to GRANTS_RELEASED, parked in the purge, and was destroyed where it stood. Then it dumped the platter from the freshly booted judge node and exited VACUOUS with "a descriptor is still standing got=0 want>=1".

`hb_after_umount.txt` was 0 bytes. The dump tool lives on the NFS share, the judge had just booted, and `/src` was not mounted on it until a build check much later in the same script. `python3` could not open the script, the error went to `/dev/null`, and ~20 minutes of rig time produced no measurement while *reporting a result about MXFS*.

The tell was visible in the console: the stage that prints the platter printed **nothing at all**, where the comparable lap printed `slot 0 magic=MXLK flags=ACTIVE ...`. A dump that prints nothing is not a platter with nothing on it.

## The rule

**Never derive a count from a capture you have not proven non-empty, and never let a failed capture become a verdict.**

Three things, all cheap:

1. Put `2>&1` **inside** the remote command (`"cmd 2>&1"`), so a remote failure comes back as output instead of being eaten by the helper's own redirect.
2. Before counting, assert the capture contains the SHAPE you expect — not just non-empty, but `grep -q 'slot '` / whatever the tool always prints. An error message is non-empty too.
3. When it fails, exit **ABORT/INFRA, never FAIL or VACUOUS**. A zero from a broken instrument and a zero from a clean system are the same number and only one of them is a result.

Also check the helper's prerequisites hold at the point of use, not at the point the script eventually gets around to them: a node that has just booted has no NFS mounts, so nothing under `/src` is runnable on it yet.

## Related

Same family as reading a probe's silence as an answer, and it recurred twice more the same day: a locality probe whose drop knob not firing was taken to mean "locally mastered" (it had already made a lap measure the wrong path), and a holder-side notification count left unscoped by inode so it counted every resource's notifications. Whenever a branch of a decision rests on an ABSENCE, that branch is the one to distrust.
