---
name: technique-audit-every-script-in-a-serial-queue-for-arm-without-disarm-before-launching-it
description: TECHNIQUE (s130): a static arm/disarm audit of 4 queued harnesses found the flagship fencing lap had no trap and no disarm at all, on 8 knobs.
metadata:
  type: feedback
tags: [rig, queue, injector, trap, harness-hygiene]
---

# Audit the whole queue for arm-without-disarm BEFORE launching it

Two sessions in a row found a harness that arms a kernel debug knob and leaves
it armed on some exit path. The first found them one at a time, after a lap had
already poisoned the next one's prep. The second found the worst case by
**auditing every script in the queue at once, statically, before launch** — and
the worst case was the harness nobody suspected.

## What the audit asks, per script

1. every write of the shape `> /sys/module/mxfs/parameters/...` — name and value;
2. every write that undoes it;
3. every `trap` line, with its signal list;
4. every `exit`, with its line number, so the exits that sit AFTER an arm and
   are not covered by the trap can be counted;
5. every backgrounded helper (`nohup`, `setsid`, trailing `&`, `sleep >= 60`) —
   whether a pid is recorded and whether anything kills it;
6. the bound the script's own header derives.

It is pure grep, so it delegates cleanly to a cheap agent; the parent only has
to read the exits-after-arm column.

## What it found

`tests/fence_crash_cuts.sh` — the fencing harness that had just run a six-cut
sweep and was queued to run two more laps — had **no trap at all and no
disarming write anywhere in the file**, across eight knobs in three families
(`dbg_fence_crash_hold_ms`/`_slot`/`_cut`, four `dbg_replay_cut_*`, and
`dl_inject_hb_pause_ms` at 150 s on the silent-victim arm). Six exits sit after
an arm.

**Why it had survived.** On the DESTROY arm the victim is killed anyway and the
reboot clears every knob, so the omission is invisible. The SILENT arm, added
later, leaves the victim RUNNING at the silence ABORT and at both VACUOUS
exits — and the cut-7 VACUOUS exit ("the module declined the cut") is reached
with the prover alive and its replay cut still armed. A lap that is only ever
run on the arm that reboots its nodes hides a missing trap indefinitely; adding
a second arm re-opens it silently.

Its two python helpers had no recorded pid and no `kill`. The churner's loop is
unbounded, so on those same paths it keeps writing to the mount the next lap
has to unmount.

## The rule

A harness's cleanup is only as good as its WORST arm, and the arm that reboots
its nodes proves nothing about the arm that does not. Audit at queue-build
time, list the exits that follow an arm, and treat any of them reached with the
target node still up as the defect it is.
