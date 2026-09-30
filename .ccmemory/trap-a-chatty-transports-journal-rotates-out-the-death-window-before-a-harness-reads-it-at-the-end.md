---
name: trap-a-chatty-transports-journal-rotates-out-the-death-window-before-a-harness-reads-it-at-the-end
description: TRAP (0.90.25, 8/cawd): journal held only T0+267s..+364s (116K lines); death/fence/replay at +60-90s were gone, harness counted 0 recoveries.
metadata:
  type: feedback
tags: [harness, journal, capture, cawd, evidence]
---

# A chatty transport's journal rotates out the death window before a harness reads it at the end

**What happened (0.90.25, `tests/multi_victim_containment.sh 8 cawd test3,test6`).**
The lap printed `recoveries completed cluster-wide: 0 of 2 victims` and FAIL,
while every survivor's workload had stalled 73 s and then run on with zero
errors. The harness counted `P163-RECOVERY-COMPLETE` with
`journalctl -k --since @T0` at the END of a 340 s window.

Asked for its first line, test1's journal for that window answered
`T0+267 s`: 116,184 lines between +267 s and +364 s and nothing earlier. The
rig's prep caps the journal (`RuntimeMaxUse=400M`) and the debug probes on
cawd under load write about 1,200 lines a second, so the death, fence and
replay lines at +60..+90 s had been rotated out before anything read them.
On TCP the same harness kept the whole window (59,054 lines in 354 s).

**How to tell:** before trusting any count taken from a node's journal, print
the FIRST line's time for the window asked for. If it is later than the
window's start, every count is a count of the tail.

**What to do instead:** start a filtered follower on each node at T0
(`journalctl -kf | grep --line-buffered -E '<the lines the verdict needs>' >> file`)
and read that file; save each node's log into the evidence directory at
collection time. A count of zero from a rotated journal is a capture failure
and must be reported as one, never as "did not happen".
