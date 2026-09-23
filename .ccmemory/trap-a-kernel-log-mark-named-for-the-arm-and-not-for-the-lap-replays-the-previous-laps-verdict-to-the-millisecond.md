---
name: trap-a-kernel-log-mark-named-for-the-arm-and-not-for-the-lap-replays-the-previous-laps-verdict-to-the-millisecond
description: TRAP (s101): a dmesg window opened at 'LURW-MARK-control' matched the PREVIOUS lap's marker, so a 14 s lap reported the earlier lap's nonce and 47261…
metadata:
  type: feedback
tags: [harness, dmesg, measurement-integrity]
---

# A log marker must be unique to the LAP, not just to the arm

`tests/lu_reset_witness_probe.sh` scoped each arm's kernel-log window with
`echo 'LURW-MARK-<arm>' > /dev/kmsg` and then
`dmesg | sed -n '/LURW-MARK-<arm>/,$p'`. `sed` opens the range at the FIRST
match, the nodes are not rebooted between laps, and the ring survives a
module reload — so the second lap's window opened on the FIRST lap's marker
and every verdict it read belonged to a run that had already finished.

It was caught only because the numbers were impossible: lap s101b finished in
14 s while reporting `upcall_ms=47261` and `nonce=28c2609b8dd89636` — lap
s101a's values, to the millisecond and to the digit. Had the fix under test
merely been slower rather than different, the stale window would have
reported a PASS for code that never ran.

This is the sibling of
`trap-a-kernel-log-window-taken-with-no-mark-dumps-the-whole-ring-and-counts-a-previous-sessions-event`:
there the window had NO mark; here it had one, and the mark was not unique.
A mark that names only what it is marking is not a mark.

Build the token once per lap from something monotonic —
`MARKID="LURW-$LABEL-$(date +%s%N)"` — and derive every arm's marker from it.
Then the first match IS the only match.
