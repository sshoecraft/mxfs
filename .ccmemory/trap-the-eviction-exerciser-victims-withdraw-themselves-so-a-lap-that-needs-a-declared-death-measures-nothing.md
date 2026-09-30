---
name: trap-the-eviction-exerciser-victims-withdraw-themselves-so-a-lap-that-needs-a-declared-death-measures-nothing
description: TRAP (0.90.34): VICTIM_EVICT=1 victims shut down at +23 s (pinned log tail) and are recovered as withdrawn before the kill; no death, no fence race.
metadata:
  type: feedback
tags: [harness, multi-victim, vacuous-lap]
---

**What bit us.** `tests/multi_victim_containment.sh` with `VICTIM_EVICT=1` pins each victim's log
tail (`dbg_ail_pin_ino`). About 23 s after the cluster forms the victim cannot finish a no-inode
release (`P-NOINO-DRAIN-STUCK`) and shuts its own filesystem down. Survivors see
`P163-WITHDRAW-SEEN` and recover it at once. The power cut that follows kills a node that is
already recovered: `dead_lines=0`, no prover, no lease race, no refusal. Two laps written to
exercise a refused replay (queue r34c) measured nothing about it.

**Rule.** A lap that needs a node DECLARED DEAD (the 62 s silent window, a fence prover, a
replayer's lease request) runs the plain load on its victims. Use the exerciser only when the
subject is what is inside the victim's unreplayed log window.

**Check before reading a lap.** `withdraw_stamp=` on the victim's summary line and
`dead_lines=` on the survivors': a lap with withdraw_stamp=1 and dead_lines=0 had no death.

**Second trap in the same laps.** The harness derives the load's end from
`LOAD_S + VICTIM_GAP * NV + 30` but reads and unmounts at `last kill + LOAD_S + 25`. With a long
gap the load is still running at the unmount (six `umount rc=32` in 0 s on a healthy cluster), and
the load's error count is read before its last cycles run. The harness now stops the load, waits
for it, and judges the count at the end.
