---
name: trap-a-recovery-completion-that-lands-after-the-watch-window-reads-as-never-completes
description: TRAP (sess593/594, D-0962): a 60 s restore wait and a 96 s capture were both shorter than the ledger-page takeover inside recovery-complete (13 ms/pa…
metadata:
  type: feedback
---

## What happened
- tcp_death_replay.sh laps s593i and s594a FAILed `P163-RECOVERY-COMPLETE published`, `gate restored` and `WE-AR in force` (60 s wait after the verify). The s593i capture ran 96 s past the replay and showed nothing, so D-0962 was filed as a recovery that NEVER completes, with the late TCP-transport death event (`P-PR-FENCE-NOKEY` + `P-TCPDEATH-DEFERRED`, ~1.4-23 s after the heartbeat fence) named as the cause.
- Reading the survivor's LIVE dmesg after s594a: `P163-RECOVERY-COMPLETE` at +104.5 s after the replay, `P-COMPLETE-TIMING ... handoff_ms=103767`, preceded by 31979 `P-TAUTH-PREPARED/ACTIVATE/PAGE-MINE/TAKEOVER-RETIRE` lines (7984 pages, one quartet each). The two PASSING laps (s593g, s593h) had handoff_ms=107376 and 43373 and logged the SAME late TCP death event before their replays.

## The lessons
1. Before writing "never completes", read `P-COMPLETE-TIMING` (refresh/ledger/dlmpurge/handoff/disklock_purge ms) and count the takeover quartets; a completion that lands after the harness stopped watching is a PACE defect with a number, not a hang.
2. A probe that appears in the failing lap is only a cause if it is ABSENT from the passing laps — diff the passing laps' timelines first.
3. The ledger page count on a preserved filesystem is the residue of every earlier lap (32000-create join laps left ~8000 pages on test2's slot); the per-page cost (~13 ms: auth read, prepare, activate, purge, import, each a synchronous ledger I/O) is the defect, the count is the multiplier.
4. The victim's own dmesg dies with it and the survivor's ring buffer rolls within ~2 laps (P-TAUTH lines are ~32k per completion): pull the survivor's log to an evidence file BEFORE the next lap.
