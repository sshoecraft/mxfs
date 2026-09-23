---
name: trap-staged-ssh-session-in-a-command-substitution-hangs-on-its-fifo-and-a-fixed-sleep-misses-the-login
description: TRAP (sess49, D-0532 harnesses): $(stage ...) with a backgrounded ssh reading a fifo blocks until the 40 s timeout; a fixed sleep before the trigger…
metadata:
  type: feedback
---

# Two harness traps from the D-0532 relog / pending-BAST arms (sess49)

## 1. A staged session launched inside `$(...)` hangs on its fifo
`ppid=$(stage node fifo out cmd)` where `stage` does `( timeout 40 ssh ... < fifo | grep > out ) & echo $!`
never returns until the 40 s timeout: the command substitution waits for every writer
of its stdout pipe, the background subshell inherits that pipe (its own commands are
redirected, the subshell fd is not), and the ssh inside blocks opening the fifo for
read because the parent has not yet run `exec 7>fifo`. Two staged sessions = 80 s = the
whole 100 s budget, with an empty evidence dir and "Terminated" as the only output.
Fix: never return the pid through command substitution; set a global (`STAGE_PID=$!`).

## 2. A fixed `sleep 1.5` before the trigger is not "the peer is ready"
`tests/d0532_relog_live_holder.sh` fed `go` into a fifo after 1.5 s; sshpass login
took longer, the trigger sat in the fifo, and the peer's write landed ~1.2 s after the
holder's rewrite — past the ~1 s quiet-age release of the holder's EX
(`P70-BP qsrc=5 held_ms=1002`), so the peer's request met no holder, no BAST reached
the drain, and the arm reported "drain never parked" on 4/4 laps. Fix: the remote
command prints READY before `read x`; the harness polls the capture file
(`grep --line-buffered`, block buffering otherwise hides READY) and aborts if it does
not appear in 10 s. A trigger that must land inside a ~1 s window needs a handshake,
not a sleep.

## 3. (same session) the print-budgeted line as a shape witness lies across runs
`P139-RECYCLE-UNLINKED` prints ~200 lines per module load. The first 200-lap run spent
the budget; the next 2000-lap run counted 0 lines and reported INCONCLUSIVE while the
exact counter `recycle_grant_cached` read 3755. Witness the shape with the exact
counter (reset before, read after), never with a budgeted line count.

## 4. The regular-file early-out hides a durable-loop injection
`mxfs_dlm_bast_process`'s regular-file early-out (`!IN_AIL && pincount==0`) is taken
on every regular file because the drain's own AIL flush lands the inode first; a knob
whose hook sits inside the durable loop (`dbg_bast_pause_ino`, `dbg_relog_force_ino`)
is then never reached. 0.87.10 makes the early-out fall through while the force knob is
armed. When an injected hook never fires, find the branch above it before doubting
the knob.
