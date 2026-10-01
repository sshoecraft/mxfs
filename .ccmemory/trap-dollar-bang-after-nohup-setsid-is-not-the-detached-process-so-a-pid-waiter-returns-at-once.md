---
name: trap-dollar-bang-after-nohup-setsid-is-not-the-detached-process-so-a-pid-waiter-returns-at-once
description: TRAP (0.90.37): `nohup setsid cmd &` — setsid forks when its caller leads a process group, so $! exits at once; record $$ inside setsid bash -c.
metadata:
  type: feedback
tags: [rig, release-chain, shell, background]
---

## What happened

The release chain was launched `nohup setsid env ... tests/release_verify_chain.sh V > out 2>&1 &` and `$!` was saved as its pid. A background waiter `tail --pid=$PID -f /dev/null` returned within 5 s while the chain was still running: setsid, finding itself a process-group leader (job control gives every `&` job its own group), forks and the parent exits. `$!` is that parent.

## Do instead

    nohup setsid bash -c 'echo $$ > PIDFILE; exec env ... the_command' > out 2>&1 < /dev/null &

`$$` inside the new session is the process that `exec`s into the command, so PIDFILE names the long-running process. Check with `ps -o pid,etimes,cmd -p $(cat PIDFILE)`.

## Also

The release chain does not stop when a window lap fails: in this case all 8 window laps failed in ~1 s each (rig still wired to group targets) and it went straight on into full_verify. Watch the first lap's `rc=` line (`tail -f out | grep -m1 'rc=.*lap 1/'` in a background task) before leaving a chain to run.
