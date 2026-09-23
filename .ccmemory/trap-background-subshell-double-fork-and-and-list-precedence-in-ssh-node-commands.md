---
name: trap-background-subshell-double-fork-and-and-list-precedence-in-ssh-node-commands
description: TRAP (sess487): in a non-interactive shell `( list ) &` double-forks ($! holds no fds, its child does) and `a && b && ( list ) &` backgrounds the WHO…
metadata:
  type: feedback
tags: [bash, harness, ssh, fifo, trap, sess487]
---

# Two bash facts that cost a rig lap each (sess487, chain 135)

## 1. `( list ) &` under a non-interactive shell forks twice
`$!` is a wrapper bash whose CHILD runs the list. An `exec {fd}<file` inside
the list opens the fd in the child, so `ls /proc/$!/fd` shows only 0,1,2
(measured on clyde: wrapper fds=3, child fds=403). In the Bash tool's own
shell the same construct showed the fds in `$!` — so a local test can pass
and the node command still read 3. `wait $!` still returns only after the
child exits (the wrapper waits for it), so a timing argument built on wait
survives; a COUNT built on `$!` does not. Sum `$!` and
`/proc/$!/task/$!/children`.

## 2. `a && b && ( list ) &` backgrounds a, b AND the list
`&` binds the whole AND-list. The setup (`rm -f flag fifo && mkfifo fifo`)
therefore ran in the background too, racing the foreground. On nodes NOT
rebooted between legs a stale flag file from the previous leg satisfied the
foreground wait instantly (READY_WAIT_DS=0); the foreground opened the STALE
fifo for writing; the background then unlinked it and made a new one; both
sides waited forever on different fifos; no umount ever ran; the harness
reported 4 "hung" nodes with no umount task. Write the setup as its own
statement (`...; mkfifo fifo || exit 1; ( list ) & HP=$!`).

## General
- Verify what a node command DID from the node (`/proc`, read-back), not
  from what it printed it intended; then make the harness ABORT the leg on
  the mismatch instead of merely reporting it.
- "Hung" with no task in the hang capture = the harness, not the kernel.
- Anything a leg leaves in /run or /tmp on a node survives into the next leg
  on nodes the prep did not reboot; use per-leg unique names or clean in the
  foreground before use.
