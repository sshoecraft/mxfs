---
name: trap-the-peer-death-detection-latency-is-our-own-socket-constant-not-tcp-behaviour-and-it-spends-the-whole-fencing-window
description: TRAP (s100): the survivor's 25.3 s to notice a power-cut peer is MXFS's own icsk_user_timeout=25000, set for an unrelated reason, and it burns 25 of…
metadata:
  type: feedback
tags: [fencing, tcp, timing, scsi-pr]
---

# A constant set for one reason silently became the budget for another

Chasing why the survivor's SCSI-PR fence always arrives after the target has
purged the dead node's registration, the timeline measured on the 2/tcp rig
after a `virsh destroy`:

| event | after the kill |
|---|---|
| survivor observes the TCP peer disconnect | **25.28 s** |
| target purges the victim's PR registration | ~32 s and ~34 s (two runs, 15 days apart) |
| MXFS declares death and attempts the first fence | **63.24 s** |

The fence is 30 s late, every time, so the already-implemented proved-exclusion
path can never fire — it requires the victim key to be PRESENT at the
classifying read.

The 25.28 s is not TCP being TCP. It is
`inet_csk(sk)->icsk_user_timeout = 25000` in `pal/linux/kern.c`, set on the DLM
socket, and its own comment says why: "Must be under the DLM lock wait timeout
(30s) so TCP aborts the connection before the DLM gives up." That is a
correctness constraint about waking DLM waiters. Nothing about a SCSI-PR purge
window was in view when it was chosen, and it now consumes 25 of the ~32 s that
window is worth.

## The lesson

A timing constant chosen against one deadline becomes an implicit budget for
every later mechanism downstream of it. When a subsystem seems to be "just
slow", check whether the latency is a constant *we* set before theorising about
the protocol or the hardware — and grep for the constant by value as well as by
name, because the measurement matched it to two decimal places.

## How the timeline was anchored

`dmesg` monotonic stamps cannot be compared with a harness's wall clock. MXFS
log lines carry a `realns=` field (realtime nanoseconds); fitting those against
the monotonic stamps over 427 lines gave an offset with **zero spread**, which
converts any monotonic stamp to UTC exactly. Anchor the kill with the mtime of
the file the harness wrote at that moment (`virsh_destroy.txt`). Any single
`realns=` line would have done; using all 427 is what proves there is no drift
to argue about.
