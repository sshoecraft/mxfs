---
name: trap-a-test-delay-in-a-serial-service-thread-keeps-the-other-side-out-of-the-window-it-was-meant-to-widen
description: TRAP (0.90.32): a 300 ms race delay put in BOTH peer setups slept the one accept thread per peer; no inbound setup met any window, control lap found…
metadata:
  type: feedback
tags: [rig, harness, control-arm, dlm, peer]
---

## What happened

The control arm for the peer receive-thread leak (`dlm/peer.c`) held the window
between a connection's install and the creation of its receive thread open with
a test parameter (`peer_recv_start_delay_ms=300`), applied in `start_recv_thread`
for BOTH callers: the outbound connect path and the accept thread.

The control lap (queue m32c, 8/tcp) overwrote no handle and lost no thread, and
the harness still printed `PASS overlaps=2`.

## Why

- There is ONE accept thread per mount and it serves every peer in turn. A delay
  inside it makes it sleep 300 ms per accepted connection, so it answers nobody
  else's handshake meanwhile. Inbound setups queue in the listen backlog and
  arrive after every outbound window has closed.
- The harness counted an overlap as "a connection replaced within 50 ms of its
  handle's store". The accept thread waking from its own delay and accepting the
  next queued connection from the SAME peer satisfies that exactly
  (`by=accept age_ms=304 since_start_ms=0`), and is not the race.

## How to apply

- Put a race-widening delay only in the path whose window is being widened, never
  in a serial service thread the other side of the race has to pass through.
- Make the instrument line name BOTH parties (`by=` and `inst_by=`), so the
  harness can require a cross-direction event instead of inferring one from
  timing.
- Write the harness's "exercised" test from the prediction's own wording. The
  queue file said `thread_pid=0`; the harness tested something looser, and a
  vacuous lap printed PASS.
- A control lap that reproduces nothing is not evidence against the hypothesis
  until its own precondition line is read. Here the fix arm's
  `P-PEER-REPLACED by=connect-install state=0` named the real path: the outbound
  install over an inbound connection that had already ended, no timing window
  needed.
