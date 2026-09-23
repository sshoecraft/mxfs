---
name: trap-an-idle-mounts-authority-lease-does-not-expire-until-something-calls-the-gate
description: SUPERSEDED (s126→s146): the PR worker's tick now asks the gate every 250 ms, so an IDLE lease closes at its deadline and the node withdraws itself; a…
metadata:
  type: feedback
tags: [trap, authority-lease, harness, measurement-integrity, superseded]
---

## What was true at s126

`mxfs_authority_ok` (`dlm/disklock.c`) is the only thing that turns an expired lease into `MXFS_AUTH_CLOSED`, "from whatever context noticed". At s126 no periodic context asked, so an idle mount kept reading ADMITTED past `deadline_ms` and `P290-AUTH-CLOSED` appeared only when the peer's own fence provoked one — collapsing any boundary measurement to zero. The lap answer then was a 2 Hz writer on the victim.

## What is true now (measured s146a/s146b, 0.89.66)

The PR worker's loop asks the gate every tick — "THE PERIODIC HALF OF THE LEASE ... this tick is what contains a node that is issuing no I/O at all" (`dlm/v5_mount.c`, just above `v5_authority_withdraw_pump`). With NO writer and a settled log, the victim closed at the deadline (`P290-AUTH-CLOSED reason=AUTHORITY_LEASE_EXPIRED`), withdrew, stamped WITHDRAWN, and the peer fired on the stamp 30.9 s after its last sight of a beat. So:

- an idle LIVE node closes on time by itself; the writer is unnecessary for that;
- but the closure withdraws, and the withdrawal hands the peer its stamp, so a live node ALWAYS takes the cooperative path — never the 62 s silent window;
- the silent shape (peer death from silence) needs the CONVERSION held, not the closure: `dbg_auth_withdraw_pause_ms` (0.89.66) keeps the lease evaluated and withholds only the withdrawal pump. `dbg_auth_pump_pause_ms` holds BOTH (the blind-victim knob) and then nothing closes at all.

Still true: `MXFS_AUTH_NOT_ADMITTED` returns **true** — a mount that has landed no beat yet admits writes, bounded by the mount. Constants: `MXFS_DISKLOCK_AUTH_LEASE_MS` 30000, `MXFS_DISKLOCK_HB_INTERVAL_MS` 2000, `MXFS_DISKLOCK_DEAD_THRESHOLD` 31.

Used by `tests/authority_handoff_phase.sh` (default arm = cooperative path, `SILENT=1` = the held-withdrawal shape); see also `trap-a-stimulus-that-provokes-the-victims-own-withdrawal-measures-the-cooperative-handoff-not-the-silent-window`.
