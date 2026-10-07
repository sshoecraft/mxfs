---
name: technique-read-the-recovery-complete-lines-ms-walls-before-instrumenting-a-slow-recovery
description: TECHNIQUE: P163-RECOVERY-COMPLETE prints 'ms: total lease+milestones purge+flush grants (ledger tables handoff) zero' at WARN; read it first, no dynd…
metadata:
  type: reference
tags: [recovery, drbd, ledger, timing]
---

The survivor's `P163-RECOVERY-COMPLETE` line (dlm/v5_mount.c, the completion ladder) ends with step walls, printed at WARN, so they are in every host's `journalctl -k` with no dynamic debug:

`ms: total=24180 lease+milestones=712 purge+flush=24 grants=18121 (ledger=17835 tables=0 handoff=0) zero=5322`

- `grants` = v5_dead_grants_retire; inside it `ledger` = mxfs_dlm_ledger_purge_owner (the dead incarnation's ledger records, one durable page commit per page: 2 emulated CAS + 3 flushes + FUA write on DRBD), `tables` = the DLM table purge, `handoff` = the page takeover (deferred by default).
- `zero` = mxfs_disklock_purge_node (scans all 65536 lock records + CAS-zeroes the dead node's).
- A waiter on a resource the dead node held is served right after `grants`, before `zero`.

Measured 2026-10-06 on the physical DRBD pair (0.90.81, p1-crash): ledger 17.8 s of a 50.6 s takeover wait; the rig did the whole path in 12.6 s. The other pieces come from timestamps of DRBD's own kernel lines (PingAck missed -> 'Connection closed' -> 'helper command ... fence-peer' -> exit code) and P-DRBD-EXCL-DEATH / P236-FENCE-CERTIFIED / 'elected (slot N) to replay' / 'foreign replay of slot N complete'. The fence handler itself ran 0.12 s; DRBD took 6 s between NetworkFailure and calling it. The `P-TAUTH-PURGE ... cand visited total_ms` line is MXFS_LOG_DEBUG (one shared pr_debug site), so for page counts use a function profiler (tests/pve_pair_profile.sh with FNS), not dyndbg.
