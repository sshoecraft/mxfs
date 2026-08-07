---
name: ccloop-c7ee71c6-sess126-ROOTED-shared-dir-pace-PR-starve-root-inode
description: sess126 ROOTED the 32-node shared-dir create pace: PR waiters on the MOUNT ROOT ino 128 starve ~3.5s behind a yield ticket whose EX waiter can never…
metadata:
  type: reference
tags: [mxfs, defect, dlm, caw, performance, rule4, crash_consistency]
---

# sess126 — D-32NODE-SHARED-DIR-CREATE-PACE / D-CRASH-CONSISTENCY-354 ROOTED

Build 0.11.452 / srcversion A1C4A05CB6356F02B8625F6, fleet-confirmed on all 32 nodes.

## 1. New tool: wall-clock stack sampling (no rebuild)
`tests/mxfs_stackprof.py` + `tests/cc_stackprof.sh` (start/stop/harvest/agg).
Samples /proc/PID/task/*/stack at 20 Hz for every D-state task plus workload
comms, histograms the blocking stack. A task found in stack S on f% of ticks
spent f% of its wall in S — the wall attribution probe COUNTS cannot give.

Virgin-fs crash_consistency @ 32/caw, 8 nodes, 30310 ticks / 34300 samples:

    26.28%  9014  mxfs_pal_cond_timedwait < caw_nudge_wait < caw_wait_for_grant
                    < mxfs_dlm_caw_lock < mxfs_v5_dlm_inode_lock
    16.59%  5690  open_last_lookups < path_openat < do_filp_open < do_sys_openat2
    39.61% 13585  do_wait    (parent shell on those children)
    13.59%  4661  pipe_read  (command substitution on those children)

Everything else <2%. Device path, CAS contention, AG locks: absent.
=> ~100% of workload blocking wall is the CAW INODE grant wait.

## 2. P138/P139/P204 are ALREADY ALWAYS-ON — do not set instr=1
P138-WAIT (dlm_caw.c:5918) is NOT gated by caw_instr_on(): INODE type,
elapsed>5ms, capped 4000/boot. P139-TAILCENSUS (>800ms) and P204-YT-DEFER
(capped 200/module-load) likewise unconditional. instr=1 perturbs hard
(86s run -> >240s, killed). New harness: `tests/cc_grantwait.sh arm|disarm|report`.

Grant waits cluster-wide (202 records >5ms, 25 nodes):
    ino 128  mode=3(PR)  202 grants  713681 ms  mean 3533 ms  ffw_share 100%
    ino 29360256 (.crash_consistency)  ONE grant, 294 ms
    caw_svc_ms sum 5767 ms = 0.8%;  caw_miss p50=0;  reads p50=13

**ino 128 is the MOUNT ROOT** (stat /mnt/shared => ino=128). The shared test
directory is essentially uncontended. All prior work chased the wrong inode.

P139-TAILCENSUS (172 tail events) discriminators:
    bit_lost=0 everywhere      -> NOT queue-position loss
    chosen nonzero in 3/172    -> NOT the chosen-waiter path
    free_defer nonzero in 2    -> NOT free-defer
    foreign_yt p50=15, ALL 172 -> deferred on a FOREIGN yield ticket
    doze250    p50=15, ALL 172 -> 15 x MXFS_CAW_DEFER_POLL_MS(250) = 3750 ms
    caw_miss   p50=0           -> NOT CAS contention

## 3. THE PROOF — P204-YT-DEFER raw, test5, ino=128, 12 consecutive samples
    yt=20000 w=b7da6953 wex=27da0000 hpr=8209288 hex=0 nb=2 age_ms=2037 ytd=5
    ...
    yt=20000 w=b7db6d73 wex=27da0000 hpr=8209288 hex=0 nb=2 age_ms=4980 ytd=16

Over 3 full seconds: the yield ticket is FROZEN on one node; **hpr (7 PR
holders) is bit-identical, frozen**; hex=0 (nobody holds EX); wex = 10 EX
waiters; w grows as more nodes pile in; age_ms climbs to 4980 and then the
5000 ms MXFS_CAW_YIELD_TIMEOUT_MS stale-ticket valve fires and it repeats.

Ticket age at defer, ino=128, n=1141: p50=2873 p90=4588 max=4994 ms.
Queue shape: waiters 19.2, waiters_ex 10.5, holders_ex 0.00, holders_pr 6.79.

modes: 3 = MXFS_LOCK_PR, 5 = MXFS_LOCK_EX (include/mxfs/mxfs_dlm.h:28).
All 202 ino-128 waits are **PR (read) waiters**.

## 4. The mechanism, stated
1. A node wants EX on the mount root (virgin-fs `mkdir -p $MNT/.crash_consistency`
   races on all 32 nodes; the dir is created once and never removed, which is
   exactly why the second run is fast — sess125's "empty dir" recipe was a
   correct observation with the wrong explanation).
2. It registers as an EX waiter; a yield ticket is armed for it.
3. Seven nodes hold PR on the root and DO NOT RELEASE under the EX BAST for
   3+ seconds. Stack evidence for why:
   `msleep < mxfs_drain_ilock_read < mxfs_dlm_bast_process < mxfs_dlm_bast_work_fn`
   — the BAST release path drains local ilock readers, and every node is
   continuously path-walking through the root for the dd/md5sum opens, so new
   readers arrive faster than the drain retires them (read-side livelock; no
   barrier stopping new readers once a BAST is pending).
4. Meanwhile every PR requester — compatible with the existing PR holders,
   hex=0 — is forced to defer on the foreign EX ticket (strict writer
   preference) and dozes 250 ms at a time.
5. Nothing can progress until the 5 s stale-ticket valve clears the ticket.
   The system is running on its safety valve.

## 5. What sess24 already knew and left open
dlm_caw.c:155-200 — `mxfs_caw_pr_batch_nodefer` (default 0, "measured never to
engage") plus the comment block at ~200-245 already states: "A PR requester is
COMPATIBLE the whole time (hex=0, ffw_ms==elapsed_ms on 99% of waits), and it
defers purely on policy: strict writer preference, unbounded. The bound that
was supposed to limit it is MXFS_CAW_YIELD_TIMEOUT_MS (5s) applied to yt_age —
but yt_age is the wrong clock. The release path re-arms yield_set_ms whenever
the ticket VALUE changes." sess126 confirms it on the ROOT inode at 32 nodes
and adds the other half: the EX waiter the ticket guards can never be granted
either, because the PR holders never drain.

## 6. Next steps for the fix (RULE 5 consult first — two independent shapes)
(a) READ-SIDE BARRIER: once a conflicting BAST is pending on an inode, stop
    admitting NEW local ilock readers so mxfs_drain_ilock_read can converge.
    Without this the EX waiter can never be granted and any ticket policy is
    moot.
(b) BOUNDED SHARED-CLASS PATIENCE: bound a PR requester's deferral by a clock
    that does NOT reset on ticket rotation (per-requester wait clock, not
    yt_age), so reads cannot be starved indefinitely by a writer that is
    itself blocked.
Do (a) first — it is the actual blocker; (b) alone would only let readers
bypass a stuck writer.

## 7. Harness notes / traps
- NEVER `pkill -f mxfs_stackprof.py` over ssh: the launching `bash -c` command
  line contains that string, so pkill kills its own shell (silent no-op).
  cc_stackprof.sh kills via /run/mxfs_stackprof.pid.
- Virgin-fs run PASSED at 86s/90s this session (hostload 15.63), not FAIL.
  The pace defect is the constant; the 90 s NO_TERMINAL_RECORD is its tail.
