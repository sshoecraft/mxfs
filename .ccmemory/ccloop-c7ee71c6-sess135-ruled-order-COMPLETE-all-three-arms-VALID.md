---
name: ccloop-c7ee71c6-sess135-ruled-order-COMPLETE-all-three-arms-VALID
description: sess135: ruled order 0x04-0x05-0x04 COMPLETE, all 3 arms VALID. 0x05 property (B) PASSES, ordering proven CAUSAL. Found+fixed a dmesg capture fault t…
metadata:
  type: reference
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, fencing, scst, test-harness, ftrace]
---

# sess135 — step-4 stage (i) A/B DISCRIMINATOR COMPLETE

## 1. The ruled order ran end to end; all three arms score VALID

| # | SA | artifact | margin (t_land - boundary) | (B) | (C) |
|---|------|--------------------------|-----------|------|------|
| 1 | 0x04 | /var/tmp/fence_ab.mViKq1 | **+12.417196 s** | FAIL | PASS |
| 2 | 0x05 | /var/tmp/fence_ab.84TNEv | **-0.000090 s** | **PASS** | PASS |
| 3 | 0x04 | /var/tmp/fence_ab.X5ajMW | **+12.370595 s** | FAIL | PASS |

The only difference between arms is the service-action byte and the outcome
flips deterministically.  0x04 BRACKETS 0x05, so no drift/state-contamination
explanation survives.  All 13 validity items ok on each (10_replay_gate n/a
until the C3 stage).  Arms 1 and 3 show VIOLATION SHOWN: YES.

## 2. The 90 us margin on 0x05 is CAUSAL, not luck — the raw trace proves it
Four consecutive lines, 181 us total (`fence_ab.84TNEv/trace.txt` lines 762-765):

    110481.887035 block_bio_queue:   7,0 W 135168+8   dm-delay releases the write
    110481.887045 block_rq_issue:    7,0 W 135168+8   issued to the loop
    110481.887126 block_rq_complete: 7,0 W 135168+8   LANDED
    110481.887216 scst_cmd_done_pr_preempt <-scst_tm_thread   P&A completes, +90 us

The `<-scst_tm_thread` caller is the point: the final hook is invoked FROM the
task-management thread as a direct consequence of the aborted command finishing.
That is sess132's source proof (`wait_for_completion(pr_aborting_cmpl)`) observed
live.  The boundary is CAUSED BY the landing, so the ordering cannot invert
however slow the storage is — a small margin is the SIGNATURE of a correct
implementation, not weak evidence.  Do not "improve" it by widening W; W does
not affect the margin, only when the landing happens.

Same trace also CONFIRMS sess134's first()->last() fix empirically: the first
`scst_cmd_done_pr_preempt` is at +0.022 (`<-scst_persistent_reserve_out_local`,
the PROUT's own exec-done).  With first() the boundary would be +0.022, t_land
+12.45, and property (B) would have FAILED SPURIOUSLY on the safety arm.

## 3. NEW DEFECT FOUND IN THE HARNESS — dmesg capture faked validity item 4
Arm 3 (first attempt, `/var/tmp/fence_ab.45tZci`) produced a **0-line**
`dmesg.txt` while the conflict line it should have contained was demonstrably
still in the ring buffer.  Cause, measured not guessed: `DMESG_MARK=$(dmesg |
wc -l)` + `tail -n +$((MARK+1))` is UNSOUND because the printk ring buffer is
bounded in BYTES, not lines.  A burst of long lines (SCST PR tracing runs ~200
chars) evicts a GREATER NUMBER of shorter old lines than it adds, the total
line count falls BELOW the mark, and `tail -n +N` yields nothing.

Why this mattered more than a lost log: an empty dmesg makes
`4_no_eh_reset_timeout` ("no EH / reset / timeout in the window") pass
**VACUOUSLY**.  That is the single most dangerous failure mode this harness
has — it reports a clean run because it captured nothing.

FIXED two ways:
- `inflight_ab.sh` stamps a unique token into `/dev/kmsg` at arm start and
  slices with `sed -n "/$TOKEN/,\$p"`.  Exact, needs no clock, and survives
  eviction accounting.  A second token marks the post-window slice.
- `verdict.py` gained validity item **`4d_dmesg_window_captured`**: the token
  must be present in `dmesg.txt`.  If it was evicted the evidence is LOST (not
  absent) and the arm scores INVALID instead of silently passing item 4.
  Verified: it flags the bad arm-3 artifact VIOLATED and passes the good ones.

NOTE the printk clock is NOT CLOCK_MONOTONIC — measured ~1.3 s offset at
110000 s uptime (printk uses local_clock/sched_clock).  Never place a dmesg
timestamp on the ftrace/userspace timeline; that is why a token, not a clock.

## 4. Other harness changes this session
- `inflight_ab.sh` RESTRUCTURED per the sess134 plan: the entire measurement
  window (property C, drain, tracing off, post-state PRINs, final dreads, dmesg)
  now runs BEFORE the held write is reaped.  Reap is then bounded (10 s), and if
  the target dropped the command without a response it is released with
  `stack.sh relogin victim`, recorded as `HELD_WRITE_ANSWERED` /
  `HELD_WRITE_RELEASED_BY` in arm.env, with a separate `dmesg_post.txt`.
  This is what unblocked the 0x05 arm, which previously hung forever.
- `ARM_SEQ` env shifts every LBA by (seq-1)*16384 sectors so a repeated service
  action lands on blocks no earlier arm ever wrote.
- `verdict.py` `4c_held_write_admitted` no longer requires `write_done` to
  exist — an absent one is the CORRECT 0x05/TAS-off behavior (admission is
  already proven by item 3: target-side active_commands + the dm bio).
- `verdict.py` `RE_TP` fixed: `block_rq_issue` prints an extra nr_bytes field
  (`7,0 W 4096 () 135168 + 8`) so it never parsed, and the report showed "--"
  for an event that WAS in the trace.  Display-only, but a misleading report.
- 0x05 reap measured: iscsiadm logout blocks ~3 min on the outstanding command.
  Budget arms accordingly (0x04 ~100 s, 0x05 ~5 min).

## 5. Where closure stands
Stage (i) — component-level in-flight exclusion at the target — is DONE and
scored.  Remaining for RULE-6 closure is the ruling's **(C3)**: prove the REAL
MXFS survivor does not begin replay before the successful fence completion is
CONSUMED (validity item 10_replay_gate, currently n/a).

Code check done this session: the shipped module DOES issue 0x05.  The only
BUILT caller of `mxfs_scsipr_preempt()` is `dlm/scsipr.c:465`, which passes
`abort=true`.  The three 2-argument calls in `dlm/mount.c` (lines 860, 1071,
1140) do NOT compile into mxfs.ko — `dlm/mount.c` is absent from the Kbuild
dlm object list (dlm.o dlm_caw.o dlm_shared.o discovery.o peer.o lease.o
disklock.o scsipr.o journal.o v5_mount.o net2*.o kern.o pinned_resource.o
yield_quantum.o) and no dlm/mount.o exists.  It is stale v1 user-mode source
that would not even build against the current 3-arg prototype.  Worth a
separate look (dead source carrying a wrong-looking fence call), but it is NOT
a live 0x04 fence path.

## 6. Rig state left CLEAN
tracing_on=0, tracer=nop, dm-delay 0, both fence sessions up
(victim=/dev/sda survivor=/dev/sdb), production target still 64 sessions, no
stray processes.  Teardown when done: `sudo bash stack.sh down`.
