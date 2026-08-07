---
name: ccloop-c7ee71c6-sess127-ROOT-bast-recv-thread-disk-read-headofline
description: sess127 RE-ROOTED the 32-node root-inode starvation: the single-threaded UDP BAST recv thread does a synchronous shared-LUN slot READ per packet.
metadata:
  type: reference
tags: [mxfs, defect, dlm, caw, performance, rule4, crash_consistency, bast]
---

# sess127 — D-32NODE-SHARED-DIR-CREATE-PACE re-rooted at the BAST RECEIVE path

Build 0.11.452 / srcversion A1C4A05CB6356F02B8625F6 (fleet-confirmed).
Run: virgin fs, `./run.sh 32 caw prep_cluster` (124 s) then
`./run.sh 32 caw crash_consistency` -> **FAIL 90 s/90 s**, hostload 12.68
(quiet rig; this is NOT a host-load artifact).

## sess126's hypothesis (a) is REFUTED — do not build the ilock read-barrier

sess126 proposed "READ-SIDE BARRIER: once a conflicting BAST is pending,
stop admitting NEW local ilock readers so mxfs_drain_ilock_read can
converge", from a low-share stack sighting.  Measured directly this session:

    P132-ILOCK-STUCK / -TIMEOUT      0 on all 32 nodes
    FOCUS (mxfs_dlm_bast* / mxfs_drain_ilock_read stacks, D-state,
           tick occupancy, 8 nodes, 30231 ticks)      1.18 %
    msleep < mxfs_drain_ilock_read < bast_process     4 samples of 724 (0.55 %)

The drain is not the blocker.  The i_lock is never contended for >5 s
anywhere in the fleet.

P36 is also NOT the cause: 295 P36-MHT-REARM on ino=128, and in **295 of
295** the printed pr=0, ex=0, pin=0 — so the busy predicate that actually
fires is `i_dlm_acq_inflight > 0` (not printed).  strikes max = 10 on every
node (~80 ms/episode), nowhere near the 2500 strikeout.  Symptom, not cause.

## New instruments (no rebuild needed; all probes used are ALWAYS-ON)

- `tests/cc_bastcensus.sh mark|report [N] [INO]` — the HOLDER side.
  Harvests P70-BP ENTRY/EXIT=full, SESS50-STARVE, P132-ILOCK, P36-*,
  pairs ENTRY->EXIT by `realns` per node, and prints the
  STALLED / UNDELIVERED / CHURN discriminator.
- `tests/mxfs_stackprof.py` + `cc_stackprof.sh agg` gained a **FOCUS**
  section: tick-occupancy + full signatures for any stack containing
  `mxfs_dlm_bast*` / `mxfs_drain_ilock_read` — i.e. the release side
  isolated from the requester side.  agg parses the new header.

## Holder-side census, ino=128 (mount root), 32 nodes, one 90 s run

    P70-BP ENTRY=332   EXIT=full=158   nodes_with_entry=32
    ENTRY mode: PR=137  NL=187 (no-op, already NL)  EX=8
    ENTRY->EXIT release wall: p50=319 ms p90=1670 ms p99=3802 ms max=5093 ms
      >=250 ms: 84 (53.2 %)      >=1000 ms: 35
    held_ms at BAST entry: p50=92203  (the root tenure spans the WHOLE run)

Only **145 real (PR/EX) release pipelines cluster-wide in 90 s** = ~1.6
handoffs/s for an inode that 19 nodes are queued on.  The limiter is
handoff RATE, not release cost.

## THE ROOT — BAST delivery is head-of-line blocked by device I/O

FOCUS full signatures, release side (total 724 samples):

    35.22 % 255  blk_execute_rq < scsi_execute_cmd < mxfs_pal_scsi_read_fua_bdev
                   < mxfs_pal_bdev_read_prio < read_slot < find_slot_skip
                   < mxfs_dlm_caw_held < mxfs_v5_dlm_inode_held
                   < mxfs_dlm_bast_notify < v5_bast_cb < bast_recv_fn
     4.14 %  30  ... < mxfs_caw_orphan_forensic < mxfs_dlm_bast_notify < ... < bast_recv_fn
     0.97 %   7  ... < caw_count_resource_slots < mxfs_dlm_caw_self_held_scan
                   < mxfs_v5_dlm_inode_self_held_scan < mxfs_caw_orphan_forensic < ... < bast_recv_fn

**~43 % of all DLM release-side blocked wall is the UDP BAST receive
thread doing synchronous SCSI slot reads inline.**

`bast_recv_fn` (dlm_caw.c:10640) is ONE thread per node and calls
`ctx->bast_cb(...)` **synchronously inside the recvfrom loop**.  The
callback chain bottoms out in `mxfs_dlm_caw_held()` (dlm_caw.c:8493),
which answers *"do I hold this resource?"* — a question about OUR OWN BIT
— by `find_slot()` -> **a read of the shared LUN**, then
`node_held_mode(slot, ctx->node_bit)`.  Zero of that read is needed: the
node already keeps `ctx->held.slots[]` / `held.count` under `held.lock`
in memory (bast_poll_fn iterates exactly that list), and XFS has
`ip->i_dlm_mode`.

Arrival rate: `MXFS_CAW_BAST_RESEND_MS 100` (and
`MXFS_CAW_BAST_RESEND_FAST_MS 25` for the first
`MXFS_CAW_BAST_RESEND_FAST_COUNT 4`) x ~19 waiters x 32 nodes.  Drain rate:
one thread x one device read per packet.  Consequence, measured:

    test5 /proc/net/snmp Udp:  InErrors 8085  RcvbufErrors 8085
    (every UDP error on the node is a RECEIVE-BUFFER OVERFLOW — BAST
     hints are being SILENTLY DROPPED)

and the socket is NOT under-buffered: `mxfs_pal_udp_open`
(pal/linux/kern.c:2420-2426) already sets `sk_rcvbuf = 4 MB` +
`SOCK_RCVBUF_LOCK` — sess8 fixed that for the nudge path.  Overflowing 4 MB
means the thread is stalled for seconds at a time.

This closes the loop on every earlier number: holders are not refusing to
release, **they have not been told**.  `hpr` bit-identical for 3 s (sess126
P204), `age_ms` climbing 2037->4980 before the 5000 ms stale-ticket valve,
mean grant wait 3533 ms, ~1.6 handoffs/s — all consistent with BAST
delivery latency of seconds plus outright hint loss.

## sess35 already fixed HALF of this and the other half was missed

dlm_caw.h:311-322 (sess35 NUDGE v2) states it exactly: *"v1 grant nudges
woke EVERY blocked acquirer on every node; each did a READ(16)+FUA
re-check, and at a 32-node single-dir create convoy those ~28 serialized
reads at the one SCSI target WERE the measured ~21.6 ms per-handoff
latency."*  sess35 added `wake_mask` so nudge receivers skip the disk read.
The **BAST** path never got the same treatment — it still does an
unconditional device read per packet, on a single thread.

## Fix shape (RULE 5 consult REQUIRED before building — not yet done)

1. `bast_recv_fn` must do **NO device I/O**.  Parse + validate
   (magic/uuid/requester), then hand off to a workqueue/ring.  O(1)/packet.
2. Answer "do I hold a conflicting mode on this resource?" **from memory**
   — `ctx->held` list and/or `ip->i_dlm_mode` — never `find_slot()`.
   Needs a resource->slot memo so the held list is searchable by resource.
3. Coalesce duplicate hints per resource inside a window (the 25/100 ms
   resend cadence guarantees many duplicates per handoff).
4. Get `mxfs_caw_orphan_forensic` (+ its `caw_count_resource_slots` /
   `mxfs_dlm_caw_self_held_scan` full scans) OFF the BAST hot path — 5.1 %
   of release-side wall on a forensic.
5. Re-check `MXFS_CAW_BAST_POLL_RELAX_MS 4000`: its comment justifies the
   relaxed idle poll with *"the UDP BAST path is operational, so the disk
   poll is no longer the lost-packet recovery path."*  RcvbufErrors=8085
   REFUTES that premise.  Note 4000 ms ~= the measured 3533 ms mean grant
   wait — check whether the relaxed poll is the actual service clock.

PASS bar (unchanged from the ledger): caw_wait_for_grant share falls from
26 % toward noise; ino-128 mean grant wait 3533 ms -> <50 ms; RcvbufErrors
delta across a run == 0; releases/run rises far above 145; crash_consistency
completes inside its 90 s budget on a VIRGIN fs.

## Traps
- Never `pkill -f mxfs_stackprof.py` over ssh (the launching `bash -c` line
  contains the string; pkill kills its own shell).  Use the pidfile.
- Do NOT set `instr=1` for this work — P138/P139/P204/P70/P36/SESS50 are
  all unconditional, and instr perturbs an 86 s run past 240 s.
- `mxfs_caw_pr_defer_max_ms` MODULE_PARM_DESC claims "default 50" but the
  variable is uninitialized = 0 (= unbounded).  The desc string is stale.
