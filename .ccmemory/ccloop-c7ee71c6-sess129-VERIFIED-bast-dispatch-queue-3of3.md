---
name: ccloop-c7ee71c6-sess129-VERIFIED-bast-dispatch-queue-3of3
description: sess129 wired + VERIFIED the sess128 BAST dispatch queue on 0.11.453: RcvbufErrors 8085->0, crash_consistency 3/3 PASS on virgin fs. Coalescing was N…
metadata:
  type: reference
tags: [mxfs, dlm, caw, bast, performance, sess129, verified, crash-consistency]
---

# sess129 — the sess128 BAST dispatch queue is WIRED, BUILT, DEPLOYED, MEASURED

Build **0.11.453**, srcversion `F20024E38213A9E64DB6718`, on all 32 nodes.

## What sess129 did

sess128 left the queue machinery written but **not wired** — none of it ran.
This session completed the ruling's own STILL-TO-DO list:

- `caw_bastq_init(ctx)` in `mxfs_dlm_caw_create` (non-fatal on failure).
- `caw_bastq_free(ctx)` in `caw_create_unwind` AND `mxfs_dlm_caw_destroy`.
- Dispatchers created in `mxfs_dlm_caw_start` **before both producers**, so a
  submission can never land on a queue with nobody draining it. Zero
  dispatchers started => `caw_bastq_free` + inline fallback (strictly better
  than a queue that can only drop).
- New `caw_bastq_join_workers()` — broadcast under `bq.lock`, then bounded
  `caw_join_bounded` per worker. Called in stop PHASE 3 **after** both
  producers are joined, and on both start-unwind paths. Mandatory because the
  PAL cond destroy is a bare `kfree` (pal/linux/kern.c:1943) — a worker still
  in `schedule_timeout` on a freed waitqueue is a UAF.
- New always-on probe **P265-BASTQ-STATS** (poll thread, 10 s cadence, + one at
  stop). Without it the coalescing ratio is unprovable.
- New harness `tests/bastq_snap.sh` (RULE 3): snapshots the `/proc/net/snmp`
  Udp row + last P265 line fleet-wide; `--delta pre post` prints the
  RcvbufErrors delta and aggregate bq totals.

## MEASURED — the PASS bar, 3/3 on the ledger's own deterministic recipe

Recipe (the detector that reproduced the FAIL 3/3 on 0.11.452):
`./run.sh 32 caw prep_cluster` (fresh mkfs) then
`./run.sh 32 caw crash_consistency`.

| cycle | crash_consistency (virgin fs) | dRcvbufErrors, 32 nodes | dInDatagrams | overflow | inline |
|---|---|---|---|---|---|
| 1 | PASS 32/32, 79s/90s | **0** | 624089 | 0 | 0 |
| 2 | PASS 32/32, 79s/90s | **0** | 591339 | 0 | 0 |
| 3 | PASS 32/32, 77s/90s | **0** | 573471 | 0 | 0 |

Was: FAIL nodes_pass=0/32, NO_TERMINAL_RECORD=32, 90s/90s, RcvbufErrors=8085.

Full board re-run on 0.11.453 (every test, not just the changed path, because
BAST callbacks now run on new threads): **27 PASS, 0 FAIL**, 1 POLICY
(open_defects, red by design). No regression.

## THE IMPORTANT CORRECTION — coalescing is NOT the mechanism

`coalescing = submitted/dispatched = 1.05-1.06x`. merged+rearmed is only ~8.7%
of submissions, and **hiwater=1** (one node hit 2) across all three cycles.
The queue is essentially never deep, because the dispatchers keep up
completely.

So the fix does NOT work by deduplicating hints. It works by **decoupling the
UDP socket drain from the synchronous shared-LUN slot read** — `bast_recv_fn`
is now O(1) per packet, so the socket drains at line rate and the 4 MB
sk_rcvbuf stops overflowing. That is exactly the sess127 root, and the
RcvbufErrors 8085 -> 0 delta is the direct evidence for it.

**Do not tune the coalescing window/table expecting it to matter.** It is
carrying ~6% of the load. If a future workload ever pushes hiwater up, the
coalescing is there and correct (conservative lattice join), but it is not
what bought the fix.

## STILL OPEN at handoff

`D-CRASH-CONSISTENCY-32-NOTERMINAL-354` — its stated closure condition
("crash_consistency runs on a VIRGIN fs inside its 90s budget with the
BAST-delivery fix in place") is now MET 3/3, but **the ledger entry was not
yet updated** — next session should disposition it.

`D-32NODE-SHARED-DIR-CREATE-PACE` — shares the root; 2 of its 5 PASS-bar items
are met (RcvbufErrors delta 0; crash_consistency in budget). **Three unmeasured:**
- `caw_wait_for_grant` share 26% -> noise  (`tests/cc_stackprof.sh agg`, FOCUS section)
- ino-128 mean grant wait 3533ms -> <50ms  (`tests/cc_grantwait.sh arm/report`, needs instr=1)
- real releases/run far above 145          (`tests/cc_bastcensus.sh report`)
Plus the defect's own headline metric — the ~42x create pace — needs
`tests/create_scale_curve.sh` (old curve mean ms: 5.2/9.2/10.8/26.0/71.7/191.8
for 1/2/4/8/16/32 participants).
NOTE the entry's item 7 says do NOT set instr=1 for the census/stackprof tools
(it takes an 86s run past 240s); cc_grantwait's `arm` DOES set instr=1, so run
that one on its own dedicated cycle, not inside a board run.

`D-READDIR-PEER-CACHED-DIR-PACE` — same root per sess127; not yet re-measured.
