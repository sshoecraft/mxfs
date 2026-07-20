---
name: sess12run-fence-190s-AG0-hold-diagnosis-and-P12-probes
description: sess12: post-FIX3 fence FAIL root = test1 held AG-0 EX GRANTED 189s (P-LKTIMEOUT-HOLDER, master t2 sent 120 BASTs, t1 zero receipts visible) starving…
metadata:
  type: project
---

# sess12 — fence/netpartition/tds triple-FAIL root: 190s continuous AG-0 EX hold

## Evidence (artifact /tmp/run_fence_during_write_20260703T233459Z, build D0151E9A r4 full suite)
- t2 rm + t4 rm both `DLM AG lock failed: ag=0 rc=-110` → defer_finish "Corruption of in-memory data (0x8)" shutdown (23:43:13, 23:44:21). Cascaded into fault_netpartition + tcp_dlm_scaling FAILs (dead FSes) — one root, 3 FAILs (same shape as sess11 r3).
- Master (test2) P-LKTIMEOUT-HOLDER: holder=234400203 (=test1) hmode=EX hstate=2(GRANTED) held_ms 129198→189614 CONTINUOUS (single grant, never released). queued_ms≈held_ms+21 → rm queued 21ms before t1's grant = FIFO fine (FAIRQ find_conflicting_waiter exists+works); the bug is the never-released hold.
- test2 sent ≥120 `P5B-AGBAST-SEND ag=0 target=234400203 rc=0`. test1: ZERO receiver-side evidence — ALL AG-BAST receiver probes (P5N/P5W/P39) were instr-gated; P67-AG-BAST-STALL(ungated)=0; P55-STUCKMETA(ungated)=0.
- Hold began ~23:40:04 DURING dir_reuse_coherency (fence started 23:42:10) — fence is collateral; wedge forms under dir_reuse churn.
- test1 was otherwise healthy/active (dir/inode DLM traffic normal). No hung-task (stuck DLM waits are S-state). Load-1.0 on idle test1 = v5_tcp_death_worker_fn msleep loop (red herring).
- FIX3 (D0151E9A) create dir→AG ordering verified individually (fence ×3 PASS fresh-cycle) but full-suite still fails — DIFFERENT shape from the pre-FIX3 create-vs-rm ABBA (that was bounded 60s cycles; this is one continuous 190s hold).
- Fresh-cycle `run.sh 4 tcp dir_reuse_coherency fence_during_write` (2-test chain) PASSED — repro needs full-suite aging/load (or flake odds; suite reproduced 2/2 on r3/r4).

## Mechanism candidates (probes discriminate)
- Release only happens via pag_dlm_bast_work_fn COMMIT. Cached fast-path re-adoption (`pag_dlm_cached` branch in __mxfs_ag_dlm_lock) has NO bast_pending check → local back-to-back trans can ping-pong the work's Phase-1/2 holders-bail forever (shape A).
- m_mxfs_ag_bast_wq is alloc_ordered_workqueue (one work at a time, all AGs; sess33 anti-xfsaild-starvation choice). If ANY AG's work wedges (top candidate: mxfs_dlm_publish_unpublished → mxfs_v5_dlm_inode_lock network acquires; pre-v0.5.5 measured 18–30s drains) then EVERY AG's release is head-of-line blocked while bast_scheduled=true suppresses all rescheduling — immune to idle gaps (shape B).
- Lost schedule (queue_work failure / flag desync) (shape C).

## Probes added (build AFEF43B92, all UNGATED ratelimited, only fire under peer contention)
- P12-AGBAST-RX (arrival: holders/cached/sched/schedule/readopt/page_ms) in mxfs_dlm_ag_bast_notify; stamps pag_dlm_bast_pending_since + resets pag_dlm_readopt_n on 0→1 (new perag fields).
- P12-READOPT (cached fast-path adoption while pending; n, page_ms, comm).
- P12-WORK enter / bail1-holders / bail1-uncached / bail2-holders / bail2-uncached / COMMIT (entry with no exit = stuck work; includes readopt + page_ms).
- P12-ULBP at unlock-last when pending (sched_now/was_sched/readopt/page_ms). was_sched=1 repeating + no P12-WORK enter for that AG = shape B signature.

## Signatures to read on next FAIL
- Shape A: many READOPT n→100s + WORK bail-holders, page_ms growing to 190k.
- Shape B: WORK enter for some OTHER ag with no COMMIT/bail after it; starved ag shows ULBP was_sched=1 + zero WORK enter.
- Shape C: ULBP sched_now=1, no WORK enter, no other stuck work.

## Fix directions (pick after probes)
- A: at unlock-last with bast_pending, claim demote synchronously (demoting=true before dropping pag_dlm_lock) so adopters block on existing wait_demote; -EAGAIN AIL-stall path must then clear demoting+wake+restore. Or deny cached re-adoption when pending (slow-path → FAIRQ fairness) but MUST still release the on-disk grant (bail1-uncached currently consumes pending without unlocking — would leak the grant).
- B: bound/parallelize publish drain (FIX-28 style skip), or move publish out of the ordered critical path. Do NOT naively unbind the wq (sess33 regression).
- Gotcha: after any defer_finish shutdown, nodes won't rmmod → virsh recycle all 4 before next run (NODE_PREP_FAIL otherwise).
