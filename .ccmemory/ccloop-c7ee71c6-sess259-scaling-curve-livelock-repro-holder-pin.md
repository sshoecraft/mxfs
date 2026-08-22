---
name: ccloop-c7ee71c6-sess259-scaling-curve-livelock-repro-holder-pin
description: sess259: 0.11.490 deployed, board chunks A+B green; scaling_curve FAIL 3/3 = -488 livelock ON-DEMAND repro; test27 ag=1 cached=1 sched=1 page_ms>90s…
metadata:
  type: project
---

# sess259 — 0.11.490 board + -488 livelock reproducible

## Board on 0.11.490 (sv B8A561D0E04957E337361E6), 32/caw
- tools had to be rebuilt (`make tools`) — sess258's `make clean` wiped
  mkfs_mxfs and prep failed with FS_PREP_FAIL until rebuilt.
- prep_cluster OK 77s, fleet converged on .490.
- PASS: precond_readiness fio_perf(seqW 7.5GB/s) fio_perf_vs_xfs
  cache_coherency(654/654) strong_consistency posix_multi mmap_coherency
  zero_silent_loss(644/644) dlm_fairness dlm_membership dlm_scaling(58s/90s
  — 3x slower than prior 19s, watch).
- FAIL 3/3: scaling_curve nodes_pass=0/32 NO_TERMINAL_RECORD 90s/90s.
  Empty node logs are NORMAL (ck() is silent until finish()).
- MQTT broker 192.168.1.149 had a transient outage at session start
  (first run.sh aborted with "coord broker unreachable"); recovered by
  itself. Likely also explains the 2026-08-12 rsync_paired
  NO_TERMINAL_RECORD=32 board cell.

## Livelock evidence (live probes during run 20260814T142218Z)
- test1 dd: D-state blk_io_schedule under __iomap_dio_rw (I/O never
  completes). test7 dd: caw_wait_for_grant→mxfs_v5_dlm_ag_lock.
  test25: done, parked at sc_wrote barrier. Single-node dd on idle
  cluster: 1.5s 180MB/s — raw path fine.
- Platter (caw_slotdump via test25): ~23 AG slots EX-held wmode=NL,
  affinity pattern ag=N by bit N; ag=1 EX by bit26 with wait_ex bit1;
  ALL revoke=0 (sess249 sticky-revoke NEVER set; 0 P280-REVOKE-RX
  fleet-wide).
- bit→host map (P265 sweep): bit26=test27, bit1=test32, bit12=test7,
  bit13=test29. (Full 32-entry node_id list in sess259 transcript.)
- **test27 (ag=1 holder): `P12-AGBAST-RX ag=1 holders=0 cached=1 sched=1
  schedule=0 readopt=147→254 page_ms=80445→90503 holder=6936/dd`** —
  in-core tracking PRESENT (cached=1), release work SCHEDULED (sched=1),
  blocked >90s on a holder/page pin owned by its own scaling dd 6936;
  page_ms KEPT GROWING AFTER dd 6936 WAS DEAD (harness SIGKILL) →
  pin leaks past process death.
- Refines -488: mechanism at the blocked holder is NOT lost tracking;
  it is an un-completable release (holder pin wedged on I/O/grant),
  i.e. distributed hold-and-wait: each dd pins one AG while waiting on
  another AG or on raw I/O. Stranded-bit/tracking-loss state is likely
  the AFTERMATH once processes die/nodes recycle.
- .490 F3 proof code not implicated so far: zero P289/P280/P281 lines.

## Next
1) Confirm page_ms still grows with dd dead; read bast_work_fn P12 emit
   to learn what page_ms/holder pin is and why it survives process exit.
2) RULE 5 consult with this evidence (differs from sess243 premise —
   revoke can't fix an unreleasable holder).
3) Then fresh prep + remaining board chunks (rsync_paired onward).
