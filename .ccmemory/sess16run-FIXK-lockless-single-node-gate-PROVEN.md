---
name: sess16run-FIXK-lockless-single-node-gate-PROVEN
description: sess16 FIX-K (F7A60942→): mxfs_dlm_is_single_node mutex→lockless read. ftrace: 2,276,687 calls/rsync-leg. paired 106-107%→97-103%, 3/3 PASS. 1/tcp 16…
metadata:
  type: project
---

# FIX-K — lockless is_single_node (the single_node_paired closer)

## RULE-4 chain
1. Hypothesis: the mutex inside `mxfs_dlm_is_single_node` (dlm/dlm.c) is the
   +2% CPU / ~5% wall residual — it gates EVERY hot overlay hook.
2. Instrument: `tests/tooling/paired_perf_diag.sh` (NEW, in-tree) — ftrace
   function profiler per leg (`*:mod:xfs` vs `*:mod:mxfs`), plus perf + stats
   modes.  Measured **2,276,687 calls in ONE paired rsync leg** (top mxfs-DSO
   consumer, ~1.95s graph time; 10× the ilock hook count — it's called from
   every buf lookup/submit/release site in pal/linux/xfs_buf.c too).
3. Dead leads proven dead the same run: xlog_grant_head_wait 49 hits on
   NATIVE leg vs 0 on mxfs (log size fine); P78/P15J fired 0× single-node
   (FIX-I costs nothing here); mxfs buf ops FEWER than native (134k vs 220k
   reads — native pays rmap overhead at default mkfs).
4. Patch: dlm.c `mxfs_dlm_is_single_node` → bare `count <= 1` read (int,
   written only under mutex at init/update_active_nodes; precedent:
   dlm_membership_settling reads it bare).  CAW arm already lockless.
5. Verified: paired rounds pre-K {105-112} ratios 103,103,106,107,107 →
   post-K ratios **103, 97, 102, 101** (4 consecutive PASS).  fio_vs also
   rewritten to position-balanced rounds (XM MX MX XM, time_based 6s writes,
   trimmed mean; reads stay informational) — PASS worst_write=109%.
6. **1/tcp column: 16/16 PASS** (first fully-clean 1-node column, iter1_k1).

## Notes
- The v5 wrapper call-chain overhead (~2 calls × 2.27M ≈ 35-55ms) remains if
  ever more is needed: cache a bool in mxfs_v5_dlm or inline in v5_mount.h.
- Heartbeat monitor still issues 63 sync 512B reads / 2s (disklock_hb_fn) —
  batchable to ONE 32KB read; measured minor (<1%), not done.
