---
name: AAA-ccloop7251-sess3-END-icluster-phase1-core-landed
description: sess3 END: ICLUSTER Phase-1 core LANDED+compiling (inert, knob 0); next = BAST fan-out + routing; full plan in DLM_PLAN.md + state.md
metadata:
  type: project
tags: [icluster, dlm, handoff, perf]
---

# ccloop 72513a13 sess3 END — ICLUSTER Phase 1 core landed

Read AAA-ccloop7251-sess3-op-ledger-and-batching-pivot for the WHY
(measured op ledger; 5 shave-fixes flat; GPT verdict full text is in the
sess3 transcript, MCP task k1ud3n6hg).

## Landed this session (all build clean, srcversion 21541B487759160548B84C5)
- 0.11.12-0.11.15 op-shave series (see CHANGELOG.md — span probe reads,
  P125 knob, verify throttles + shared snapshot, UDP GRANT NUDGE,
  grant-time heldchk stamp, nlink==0 demote suppression, P87 1/64
  sampling, BAST relax 4s). All deployed+PASS on 8/cawd; round time flat
  → proved granularity is the wall.
- ICLUSTER scaffolding (dlm side) + Phase-1 CORE mediating layer (xfs
  side, end of xfs_mxfs_dlm.c): see state.md "ICLUSTER implementation
  status" for the precise DONE/NEXT lists. Knob mxfs.icluster_dlm=0
  default = inert. VERSION still says 0.11.15; bump to 0.11.16 when the
  wiring (fan-out + routing) lands.

## Critical next-session steps (state.md has details)
1. BAST fan-out in mxfs_iclus_bast_notify (invalidate covered cached
   inodes via existing per-inode bast machinery) + register callback +
   purge_all at unmount.
2. Route S_ISREG through mxfs_iclus_lock/unlock at the ~17
   mxfs_v5_dlm_inode_* call sites (knob+CAW gated).
3. 0.11.16 → deploy → icluster_dlm=1 → dir_reuse@8 6-round A/B (expect
   verify+rm ≥3×) → correctness battery at 8 → then Phase 2 (batched
   drains, inactive grant reuse, dir tenure cohorting, allocation
   steering) per DLM_PLAN.md.

## Rig facts
- 8/cawd formation live on 0.11.15 (E7854361F1BB8CFEB711558);
  pr_idle_release_ms=400 runtime-set on nodes (module default 0; next
  prep reset). dir_reuse@8 6-round ≈ 134-145s on all recent builds.
- kprobe recipe + DRCph windowing in the op-ledger memory. kprobes work
  on mxfs.ko; ftrace function tracer does NOT.
- Killed leftover runaway ugrep on clyde (watch for stray processes from
  old sessions — check `ps -eo pcpu,comm --sort=-pcpu | head` at start).
