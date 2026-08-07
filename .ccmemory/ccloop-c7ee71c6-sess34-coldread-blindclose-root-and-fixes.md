---
name: ccloop-c7ee71c6-sess34-coldread-blindclose-root-and-fixes
description: sess34: COLDREAD-STALE-SPLIT root REVISED = merge-overlay BLIND-CLOSE (not overlap); FIX-1/2/3 shipped 293, FIX-1 narrowed 294 after livelock; orphan…
metadata:
  type: project
---

# sess34 (wrapper session 16) — the blind-close root + 293/294

## D-CRASH-COLDREAD-STALE-SPLIT — root chain PROVEN-REVISED
Overlap/out-of-order-landing REFUTED (39 P170 submissions, cc=6 NEVER
submitted; zero P-SEMA-DUALLOCK/OVERUP/WRCNT-RESUBMIT in capture).
Chain: O_SYNC append committed SUB-EX (delalloc writeback path, P26PRE
mode=0 — holders census blind) during release abort(P15)/re-entry;
durable-pass copy-in staged cc=6 (flush 6->11); **cluster-merge overlay
(`mxfs_iflush_cluster_merge_dirs`, P-CLMERGE restored) replaced the
staged slot with platter cc=4 WITHOUT rolling flush back**; completion
stamped durable=flush=11 (xfs_inode_item.c:1107 is honest, input was
poisoned) = BLIND CLOSE; `mxfs_relbar_close_or_defer` saw pend==dur ->
anchored wire unlock ran (that's why P228=0); reload at 13:20:02 adopted
stale platter (P177 SILENT — ledger read closed) destroying the only
cc=6 copy. Loss = acknowledged O_SYNC data, cluster-wide, silent.

## Fixes (0.11.293, srcver C569FD299...; 0.11.294 289555CFD964C57A7890B16)
- FIX-1 P238-CLMERGE-LEDGER-ROLLBACK (xfs_inode.c, mxfs_clmerge_ledger_
  rollback + slot_ip[] map): overlay of staged slot -> flush=durable +
  PUB_SKIPPED (P187 completion re-arm keeps item dirty+in-AIL).
  **294 NARROWED to RELFLUSH-window only**: 293's unconditional form =
  livelock engine for copy-in-gate/merge-mask AUTHORITY-GAP slots
  (copy-in allowed, mask condemns): test32 ino 62914705 50×P238 loop,
  1926 P187, immortal dirty item -> P-NOINO-RELFENCE-WEDGE ino=8388746
  -> node shutdown -> board cascade. Void-change slots must keep
  complete-clean (designed resolution).
- FIX-2 P236-REL-OBLIGATION-DEFER `mxfs.rel_obligation_gate=1`: pre-NL
  gate at bast_process commit point (p236_gate + obligation_only wired
  into the abort machinery, CACHED+bast_pending, dwork 25ms bastq_src=21,
  gate_defer counter in P220 dump). Exempt: dirs/ISTALE/dead_incarn/
  dlm_stale/shutdown/entry-NL.
- FIX-3 P237-EVICT-OBLIGATION `mxfs.evict_obligation_shutdown=1` in
  mxfs_dlm_evict: last-chance publish if EX (mxfs_inode_cluster_durable)
  else pr_err + force_shutdown (Gemini: dirty-at-NL teardown must be
  fatal, in-core is the only copy).

## Verification state
294 full 32/caw board GREEN except ag_strand_repair 27/32 (strands=0
all-zeros signature, SAME as 292-era 3-of-5 history, 2/2 now — next
root; NOT mine: P236/237/238=0 in its laps). crash 4×PASS, dir_reuse
PASS 105s. gate_defer=0 everywhere (no natural recurrence).
**NOT closed**: incident overlay condemned a RELFLUSH-window slot —
mask should have protected (7516 honors RELFLUSH for ATTACHED items);
unresolved: mask-walk attachment gap vs SECOND BUFFER INSTANCE (run64/
P-WRCNT-RESUBMIT family). FIX-1's slot_ip[] uses the same b_li_list ->
same blindness. Closure needs: authority-predicate unification (copy-in
gate vs merge mask), instance question settled, amplified repro
(fix27_delay_ms widens sub-EX window), or survived recurrence.

## Orphan wire-EX (dir_reuse 0/32 wedge, SEPARATE defect)
Budget SIGKILL killed mkdir between wire EX CAS win and in-core consume
-> ino 34081568 slot16 EX on wire 350s+, in-core NL, NO reaper (P36-MHT
in-core-only; P15-TCP-ORPH-PROCEED gated !transport_caw), heartbeat
keeps stamping (gen climbs, yt/ysm FROZEN), any local access queues
behind it. Evidence tests/logs/sess34_dirreuse_orphan_ex_144733. FIX
SHAPE: CAW abandoned-grant reap in the acquire stuck-detector (holder==
own slot + no live tenure/acq_inflight + persistent) with sess15-FIX-H
live-gen guard. Recovery = re-prep only.

## Method notes
- P141-UNLK-EXCLR lives in dlm_caw.c:4184 (anchored CAS unlock).
- close_or_defer head: instant-false when pend==dur — a blind-close
  upstream makes ALL tail enforcement vacuous. Ledger honesty is the
  load-bearing layer.
- 289 EX-gate (site xfs_buf.c~3836) sets PUB_SKIPPED UNGATED — the 18
  baseline P187s are that, benign.
- pub_obligation_enforce still 0 (P176 re-log arm unarmed) — candidate
  lever if UNCOPIED obligations with clean items need convergence.
