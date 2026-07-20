---
name: AAA-ccloopa864-sess4-END-three-wedges-and-combined-config-plan
description: sess4 END: dir_reuse@32/caw has 3 stacked wedges. #1 orphan FIXED (in tree). #2 durable-signal bwrite hang (dirop_durable_caw=0 avoids, coherency hel…
metadata:
  type: project
---

# sess4 END (ccloop a864) — dir_reuse@32/caw = THREE stacked wedges; combined-config plan

## CRITERIA NOT MET. Only gap = dir_reuse_coherency@32/caw (criteria.json: 1/2/4/8/16 caw = 17 PASS each; 32/caw = 16 PASS, dir_reuse absent). This session peeled 3 distinct wedges, each proven by RULE-4 instrumentation/A-B.

## Build in tree: E5F760E6 (VERSION 0.10.50) = FIX#1 orphan wall-clock strand escape. KEEP.

## THE THREE WEDGES (peeled in order):
1. **mode=NL orphan (FIXED, build E5F760E6).** orphan_live 280-strike escape never converges on CAW (grant_seq churn resets it; 0 P15H fired in 1748 stuck-waits, node held dir EX 119s idle). FIX = wall-clock strand escape (xfs_mxfs_dlm.c ~11957, CAW-only, param caw_orphan_force_ms=3000, field i_dlm_orphan_since_ns) + `!p15h_reap` bypass of gen_moved abort (~11983). VALIDATED: P15H-STRAND-TIMEOUT fired 15+/node, progressed r4-wedge→r9. See memory ...orphan-fix-WORKS...
2. **per-op durable-signal SYNC bwrite hang.** rank1 rm-rf: xfs_remove→mxfs_dlm_dir_durable_signal→mxfs_dir_flush_data_blocks→{owner_scan OR bmbt_scan}→xfs_bwrite→xfs_buf_iowait STUCK 302s (inflight=0), holds dir EX, cluster starves. A/B `dir_owner_scan=0` just moved hang owner_scan→bmbt_scan (same sync bwrite). A/B `dirop_durable_caw=0` REMOVED this hang → progressed to r8 with **fail=0 (coherency HELD, no readdir/leaf-hash loss through 8 reuse rounds)**. See memory ...wedge2-is-durable-signal-sync-bwrite-hang.
3. **acquire STARVATION (now the limiter).** With dirop_durable_caw=0, at r7/r8 an EX waiter (dd in caw_wait_for_grant→caw_acquire_poll_sleep) starved to el_ms=119s. Holder ROTATES (hex=800→hex=40000, lock IS handing off) but free-for-all CAS starves one unlucky EX waiter. `yt` (yield ticket) IS set by releasers (72030082) but IGNORED because **mxfs_caw_fair_handoff defaults OFF** (dlm_caw.c:88, honored only at dlm_caw.c:1655). Fix candidate = caw_fair_handoff=1 (round-robin, honors yt). History: fair_handoff had sess130 livelocks but v0.10.39-42 fixed streak-yield; UNTESTED with current build.

## NEXT SESSION — EXACT NEXT EXPERIMENT (no rebuild; modargs on build E5F760E6):
`MXFS_EXTRA_MODARGS='dirop_durable_caw=0 caw_fair_handoff=1' MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency`
Watch tests/drc_progress_watch.sh (OUT=scratchpad/progress.log): PASS = 24 rounds, fail=0, no el_ms→120s. 
- If PASS → the 3 levers (orphan fix built-in + these 2 modargs) are the solution. THEN make them DEFAULT: flip mxfs_dirop_durable_caw (dlm... xfs_mxfs_dlm.c:873) — BUT that disables a coherency mechanism sess48 added for a 2/tcp gap; safer to instead FIX the durable-signal bwrite hang (keep coherency) + set mxfs_caw_fair_handoff=1 default. Then re-verify ALL caw node counts 1/2/4/8/16/32 (criteria = full applicable suite per count) with the new defaults.
- If fair_handoff=1 LIVELOCKS (no progress) → don't use it; attack starvation differently (the yt ticket is already set; maybe honor it without the full fair_handoff, or add acquire aging).
- If still wedges on a NEW mechanism → peel wedge #4.

## Alt path (RULE-4 cleaner, keeps coherency): instrument WHY the durable-signal xfs_bwrite hangs with inflight=0 (pre-bwrite probe: daddr, b_flags, pin, bli li_flags incl FLUSHING, _XBF_MXFS_ALLOC_QUEUED) → fix the I/O-path hang instead of disabling the flush. owner_scan=xfs_mxfs_dlm.c:1042 (bwrite at ~1135, async log_force at 1134 may be insufficient for pinned bufs).

## Cluster state: clean (no run, lock free); nodes may be wedged from killed runs — run.sh prep power-cycles them. Diagnostic: tests/drc_progress_watch.sh (new). NEVER rebuild mxfs.ko while a run is active (mid-run node reboot re-insmods → contaminates the experiment).
