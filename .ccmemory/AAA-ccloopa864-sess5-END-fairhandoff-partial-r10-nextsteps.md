---
name: AAA-ccloopa864-sess5-END-fairhandoff-partial-r10-nextsteps
description: sess5 END: caw_fair_handoff=1 (durable_caw=1) is PARTIAL — grinds past default's r8 wedge to r10 fails=0 but still stalls (P15-REL-ABORT persists). R…
metadata:
  type: project
---

# sess5 END — caw_fair_handoff=1 result: PARTIAL (r8→r10, still stalls). Next: fix the release-abort site directly.

## Result of the fair_handoff=1 experiment (build 0349484E, durable_caw=1 default)
`MXFS_EXTRA_MODARGS='caw_fair_handoff=1'` progressed r1→r10 with **fails=0, P-IOWAIT-STUCK=0, no hard-hang** — GOT PAST the default config's r8 wedge (default: r1→r8 then P15-REL-ABORT starvation). BUT still HIGH P15-REL-ABORT (300-566/round) and stalled ~4.5min+ at r10 (locks still granting — fresh 10ms waits — but shared dir ino=131 EX waits 11-40s; NOT a hard deadlock, a slow grind). So fair_handoff=1 REDUCES the ino=131 handoff starvation but does not eliminate it. Run left LIVE at r10 — completion watcher bwso4j560 + autocapture_fh.log will record whether it grinds to r24 (possible PASS within 4480s budget) or wedges. CHECK scratchpad/run_fh.log + autocapture_fh.log FIRST next session.

## STRATEGIC CONCLUSION (dir_reuse@32/caw is contention-limited on ONE hot dir ino=131)
The single shared directory gets create(50 files×32 nodes)+rm-rf+verify each round. The dir EX lock can't hand off fast enough: P15-REL-ABORT (xfs_mxfs_dlm.c:12056) keeps aborting the release when the local workload re-acquires during the drain (gen_moved) or orphan-clock resets (orph). fair_handoff (defer FRESH local acquirer to a pending peer ticket) helps but the ABORT still fires because it's not just fresh acquirers — it's in-flight re-acquires and the orphan case.

## NEXT STEPS (priority order)
1. **Check if the fair_handoff run reached r24** (run_fh.log). If PASS → make caw_fair_handoff=1 DEFAULT (dlm_caw.c:88 `int mxfs_caw_fair_handoff = 1;`), rebuild, verify PLAIN run@32 + re-verify 2/4/8/16 caw don't regress. CRITERIA MET if all pass.
2. If it stalled <r24: **fix the release-abort site directly** (xfs_mxfs_dlm.c:12056). Make the abort STARVATION-AWARE: when a peer BAST has been pending > X ms (a peer starving), do NOT abort on local re-acquire/orphan — instead PROCEED with the release (hand off), and make the local re-acquire re-BAST after. I.e., BAST-priority over local re-acquire when a peer is starving. This is the root fix for wedge#3. Combine with fair_handoff.
3. **Reduce per-create lock hold**: the durable_signal (xfs_inode.c:2195, per-create publish-flush) holds dir EX while doing sync bwrite — that's WHY each create holds ino=131 long → contention. Making it faster/async-with-barrier would cut contention (but wedge#2a lost-wakeup lurks there — P-IOWAIT-STUCK probe in build 0349484E catches it).
4. **Hard-hang** (separate, reproducible spinlock deadlock): autocapture.sh auto-injects NMI on next occurrence → serial stack in autocapture_*.log. Fix the lock-lifetime bug.

## BUILD/STATE
- Build in tree: **0349484E48664B480423690 (VERSION 0.10.51)** = orphan fix + P-IOWAIT-STUCK probe (pal/linux/xfs_buf.c xfs_buf_iowait). KEEP.
- run.sh convergence gate parallelized (converges 6-9s now). tests/: drc_wedge_capture.sh, drc_hardhang_capture.sh, drc_autocapture.sh (autonomous NMI capture), drc_progress_watch.sh.
- All 32 nodes have unknown_nmi_panic=1 (/etc/sysctl.d/99-mxfs-nmi.conf) for hard-hang capture.
- MXFS_DEV=/dev/mapper/mpatha. Budget 140*32=4480s. Never rebuild while a run is active.
- See sess5 memories: COMPREHENSIVE-STATE, WEDGE2-FRESH, WEDGE3-release-abort, HARDHANG, durable0-fairhandoff-FAILED.
