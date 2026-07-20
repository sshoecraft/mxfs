---
name: sess34-WIN-newtenure-evict-plus-bli-retire-passes
description: sess34: dir_newtenure_evict=1 + BLI-retire = dir_reuse 4/5 PASS (was ~50%). Residual 799 = TRYLOCK-skip gap. Per-block prior-tenure evict+retire buil…
metadata:
  type: project
---

## sess34 — BIG progress on dir_reuse 8/tcp. CRITERIA NOT MET (4/5, need 100%).

### THE FIX (xfs/xfs_mxfs_dlm.c mxfs_dir_evict_data_blocks): NEW-TENURE force-evict + BLI-RETIRE.
At the first modify of a new cross-node tenure (new_tenure = master dir epoch advanced) the undestaged keep-clause is bypassed → stale prior-tenure base force-evicted (DONE cleared → cold re-read). sess26 set dir_newtenure_evict=0 because clearing DONE left a ZOMBIE in-AIL BLI that reflushed the stale image → readdir=0. **sess34 FIX = RETIRE that BLI** (xfs_buf_item_done) at the new-tenure evict — loss-safe because at new_tenure the block is durable (Inv 1).

### RESULT (build B191F20A, `drc_repro_loop.sh 6 "dir_newtenure_evict=1" 24`): **4/5 PASS** (iters 1-4 PASS 8/8, NO readdir=0, NO shutdown). iter 5 FAILED round 13 readdir=799 lookup_fail=0 (clean single-dirent loss). So the loss freq dropped ~50%→~20% but NOT eliminated.
- RESIDUAL ROOT: new_tenure fires only on the FIRST evict-call of a tenure; a stale base XBF_TRYLOCK-skipped on that call (P36-EVICT-LOCKED, transient in-flight I/O) escapes — on later calls new_tenure=false so the undestaged keep-clause preserves it → RMW'd stale → 799.
- NOTE iter5 was slow (~7.5min vs ~5 for others); watch RULE-0 budget (dir_reuse N>4 = 480s in run.sh). Could be incidental to the failure.

### PER-BLOCK ENHANCEMENT (build 2EAA0090, default-on, BUILT BUT UNTESTED): close the TRYLOCK gap.
1. On the new_tenure FIRST call ONLY, sync `i_dlm_dir_valid_epoch = cur_mep` (master epoch) BEFORE any modify — so every this-tenure-touched block stamps b_mxfs_dir_epoch == cur_mep (avoids the sess26 readdir=0 trap of syncing mid-tenure).
2. Undurable keep-clause: a block with `b_mxfs_dir_epoch < cur_mep` (prior-tenure stale base) bypasses the undestaged keep → force-evicted on ANY evict call (catches TRYLOCK-skipped blocks on retry).
3. Retire broadened: fires on `new_tenure || (b_epoch < cur_mep)`.
SAFE because valid_epoch==cur_mep all tenure (cur_mep can't advance under continuous EX), so current work (b_epoch==cur_mep) is NEVER flagged; only genuine prior-tenure (b_epoch<cur_mep) is.

### dir_newtenure_evict NOW DEFAULT 1 (src). Inert for shortform dirs (return-true early) + single-node → 1/tcp + tcp_dlm_scaling unaffected.

### NEXT SESSION:
1. Deploy 2EAA0090, run `drc_repro_loop.sh 8 "" 24` (BARE, no modarg — newtenure_evict now default-on) — confirm dir_reuse 8/8 across many iters (aim 8/8+).
2. If reliable, run BARE full suites: `./run.sh 1 tcp`, `2 tcp`, `4 tcp`, `8 tcp` — ALL 100% (the criteria). Watch tcp_dlm_scaling + broad 8-node flakiness + dir_reuse timing (RULE-0 480s).
3. If 799 persists, the TRYLOCK-skip may need a per-block retry-until-evicted, OR the master epoch (dg_shadow) reads 0 occasionally (sess23) → new_tenure under-fires; instrument P34-NEWTENURE-RETIRE + P36-EVICT-LOCKED on the losing round.
REFUTED this sess (don't retry): epoch-skip at drain (loss block is current-tenure there); drain-side graft/merge even with removed-set + global in-core dedup (801 cross-disk-block dup — can't verify global uniqueness without reading all disk blocks). See [[sess34-REFUTED-drain-graft-pivot-newtenure-evict-retire]] [[sess34-HEAD-removed-set-drain-merge]].
</body>
