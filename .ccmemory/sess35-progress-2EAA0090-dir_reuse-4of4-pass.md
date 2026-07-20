---
name: sess35-progress-2EAA0090-dir_reuse-4of4-pass
description: sess35: build 2EAA0090 (per-block prior-tenure evict+BLI-retire, dir_newtenure_evict default-on) — dir_reuse 8/tcp loop 4/4 PASS so far, clean. Next:…
metadata:
  type: project
---

## sess35 — deploying sess34's 2EAA0090 build for the dir_reuse 8/tcp criteria.

### Build under test
- srcversion `2EAA009009BEA7F6231D9A9`, deployed+confirmed on all 8 nodes (test1/4/8 checked), `dir_newtenure_evict=1` (default-on).
- The fix: per-block prior-tenure evict + BLI-retire in `mxfs_dir_evict_data_blocks` (xfs/xfs_mxfs_dlm.c ~3819 prior_tenure clause + ~4012 P34-NEWTENURE-RETIRE). Closes sess34's TRYLOCK-skip gap (residual 799 at iter5).

### Result so far (`tests/tcp/drc_repro_loop.sh 8 "" 24`, bare/default-on, started 14:47)
- iter1 PASS 8/8, iter2 PASS 8/8, iter3 PASS 8/8, iter4 PASS 8/8. **4/4 PASS** (sess34's B191F20A was 4/5, failed iter5). iter5 running at 15:11.
- NO FS-corruption markers on nodes (checked test1/2/8: no EFSCORRUPTED/EFSBADCRC/forced-shutdown/lookup_fail). The `dmesg | grep shutdown/Corruption` hits are ONLY rmmod-time slab leaks ("Objects remaining in mxfs_ili/mxfs_inode on __kmem_cache_shutdown") + "scsipr unregister on shutdown failed" — module-teardown noise, NOT test failures. (Pre-existing cleanliness bug: ili/inode objects leak at module unload.)

### Recorded criteria baseline (showstat.sh)
- 1/tcp = 16/16 PASS, 4/tcp = 17/17 PASS, 8/tcp = 16/17 PASS (only dir_reuse PENDING), 2/tcp = 0/17 (all PENDING, needs a run).
- So the ONLY 8/tcp blocker is dir_reuse (being validated now); 2/tcp needs a fresh full run.

### NEXT (this/next session)
1. Confirm dir_reuse loop reaches 8/8 (or strong majority) — if iter5+ stays PASS, the per-block fix beat sess34.
2. Run `bash tests/run_criteria_tcp.sh "1 2 4 8"` (NEW this sess, clean-reboots each cond then ./run.sh + showstat) for the 100% criteria. Watch tcp_dlm_scaling + broad 8-node flake + dir_reuse 480s budget (RULE-0).
3. If 799 recurs: prime suspect is `cur_mep==0` from `mxfs_dlm_grant_dir_epoch` (dlm/dlm.c:2383 returns 0 if no locally-owned GRANTED lock for the dir or dir_epoch stamped 0) which disables BOTH new_tenure and the per-block prior_tenure check (both require cur_mep!=0). Instrument cur_mep at the losing round (P26-NEWTENURE-EVICT / P36-EVICT-LOCKED).
See [[sess34-WIN-newtenure-evict-plus-bli-retire-passes]].
</body>
