---
name: sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage
description: sess5(run6614) MILESTONE build 59784327: FULL ./run.sh 2 tcp = 17/17 PASS at DEFAULT force_block=1 (salvage fix + gated diagnostic dump_stack). cache…
metadata:
  type: project
---

## sess5 (run 6614) — 2/tcp GREEN at tree-default force_block=1

Build **59784327**. `./run.sh 2 tcp` (bare, DEFAULT force_block=1) = **17/17 PASS**. All: cache_coherency, dir_reuse_coherency, crash_consistency, dlm_*, fault_netpartition, fence_during_write, mmap, posix_multi, rsync, scaling, soak, strong_consistency, tcp_dlm_scaling, zero_silent_loss.

### Two changes that got here (both KEEP):
1. **Undestaged cold-read SALVAGE** (xfs_da_btree.c, F8444712): restore XBF_DONE on an in-core dir DATA buffer that is undestaged + self-owned + not stale, instead of cold-reading stale/foreign disk. Fixes the ~50-session deterministic cache_coherency@fb1 shutdown. See [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]].
2. **soak dump_stack gate** (pal/linux/xfs_buf.c): gated P-DIRSTALE + P-DIRFREE diagnostic probes' `dump_stack()` behind `mxfs_instr_enabled`. They emitted "Call Trace:" during normal ops, which soak's dmesg-scan (DPAT includes 'call trace') counted as errors → false FAIL. NOT a real bug — pure diagnostic noise. Now soak PASSES.

Also kept: Fix A (drop `!in_ail` from xfs_da_btree keep-guard bypass, complements salvage) and P-DBLALLOC-AGF probe (xfs_dir2_data.c, harmless FUA compare).

### NOTE: 2/tcp now passes at BOTH force_block settings (fb0 was sess4's 17/17; fb1 now also 17/17). The salvage removed the force_block tension for 2 nodes. Tree default stays fb1.

### NEXT: run full 4/tcp then 8/tcp (salvage should fix dir_reuse@4/8 — same undestaged-coldread mechanism). Then 1/tcp tooling residuals (online_resize/dkms_install/fault_io_error). Criterion = 1/2/4/8 tcp all 100%.
See [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]] [[sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision]]
