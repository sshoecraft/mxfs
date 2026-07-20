---
name: caw-ladder-fb0-progress-2-4-8-green
description: PROGRESS (sess3): fb=0 default flipped (build 9731510A). Validated at DEFAULT: 2/caw(8), 4/caw(15), 8/caw(14), 16/caw coherency(5) ALL PASS. Remainin…
metadata:
  type: project
---

## CAW ladder validation at fb=0 default — PROGRESS (sess3, 2026-07-07)

Default flipped `mxfs_dir_force_block` 1->0 (xfs_mxfs_dlm.c:7908), build **9731510A227FC38B877624F**
(carries light P-AGLOW probes in xfs_alloc.c — remove for the FINAL clean confirmation run).
Root fix rationale: [[caw-4node-RESOLVED-forceblock0-passes-all-three-tension-tests]].

### GREEN at fb=0 DEFAULT (run.sh recorded PASS, this session):
- **2/caw**: 8 coherency+dlm tests PASS.
- **4/caw**: 15 multi-node tests PASS (cache_coherency+zsl confirmed at DEFAULT no-modarg; rest via
  fb=0 modarg pre-flip: dir_reuse 336s, strong_consistency, posix_multi, mmap, crash, dlm_fairness,
  scaling_curve, dlm_scaling, rsync_paired, dlm_lock_correctness, dlm_membership, fence_during_write,
  fault_netpartition).
- **8/caw** at DEFAULT: 14 multi-node PASS (5 coherency + crash + dlm_fairness/scaling_curve/dlm_scaling/
  rsync_paired/dlm_lock_correctness + dlm_membership/fence_during_write/fault_netpartition).
- **16/caw** at DEFAULT: cache_coherency, strong_consistency, posix_multi, mmap_coherency,
  zero_silent_loss = 5/5 PASS 16/16.

So the coherency-corruption BLOCKER (this run's whole struggle) is SOLVED by fb=0 across 2/4/8/16.

### REMAINING for the criteria (1/2/4/8/16/32 caw 100%)
1. **16/caw** rest: dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired,
   crash_consistency, fence_during_write, fault_netpartition, dlm_lock_correctness (all fast, expect
   PASS — none force_block-sensitive; all passed at 8/caw). Nodes test1-16 up+ready.
2. **32/caw** full suite: boot test17-32, `scripts/caw_preflight.sh 32`, then run. INCLUDES the
   SEPARATE perf blocker dlm_scaling ([[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]] — iSCSI target
   read-command saturation; may still FAIL regardless of force_block; that's the last real risk).
3. **dir_reuse @ 8/16/32**: budget 140*N = 1120/2240/4480s > 600s foreground cap → run in BACKGROUND
   (run_in_background=true), ONE run.sh at a time (VM/LUN conflict). fb=0 dir_reuse PROVEN correct @2/4;
   8+ is a TIMING check only.
4. **1/caw** single-node suite. 5. single-node coord=none cells (posix_single/fsx/fio_verify/
   integrity_filetypes/fio_perf/fault_enospc/soak) per N as the matrix needs.
6. **FINAL**: remove P-AGLOW probes (xfs/libxfs/xfs_alloc.c: the P-AGLOW-ALLOC block before P-DBLALLOC
   in xfs_alloc_vextent_finish, + the P-AGLOW-FREE block in xfs_free_ag_extent), rebuild, ONE clean
   full-ladder confirmation at DEFAULT. Then rev version per CLAUDE.md and write the criteria marker.

### Infra workflow that works
Boot testN in parallel (`virsh -c qemu:///system start`), `sleep ~55`, `scripts/caw_preflight.sh N`
(restores /src+iSCSI+mpath, verifies READY), THEN `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw <tests>`.
Do NOT let run.sh boot many shut-off nodes itself (sequential power_cycle ~180s each = too slow).
</body>
