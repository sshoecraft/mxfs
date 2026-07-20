---
name: caw-multipath-matrix-progress
description: ccloop 186320ae caw-mpath matrix: sess6 infra fixes (superset teardown, hard converge gate, iscsi enable) → 2/caw green, 8/caw sweeping; build 57773C…
metadata:
  type: project
---

# CAW-on-multipath matrix (ccloop 186320ae) — progress + design log

**Criterion**: full `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw` matrix at N=1,2,4,8,16,32, all tests PASS. Modargs used throughout: `MXFS_EXTRA_MODARGS="dirwr=1 dirland=1"`.

## Build chain
- `656E89B4` (v0.6.5, sess5): FIVE fixes → 4/caw 17/17 + 1/caw 17/17 (see caw-v065-fix-chain-4caw-17of17).
- `57773CBD` (sess6, current): 656E89B4 + P124-ALLOC-REVERT probe gated instr-only (was dirwr||instr). P124's "no this-node-ahead content" premise is false for a sole-EX-holder under sustained load (no release → no destage → AIL legitimately ahead of disk); its dump_stack failed soak's clean-dmesg criterion on healthy traffic (P88 companion proved forward progression 33→34→35→36, disk catching up each step). LOG-ONLY change.

## sess6 infra root-causes (2/caw formation failure = 100% infra, NO kernel bug)
Forensics from live test1/test2 dmesg.streams (wall-clock correlated):
1. **Leftover higher-rung nodes**: 4→2 transition left test3/4 mounted+announcing → test2 discovered 3 peers, active_count=4 in a 2-node run → converge gate could never reach 2 → best-effort proceed → chaos + P131 self-fences.
2. **Silent step-1 cleanup failure**: run.sh prep teardown was fire-and-forget (`>/dev/null 2>&1 ... true`); test2's old mount survived (busy), passed the step-5 readiness check (same srcversion!), then test1 re-mkfs'd the LUN UNDER it → test2 ENOENT-everything, announced under OLD FS uuid; test1's fresh mount correctly ignored foreign-uuid announces → single_node=true. Mutual invisibility fully explained.
3. **Converge gate was WARN+proceed** → 17 garbage FAILs instead of one loud abort.

## sess6 harness/infra fixes (all in-tree)
- run.sh: TEARDOWN snippet (fuser -km + umount -f + rmmod, prints MXFS_CLEAN/MXFS_STILL_LOADED); prep step 0 tears down ALL running test VMs outside NODES (virsh list), power-cycles dirty ones; step 1 verifies teardown per in-run node and escalates via power_cycle_node() (virsh destroy+start + ssh wait + DEV wait); converge gate now HARD-FAILS (window 90+5N s, prints per-node membership on fail).
- tools/mxfs_sshpass.sh: ConnectTimeout=10.
- prep_node.sh: fuser -km before umount.
- **iscsid + open-iscsi were disabled on ALL nodes** — node.startup=automatic did nothing after power cycle (node came up with 0 sessions, no mpatha). `systemctl enable iscsid open-iscsi` applied on all 32 + mpath_up.sh now enables (not just restarts).

## Ladder status (criteria.json is source of truth)
- 1/caw 17/17 PASS, 4/caw 17/17 PASS (656E89B4, sess5).
- 2/caw 17/17 PASS sess6: 16 tests on 656E89B4 + soak on 57773CBD. Formation converges in ~9-13s.
- 8/caw on 57773CBD: 12/12 PASS through chunks 1-3 (precond, cache_coherency, dlm_fairness, posix_multi, mmap, strong_consistency, zero_silent_loss, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency); chunk 4 (dir_reuse 800s budget, dlm_lock_correctness, fence_during_write) in flight; then fault_netpartition + soak.
- 16/32: expect REAL work — early 32-node CAW observation was EUCLEAN+shutdown on ~20/32 (pre-fix-chain build though). verify_infra.sh multipath N: PR reports B_sees_resv=0 but ENFORCEMENT works (registrant ok, non-registrant blocked) — fence tests are the oracle.
- Known open non-blocker: mxfs_ili kmem-cache leak at rmmod ('Objects remaining' BUG line between runs, task #8).
- PLAN: 8 green → 16 → 32 → full-ladder rerun on ONE build → marker.
