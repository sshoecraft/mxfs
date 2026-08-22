---
name: sess386-state-bounded-reserve-landed-clyde-wedged-again
description: sess386 END STATE: 0.19.24 built+in-tree (bounded CAW reserve + dialloc hygiene + P87 repair instrumentation); clyde host-wedged AGAIN (KVM soft lock…
metadata:
  type: project
---

## Where sess386 stopped (2026-08-21 ~09:15 CDT)

**Clyde wedged for the second time in 24h — DIFFERENT mechanism than sess385.**
This time: KVM vCPU threads (CPU x/KVM, pids ~171711-171714) soft-locked-up from
~09:05:34; `migration/49` stuck >387s in `multi_cpu_stop` (stop-machine never
completes) => RCU stalled (23 threads in synchronize_rcu via __fput), jbd2 on
root ext4 deadlocked in __wait_on_buffer with nvme IDLE, journald unkillable
after SIGKILL, taint `G B D W` (a prior oops + bad page predate the dmesg ring;
journalctl hangs so the first fault is unrecovered). Trigger window = the start
of `MXFS_FORCE_PREP ./run.sh 32 caw prep_cluster` for 0.19.24 (its virsh
destroys all timed out at 60s — virsh was already stuck when prep tried).
Host reset required (RULE 2: user's call). After reset follow
`rig-recovery-after-clyde-reboot-scst-mpath` + `trap-sudo-mpath-up-leaves-root-owned-passfile`.

## Build/tree state

- Tree = **0.19.24**, srcversion `F980E0442B751165FF31CA4`, builds clean, tools
  rebuilt. NOT yet deployed to any node (the wedge killed the prep).
- Fleet last ran **0.19.23** (`489E81B9493ED7386D5B428`).
- IMPORTANT post-reset: `make clean && make modules && make tools` before
  trusting artifacts (convention after interrupted work), then FORCE_PREP.

## What landed this session (all on NFS, safe)

1. **0.19.23 — bounded CAW reserve fix** (sess386 GPT ruling, see
   ccloop-c7ee71c6-sess386-GPT-ruling-bounded-caw-reserve-deadline):
   - caw_wait_for_grant/caw_lock_body take `deadline_ms`;
     `mxfs_dlm_caw_lock_deadline` exported; deadline checked AFTER each
     read+grant lap (grant-wins), exits via existing caw_drop_own_waiter;
     P-RESV-DEADLINE probe; poll clamped to remaining time.
   - v5_mount.c inode_lock_retries CAW branch honors retries (retries*1s
     deadline) — was silently unbounded ("no short-budget variant" hole).
   - xfs_dialloc_try_ag: -EAGAIN from xfs_dialloc_ag now exits via
     out_release (brelse AGI + immediate AG unlock) instead of leaking the
     locked AGI + deferred AG unlock into the rest of the create.
   - xfs_dialloc: 4 jittered re-sweeps (P-DIALLOC-SWEEP-RETRY) before ENOSPC.
2. **0.19.24 — P87-REPAIR-FAIL instrumentation**: every silent false-return in
   mxfs_p87_publish_repair now names its arm (imap/noincore/nolist/iflush/
   bwrite/reread-linked). Needed because TREATMENT lap showed repair failing.
3. run.sh: `local -A step_count=()` (+state_count, pc_count) — unset assoc
   array under set -u killed the whole sweep when a failing node had no step=
   breadcrumb (measured: lost a row's result).
4. tests/d385_publication_verify.sh: stepwise mode (D385_OUT + D385_STEP =
   arm_prep/arm_lap/arm_collect/verdict) for <10min foreground calls.
5. tests/suite/dirent_durability.sh: mkdir stderr captured into DD-MKDIR-RC.

## Measurement state (0.19.23, knob=1 TREATMENT, laps at 32/caw)

- Lap 1: 4/4 PASS. Lap 2: collapse REDUCED to 3 nodes (from 13-14 pre-fix) —
  test24/test25 died from the #361 family (P84-UNL-RELOAD-LIVE nlink=1
  cached=0), test32 secondary relfence wedge during their recovery (474
  facet 2).
- TREATMENT tally: heads=584 joint_ok=580 REPAIRED=1 **SPLIT=2** BADHEAD=2 —
  **the sess385 publication repair converts only ~1/3; 2 unrepaired splits
  were published (publish_refuse_unlock=0) and killed their readers.**
  The 3 P86-AGI-UNLINKED-PUBLISH events (test1 ino=637, test19 ino=20972123,
  test6 ino=8389018) all tries=3; no P129-CLSKIP for those inos, so the
  blocker is NOT xfsaild-visible ILOCK — the P87-REPAIR-FAIL arms in 0.19.24
  will name it. THAT is the next measurement.
- P-RESV-DEADLINE fired 113x in one lap — the bound engages; no minutes-long
  AGI holds observed post-fix; leg A of 474 looks closed (needs a clean A/B
  to claim, blocked on the split-publication kills).

## Next steps in order

1. (user) host reset; rebuild; scst_setup + mpath_up (as steve for passfile!)
   + FORCE_PREP on 0.19.24.
2. Repro TREATMENT laps; read P87-REPAIR-FAIL arms; fix the repair (or land
   refuse_unlock once repair converts ~all) => closes the #361 chain
   (D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN + -361).
3. Then d385 stepwise protocol end-to-end for the formal closure run.
4. 474: leg-A fix verification rides the same laps (expect 0 relfence wedges
   once splits stop killing nodes); facet-2 (recovery-aware fence) still open.
5. Evidence preserved: /src/mxfs/.evidence/sess386_ailfreeze_1313/ (gz
   kernlogs of the leg-A incident); /tmp/run_* dirs are LOST on reset.
