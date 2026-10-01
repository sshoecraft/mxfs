---
name: trap-a-test-injector-that-plants-state-owned-by-a-task-confounds-both-arms-when-the-task-exits-first
description: TRAP (0.90.37): injected demoter claims whose owner exited wedged/withdrew nodes in BOTH arms of an A/B; plant only where the owner provably returns.
metadata:
  type: feedback
tags: [rig, control-arm, injector, dlm, demoter]
---

## What happened

To A/B the demoter-bypass grant gate, a test-only injector planted a demoter
claim (`i_dlm_demoter = current`) when a task dropped an EX hold on a directory,
so that the task's next lock would meet the bypass with the grant gone.

Four laps of 8/net/mesh/direct (tests/stress_rmdir_mkdir_race.sh) were
confounded, each a different way:

1. **Planted for every user task.** Each `mkdir` exited at once, so its claim
   was never cleared. Releases of those directories stalled, peers timed out,
   and nodes withdrew in **both** arms. The audit never ran.
2. **Set at module load.** The budget was spent by `alloc_witness`'s `rm -f` in
   the audit phase, not by the load.
3. **Restricted to `rm`, consumed at its next lock.** The remover's **last**
   operation is the removal of a slot directory from the base, so the claims on
   the base directory still had dead owners. One control lap was corrupt, and
   the fix lap wedged (`P-INODE-WEDGE`) and withdrew. Both effects came from
   dead-owner claims, not from the gate.
4. **Task-structure reuse.** A dead owner's claim was presented 12 s later by an
   unrelated `mkdir` whose `task_struct` reused the address. The claim is a bare
   pointer compared with `current`.

## How to apply

- An injector that plants state owned by a task must plant only where that same
  task provably acts on the object again. Exclude the objects it touches last
  (here, the base directory, passed in by inode number).
- Arm the injector only for the load, after prep and before the audit: write it
  through sysfs on the node that runs the target task, and reset it when the load
  ends.
- After every lap, read the injector's own counters (planted, consumed, left)
  before reading the result. A lap whose injector fired outside the load, or
  never fired, measured nothing.
- A planted state with its own destructive side effects confounds both arms.
  When the fix arm fails the same way as the control arm, suspect the injector
  first.
