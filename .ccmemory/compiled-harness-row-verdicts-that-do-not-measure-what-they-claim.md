---
name: compiled-harness-row-verdicts-that-do-not-measure-what-they-claim
description: Five traps where a test row's verdict, exclusion or capture did not reflect the filesystem: unread rows, small-N geometry, reused mounts, failure-onl…
metadata:
  type: feedback
tags: [compiled, harness, vacuity, board, crash_consistency, node_death_replay]
---

Topic: test-harness rows whose verdict, exclusion or capture step did not reflect what the filesystem did. In every case a harness artefact was read as evidence. A PASS, a FAIL, or an exclusion from the board each needs the row's script, the probe counts and the artefact's lifetime checked before it is believed.

## 1. Do not exclude a row for what its comment says it does
[[trap-a-row-excluded-for-what-its-harness-supposedly-does-was-never-read]] (0.90.40). Five rows (`dlm_membership`, `crash_consistency`, `fence_during_write`, `fault_netpartition`, `soak`) were left off the DRBD board as "restart a killed node with a plain virsh start". None of them kills or restarts a node:
- `dlm_membership` and `fault_netpartition` only iptables-block DLM port 7600.
- `fence_during_write` injects nothing and asserts that no fence happens.
- `crash_consistency` only drops caches.
- `soak` has no fault at all.

The only `virsh destroy/start` on that path is the prep-time `power_cycle_node` in `run.sh`. A misleading `run.sh:542` comment is the likely source of the claim. Read what the row's script does before excluding it or calling it inapplicable. Real node-kill rows are `coord=host` (e.g. `node_death_replay`).

## 2. A harness FAIL below its designed N is not a filesystem verdict
[[trap-node-death-replay-row-unrunnable-below-32-nodes-slotmap-empty-and-32-node-geometry]]. At 4/caw on 0.70.18, `node_death_replay` failed in 3 s with `could not pick 2 victims of class 'shared'` and every node at `slot=?`. Two independent causes in `tests/tmpfile_churn_kill.sh` (~143-168):
- The slot map greps `disklock: claimed heartbeat slot N` from `journalctl -k --since -20min` and dmesg. The journal was flooded with `P291-EXWIN` probe lines, so no node had a slot. Fix direction: read the slot from sysfs or the disklock table.
- Victim classes are hard-wired to 32 nodes (`slot 7..24 = single`, everything else `shared`, `ag = slot % 25`). At N=4 every node is "shared". Victim selection must come from declared geometry.

A small-N board has zero death/replay coverage even when everything else is green. Do not file this FAIL as a replay defect.

## 3. A create workload re-run on an un-re-prepped mount measures overwrites
[[trap-rerunning-a-create-workload-on-the-same-mount-measures-overwrites-not-creates]] (chain 139). `crash_consistency` re-run with `create_cost_ms=1` on the mount a failed run had left behind PASSED in 23 s and 29 s of a 90 s budget. The `.crash_consistency/node<R>_f<i>` files already existed, so every `dd oflag=sync` was an O_TRUNC overwrite and not a shared-directory create. The probe that fires on every create >= 1 ms logged 102 lines on 9 nodes (leg A) and 1 line on 1 node (leg B), against about 3200 on 32 nodes expected. Leg B's in-tenure sample set was empty, so the A/B had no B side.
- A create-pace measurement needs a directory that does not exist yet: prep, or `CC_TAG=<word>` (puts the run in `.crash_consistency_<word>`).
- Compare the probe count to the planned population (3200) before reading any per-sample statistic. A count an order of magnitude low means the harness measured something else.
- The board runs `crash_consistency` right after `rsync_paired` on a fresh directory. A standalone re-run on the same mount is not the board condition.

## 4. A vacuity gate keyed on a failure artefact cannot score a pass
[[trap-anti-vacuity-gate-keyed-on-a-failure-artefact-refuses-to-score-a-pass]] (chain 126, the shared-directory vs `CC_PRIVATE=1` A/B). The gate declared a leg unscored when no new `tests/evidence/run_crash_consistency_*` directory appeared, but that directory is written only when the row FAILS. So the private legs, the ones expected to pass, were discarded. The captured output had the answer: private laps PASS 18 s and 19 s with 32/32 nodes and 204/204 checks; shared laps FAIL at 90/90 s with 0/32 nodes.
- A liveness gate must key on an artefact produced in every outcome. Ask whether the key exists when the result is the good one; if not, it is a pass-suppressor.
- The right key was `=== run @ 32/caw (run_id=<stamp>) ===`, which `run.sh` prints on every invocation. Fixed in `tests/sess480_chain126_cc_private_barrier.sh`: score on a fresh `run_id` plus a `nodes_pass` verdict row, and use the evidence directory only for parked/straggler detail.
- Anti-vacuity gates are code and need falsification like what they guard. A gate only ever exercised against failures has never been tested.
- Result recovered: `D-32NODE-SHARED-DIR-CREATE-PACE` (raised major to critical) owns the `crash_consistency` row. `D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401` loses that row as evidence without being disproved.

## 5. `timeout` around an unkillable step never returns
[[trap-timeout-around-an-unkillable-umount-never-returns-so-a-stall-capture-after-it-never-runs]] (0.90.14 and 0.90.16, 4/tcp chk_clean, twice). `timeout 60 umount $MNT` sends SIGTERM at 60 s and then waits for its child. An umount stuck in the kernel (`xfs_ail_push_all_sync`) never exits, so `timeout` never returned and the stall capture after it never ran. The 180 s row budget killed the node script and the run recorded `rc=124` with no output and no stack. `timeout -k` does not help, because SIGKILL does not end a task in the kernel either.
- Fix (`tests/tooling/chk_clean.sh`, 0.90.16): background the umount, poll `kill -0 $pid` against the script's own deadline, and capture while it is still in flight. Capture `/proc/<pid>/stack` of the umount task first, then xfsaild, the mxfs-* workers, kworkers with xfs/mxfs frames and D-state tasks.
- Do not wrap in `timeout` any step that can stick in the kernel (umount, mount, sync, a fenced node's I/O) if a later step must observe the stall.

## Common thread
Before trusting a harness result, check these four things:
- the row's script, not its comment or header;
- the geometry the row was written for;
- the freshness of the mount and directory it ran against;
- that every gate and capture step can execute on the outcome being hoped for or feared.
