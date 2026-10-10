---
name: compiled-release-claims-rig-capacity-and-config-naming-traps
description: Release claims need failure-mode tests; clyde VM capacity limits; caw/cawd/cawp key traps in defects queue and prose; timeouts as perf assertions; VM…
metadata:
  type: feedback
tags: [compiled, release, rig, clyde, defects, caw, mpath, timeouts]
---

Compiled from a topic group: what a release claim requires, how many rig VMs clyde can carry, how the CAW configuration names mislead the defect queue and release prose, and the timeout and VM-disposability directives.

## A release claim for a failure-surviving feature requires the failure to be tested

[[feedback-an-attachment-is-not-released-until-its-failure-mode-is-tested]] (0.90.43). All eight `{2,4,8,16}/{net/mesh,disk/caw}/mpath` boards passed 31/31 with each node on a dm-multipath map over two iSCSI portals. Both portals were addresses on the same host bridge and each VM had one NIC, so no row ever removed a path. Writing "released; path failover not verified" in the README was rejected. The user said mpath is not working until it is tested fully, because production users will test it.

- Applies to any attachment or redundancy feature: multipath, replication, redundancy, fencing. The happy path does not earn the claim.
- Build the real topology: independent NICs or networks per path, not aliases on one wire.
- Inject the failure under load. Verify failover AND failback, and that I/O is actually carried by the returned path.
- When a criterion says "boards pass on X", ask what a production user would do to X on day one and make it a suite row on X's columns before releasing.
- Documenting the gap is not a substitute for testing it when the claim is "released".

## Timing is a pass/fail property

[[timing-is-first-class]]. Timeouts are performance assertions, not safety nets.

- Budget = measured infra (boot, mkfs, mount, ssh) + workload at 2x the native-XFS equivalent. Set the Bash timeout to that budget, never a round number or the tool cap.
- A timeout is a FAIL even with zero errors. Kill it, record FAIL, diagnose the slowness as a first-class bug.
- 2x native XFS is the hard ceiling for workloads. Never widen a timeout or re-run with a bigger one to see if it finishes.
- After each healthy PASS, record the actual wall in `tests/criteria/TIMEOUT_BUDGETS.md` and tighten.
- Baselines: mkfs 0.6s, first mount 2.7s, later mounts 4.8s, umount 0.4s, VM power-cycle to ssh 40-50s, 4-node fresh_cluster_mount ~60s.
- Internal-timeout debt: barrier_wait 120s (should be <=15s) and MXFS_CAW_WAIT_TIMEOUT_MS=120s.

## Rig VMs and clyde capacity

- [[Test VMs are disposable]]: `virsh destroy` / `start` / rebuild of test1..test32 needs no permission (confirmed in the v0.3.4 session after a D-state self-deadlock on test2). The restriction applies only to the host (clyde and other production hosts).
- [[trap-32-idle-vms-running-exhausts-clyde-ram-harness-kills-background-tasks-shut-idle-vms]] (2026-09-05). 32 VMs left running at ~1.2-1.4 GB RSS each put clyde at 0 free and 20 of 23 GB swap used. Claude Code killed the session's background Bash ("running low on memory"), but the chain it launched survived as an orphan and died later.
  - Before a long background rig job, check `free -g`. If swap is in use, shut the VMs the job does not need (test1-test4 stay for the 2- and 3-node arms).
  - `virsh shutdown` (ACPI) did not complete on any of 28 VMs within 60 s, so `virsh destroy` was needed. Delegate this to a rig-runner.
  - Restart the VMs in batches of ~8, then use `scripts/mpath_up.sh up 32` as the readiness gate.
  - A killed wrapper does not kill its chain: check `tools/mxfs_pgrep.sh <script>` and attach a Monitor to the orphan's log. Do not relaunch on top of it.
- [[trap-the-host-fits-14-rig-vms-under-load-so-six-release-boards-cannot-run-at-once]] (corrected 2026-10-01). Rig VMs have Max 4 GiB with balloon Used 2.5 GiB and 4 vCPU (`virsh dominfo`). The earlier "14 VMs max" claim counted the balloon ceiling.
  - Memory: 28 nodes x 2.5 GiB = 70 GiB fits the 94 GiB host, until balloons are raised or platform sets are up at the same time.
  - The real limit is CPU: 28 x 4 = 112 vCPU on 56 cores. A fully parallel six-board run risks pace failures from host contention, since the boards grade pace. Throughput rows already take a host-wide lock.
  - Check `virsh dominfo <vm>` Used memory before sizing a parallel run. Do not quote the max.

## Configuration names: caw, cawd, cawp

The three CAW names are the rig's names for how the LUN is attached, not different transports. `caw` was CAW over dm-multipath, `cawd` was direct in-guest single-path iSCSI, and `cawp` was passthrough. `run.sh` maps `cawd|cawp` to `BASE_TRANSPORT=caw`.

- [[trap-a-defect-record-tagged-cawd-or-cawp-is-invisible-to-the-queues-caw-views]] (0.90.24). `blocks()` in `tools/defects.py` matches `dlm` exactly. A record added with `-D cawd` (the board name) was missing from `N caw` and `N caw --release`. The README said 9 records reach 4-node CAW and the true count was 10. A blocking record tagged this way would have passed the release filter unseen.
  - Pass `-D caw` for anything seen on a caw, cawd or cawp board, and `-D tcp` for TCP. Never copy the board's condition name into `-D`.
  - Before citing a per-configuration count, check that no record in `data/defects.json` carries `cawd` or `cawp`.
  - The opposite holds for `tools/criteria.py`, which wants the condition name (`4 cawd`). `4 caw` is a different, mostly empty column.
- [[trap-an-old-caw-key-is-the-multipath-rig-while-released-caw-was-cawd]] (0.90.37 key migration). Before 0.90.37, `N/caw` meant disk/caw/mpath, but every CAW release (0.90.7, 0.90.24, 0.90.36) was graded on `cawd` = disk/caw/direct. `scripts/rekey_invocations.py` mapped the README's `8 caw --release` to `8/disk/caw/mpath`, a configuration that was never released, and it had to be fixed by hand.
  - Map: tcp -> net/mesh/direct, cawd -> disk/caw/direct, caw -> disk/caw/mpath, cawp -> disk/caw/pass, tcpmp -> net/mesh/mpath (`data/configurations.json` retired_keys).
  - TCP history before 2026-09-26 ran on LIO/QNAP (XML-wired /dev/sda), not direct iSCSI.
  - Any mechanical translation of release-claim prose must be checked by hand.
