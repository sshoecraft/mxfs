---
name: compiled-harness-liveness-grading-rig-restoration-and-standalone-env-traps
description: Harness traps: grade survivor liveness on return in its own domain, restore rig on every exit, export MXFS_DEV for standalone QNAP runs.
metadata:
  type: feedback
tags: [compiled, harness, measurement-integrity, rig, recovery-blocked]
---

Three harness traps that make a run FAIL or burn its budget without the product being at fault. Each produced a verdict that looked like a defect and was not.

## 1. Survivor liveness: touch a domain the survivor owns, grade the return, not the success

[[trap-grading-a-survivors-liveness-with-an-operation-in-the-dead-nodes-domain-measures-the-designed-fail-fast]] (s83, fencing-refusal verification). A check "does the prover still serve after refusing?" did `mkdir -p /mnt/shared/<new>` plus a write and FAILed rc=1. The log line was `P240-QUAR-NSOP-REFUSE op=lookup ino=128 comm=mkdir rc=-5`: the inode belonged to a node whose recovery was BLOCKED, and refusing fast before any transaction is the designed behaviour (the alternative is waiting out an acquire budget).

- "Can the survivor do work?" is asked in a domain the survivor took BEFORE the cut: create the directory and fsync a file into it while healthy, write into it afterwards. With the dead node's domain blocked this returned rc=0 in under a second.
- "Did anything hang?" is the graded question, and it is graded on the operation RETURNING: `timeout N` kill (rc 124) is a hang, any other rc is not. Whether it succeeded is a FINDING to print, since availability cost depends on which domain the caller touched.
- Grading success instead of return converts a designed fail-fast into a failure, and the reflex "loosen the assertion" is how a real hang later passes the same check.

## 2. A harness that takes the rig down restores it on every exit

[[trap-a-lap-that-exits-early-after-destroying-the-victim-bills-the-next-lap-for-a-powered-off-node]] (s82, `fence_gate_basis.sh`). A non-vacuity check between `virsh destroy` and the restart exited VACUOUS, so test2 stayed off. The next lap spent 48 polls x 5 s = 240 s in `waitboot` on a powered-off node, then `prep_cluster` had to power-cycle it and the lap hit the caller's 580 s timeout at the files stage with a 0-byte `B_files.txt`. A budget failure with no product in it, manufactured by the previous lap's exit path.

- Set a flag at destroy, clear it at restart, `trap` a restorer on EXIT; this covers FAIL, VACUOUS, ABORT and the caller's timeout.
- Ask the hypervisor first: `virsh domstate` answers in milliseconds; if not `running`, start it and say so. Minutes of ssh polling is a budget leak, not a liveness check.
- Generalises: the exit paths that skip restoration are the failing ones, the laps whose evidence is needed next.

## 3. Standalone runs on the QNAP rig need MXFS_DEV exported

[[trap-domain-admission-matrix-defaults-to-mpatha-run-standalone-on-qnap-rig-needs-mxfs-dev-exported]] (sess517). `tests/domain_admission_matrix.sh` run by hand defaults `DEV=${MXFS_DEV:-/dev/mapper/mpatha}`; the chain script exports the QNAP by-path, a standalone call does not. Result: 9 FAILs, every row `MOUNT_RC=32 WALL=0 NOT_MOUNTED`, `REJOIN_RC=32`, no kernel refusal lines; about 8 minutes of laps wasted. test2 tried to mount mpatha while test1 was up on the QNAP LUN.

- Signature: ALL rows fail including the refusal rows (a real admission bug fails one or two), walls of 0 s, no kernel refusal lines. Not a product fault.
- Fix: the matrix header now prints `dev=`. Any `tests/*.sh` run by hand against the QNAP cluster needs `export MXFS_DEV=/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772-lun-0 MXFS_NODE_LIST=test1,test2` (same trap as the bare `run.sh` prep, sess513).

## Common thread

A FAIL is not a defect until the harness is shown to have measured the property: wrong domain, wrong device, or a rig left in a state by an earlier lap each produce a convincing failure. Check the harness's own preconditions (domain ownership, `dev=`, `domstate`) before reading the product.
