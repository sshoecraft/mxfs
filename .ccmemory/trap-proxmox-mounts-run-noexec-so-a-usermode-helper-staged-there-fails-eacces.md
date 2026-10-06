---
name: trap-proxmox-mounts-run-noexec-so-a-usermode-helper-staged-there-fails-eacces
description: TRAP (0.90.76): a test wrapper in /run on a PVE host never ran: /run is noexec, the module's upcall failed P-DRBDW-NOEXEC rc=-13 at once. Use /dev/sh…
metadata:
  type: feedback
tags: [proxmox, drbd, testing, usermode-helper]
---

**What happened.** `tests/pve_cas_witness_stall.sh` pointed the module's `drbd_witness_helper` at a slow wrapper script written to `/run/mxfs-slow-witness` on pve9-1. The control arm "failed" in 2 s with `P-DRBD-CAS-PEER-NOT-EXCLUDED why='' quiescent=''`, the kernel log held `P-DRBDW-NOEXEC helper='/run/mxfs-slow-witness' mode=recheck rc=-13`, and nothing was slowed: the run tested nothing.

**Why.** Proxmox VE 9 mounts `/run` as `rw,nosuid,nodev,noexec`. `call_usermodehelper` (and any exec) of a file there returns -EACCES immediately. `/dev/shm` is `rw,nosuid,nodev` (exec allowed).

**How to apply.**
- Stage anything a host must EXECUTE (usermode-helper wrappers, test helpers) in `/dev/shm` or on the root fs, never `/run`.
- A test that swaps in a helper must also assert the helper actually ran (count `P-DRBDW-NOEXEC`, or have the helper leave a mark); a fast "verdict" with empty reasons is the signature of an exec failure, not of the code under test.

Provenance: session of 2026-10-06, run d6c5d48b, the 0.90.77 witness-skip verification.
