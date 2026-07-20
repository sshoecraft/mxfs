# MXFS Cluster Orchestration Scripts

Higher-level scripts for cluster management, session-level test
harnesses, and dev-host orchestration.  Distinct from:

- `tests/single/`, `tests/cluster/`, `tests/stress/` — individual
  test scripts (per-feature, run by `tests/run_tests.sh`)
- `tests/decision_reproducers/` — per-spec-decision reproducers
  (D8 per-AG AIL drain, v6a H1 metadata amortization, etc.)
- `bench/` — performance benches (rsync_bench, etc.)
- `tools/` — userspace utilities that ship with MXFS (mkfs_mxfs,
  chk_mxfs, resize_mxfs, fua_verify, caw_verify, mxfs_sshpass.sh,
  prep_*.sh)

These scripts live in the source tree per `CLAUDE.md` RULE 3
(persistent scripts must survive cluster reboots).  Earlier sessions
kept them in `/tmp` and burned cycles re-creating them after
reboots.

## Inventory

### `cluster_reset.sh`

Hard reset of the test cluster: unmount, rmmod, fresh insmod, mkfs
on test1, mount on test1 then test2.  Handles transient `rmmod-busy` via
8× retry with 10s sleeps.

```
scripts/cluster_reset.sh
```

Hardcoded for the current 2-VM test cluster:
- test1 = 192.168.120.186
- test2 = 192.168.120.182
- device = /dev/sda
- mountpoint = /mnt/shared
- module path = `/mnt/mxfs-src/mxfs.ko` (NFS mount on the VMs)

### `stress_session.sh`

Session-level stress harness (sess23-fixed).  Runs N iterations of
cross-node `dd` workload at MB size, requires both `T1_DD_OK` and
`T2_DD_OK` markers per iter, scans dmesg for failure markers
(`Internal error`, `SHUTDOWN`, `Corruption`, `Free inode`,
`RIGHT-FAIL`, `LEFT-FAIL`, `disk lock acquisition timed out`, etc.),
auto-fails if peer crashes.

```
scripts/stress_session.sh <iters> <mb_per_iter>
scripts/stress_session.sh 15 256       # the canonical 15×256MB run
scripts/stress_session.sh 5 512        # smaller variant
```

Wrapped by `tests/decision_reproducers/d8_per_ag_ail.sh`.

### `stress_session_4node.sh`

4-node variant added in sess29 for TCP stress.  Same logic as
`stress_session.sh` but takes a node-list argument and runs
dd+rm in parallel across N nodes.

```
scripts/stress_session_4node.sh <iters> <mb> [node_ip...]
```

Defaults to test1, test2, test3, test4 if no node list provided.
Relocated from `/tmp/mxfs_stress_4node.sh` in sess31.

## Other /tmp scripts not yet relocated

`/tmp` still contains additional MXFS scripts from prior sessions:

- `mxfs_p0_bench.sh` (sess29 Phase-0 fio bench)
- `mxfs_stress_batch.sh`, `mxfs_stress_no_drop.sh` (stress variants)
- `mxfs_dirstress.sh`, `mxfs_diropts_v01.sh`, `mxfs_mkdir_test.sh`,
  `mxfs_mkdir_test_verbose.sh`, `mxfs_root_only.sh`,
  `mxfs_buga_mkdir.sh`, `mxfs_buga_stress.sh` (older bug reproducers
  / debugging harnesses)
- `mxfs1_*` (5 files — mxfs.1-era; properly belong under
  `~/src/mxfs.1/` if still load-bearing for that line)

These should be audited and either relocated to `scripts/` or
`bench/` per RULE 3 if still in use, or deleted if obsolete.
Sess31 did not do this scrub because the bench was running and
breaking these scripts mid-run would be disruptive; sess32 should
do it before any reboot.

## Migration note (sess31)

Prior to sess31 these scripts lived in `/tmp/mxfs_cluster_reset.sh`
and `/tmp/mxfs_stress_v033.sh`.  Copies remain at the old paths as
of 2026-05-07 for backward compat with any external callers; the
canonical location going forward is here.  Remove the `/tmp` copies
once all callers have been updated.

References updated in sess31:

- `/src/mxfs/CLAUDE.md` Test-environment section
- `/src/mxfs/tests/decision_reproducers/v6a_h1_metadata_amortization.sh`
- `/src/mxfs/tests/decision_reproducers/d8_per_ag_ail.sh`
- `/src/mxfs/state.md` Test-environment section
