# MXFS Test Framework

Comprehensive correctness/perf test harness for MXFS, inherited from mxfs.1
and copied into v5 in sess28 alongside the architecture spec.

**Status as of sess30 (2026-05-07):** the framework is functional but
underused. Sess21–sess30 ran ad-hoc `/tmp/mxfs_stress_v033.sh` cross-node
dd loops and a one-off `/tmp/mxfs1_rsync_bench.sh` rsync sweep, NOT the
formal suite below. There is no measured baseline of which framework
tests currently pass or fail on v5. Establishing that baseline is itself
work to do.

## Architecture

Three-layer harness:

```
┌──────────────────────────────────────────────────────────────────┐
│ Dev host (this machine, e.g. clyde)                              │
│   tests/run_tests.sh   ← orchestrator (parses args, dispatches)  │
└────────┬─────────────────────────────────────────────────────────┘
         │ SSH (parallel) via tools/mxfs_sshpass.sh
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ Each test node (test1.vm.localdomain, test2..., testN...)        │
│   tests/mxfs_test.sh   ← per-node executor                       │
│     sources lib/common.sh  (assertions, logging, lifecycle)      │
│     sources lib/cluster.sh (barriers, mount checks, peer ops)    │
│     sources tests/<phase>/<test_name>.sh                         │
└──────────────────────────────────────────────────────────────────┘
```

Tests synchronize across nodes via file-based barriers in
`$MOUNT_POINT/.mxfs_barriers/<barrier_name>/`. Each node touches a marker
file; nodes wait until the expected count of markers exists.

## Test phases

Tests are grouped into three phases, by directory:

- `tests/single/` — single-node correctness (mount, basic file ops,
  symlinks, hardlinks, rename, permissions). Run on node 1 only.
- `tests/cluster/` — cross-node coordination correctness (concurrent
  writes/reads, dir-stress, visibility, sequential consistency, large-
  file integrity). Requires 2+ mounted nodes.
- `tests/stress/` — long-running endurance + contention (file_storm,
  metadata_storm, mixed_workload, throughput). Requires 2+ nodes for
  the cluster-level stress patterns.
- `tests/decision_reproducers/` — small focused scripts that prove
  individual spec decisions (`d8_per_ag_ail.sh`, etc.). Not part of
  the routine sweep.

## Prerequisites

- N test VMs reachable as `testN.vm.localdomain` (1-indexed) in the
  resolver. Currently configured: `test1.vm.localdomain`
  (192.168.120.186) and `test2.vm.localdomain` (192.168.120.182).
- SSH access via `tools/mxfs_sshpass.sh <host> <pass-file> <command>`.
  Pass file: `/home/steve/.mxfs/pass` (default) or `/tmp/.mxfs_pass`
  (used by ad-hoc scripts; identical content).
- NFS mount on each test node: `192.168.120.1:/src/mxfs` →
  `/mnt/mxfs-src/` so the test scripts in `tests/` and the kernel
  module `mxfs.ko` are reachable.
- Each test node has the shared block device the cluster mounts.
  On the current clyde+tcm_loop setup the device is `/dev/sda`
  (NOT `/dev/sdb` which is the framework's default — see Defaults below).
- Module loaded and FS mounted on all participating nodes BEFORE
  running the framework. Use `tools/mxfs_deploy.sh <host>` per node,
  or use the ad-hoc reset script `/tmp/mxfs_cluster_reset.sh`. The
  framework's `verify_environment()` checks that all expected nodes
  show `/mnt/shared` mounted; if any don't, the run fails up front.

## Defaults

`run_tests.sh` defaults that may need overriding for current setup:

| Param | Default | Override for current setup | Notes |
|---|---|---|---|
| `--nodes` | 1 | as-needed | Required for cluster/stress phases |
| `--phase` | all | single \| cluster \| stress \| all | |
| `--mount-point` | `/mnt/shared` | (correct) | |
| `--device` | `/dev/sdb` | **`--device /dev/sda`** | clyde+tcm_loop uses /dev/sda |
| `--pass-file` | `/home/steve/.mxfs/pass` | (correct) | |
| `--results-dir` | `/home/steve/.mxfs/results` | (correct) | |

## Running

```bash
# Smoke check: single-node mount test
./tests/run_tests.sh --nodes 1 --test test_mount --device /dev/sda

# Single-node phase (12 tests, all in tests/single/)
./tests/run_tests.sh --nodes 1 --phase single --device /dev/sda

# 2-node cluster phase (12 tests, all in tests/cluster/)
./tests/run_tests.sh --nodes 2 --phase cluster --device /dev/sda

# 2-node stress phase (6 tests, long-running)
./tests/run_tests.sh --nodes 2 --phase stress --device /dev/sda

# Specific test (auto-detected phase)
./tests/run_tests.sh --nodes 2 --test test_metadata_storm --device /dev/sda

# List all tests
./tests/run_tests.sh --list
```

## Test inventory

### tests/single/ (12 tests, run on node 1)

| Test | What it validates |
|---|---|
| `test_mount` | Mount point exists, type is `mxfs`, df/stat work |
| `test_write_read` | Write file, read back, content matches |
| `test_touch` | Create empty file, mtime/ctime set |
| `test_stat` | stat returns sane size, mode, links |
| `test_unlink` | Delete file, lookup returns ENOENT |
| `test_rename` | Rename within same dir, rename across dirs |
| `test_mkdir` | Create dir, removed correctly |
| `test_nested_dirs` | Deep dir trees, traversal |
| `test_symlink` | Create symlink, readlink returns target |
| `test_permissions` | chmod, chown, mode bits visible |
| `test_large_file` | Write/read multi-GB file |
| `test_many_files` | Create thousands of files in one dir (format transitions) |

### tests/cluster/ (12 tests, run on N≥2 nodes)

| Test | What it validates | Most relevant spec decisions |
|---|---|---|
| `test_concurrent_write` | All nodes write SEPARATE files, then md5 cross-verify each others' files | D6 (cache invalidation on acquire), D13 (reload-from-disk after unlock+relock) |
| `test_cross_write_read` | Node A writes 1MB, node B reads, md5 verify, round-robin | D6, D7 (FUA writes on metadata cross-release) |
| `test_concurrent_mkdir` | Concurrent mkdir from multiple nodes | D6, D11 (discard-not-flush on membership) |
| `test_concurrent_touch` | Concurrent touch from multiple nodes | D6, D9 (pinned-resource pattern) |
| `test_dir_stress` | Concurrent dir create/list/rename | D6, D9, D10 (BAST yield quantum) |
| `test_cross_visibility` | File created on A is visible on B | D6, D13 |
| `test_unlink_visibility` | File unlinked on A disappears on B | D6, D13 |
| `test_rename_visibility` | Rename on A visible on B | D6, D13 |
| `test_sequential_consistency` | Odd nodes write counters, even nodes verify final | D6, D7 |
| `test_large_file_integrity` | Multi-GB file written/read across nodes | D6, D7 |
| `test_discovery` | Multicast peer discovery completes | D5 (separable cluster code) |
| `test_tcp_mesh` | TCP DLM mesh forms (when transport=tcp) | D4 (CAW + TCP, auto-detect) |

### tests/stress/ (6 tests, run on N≥2 nodes, long-running)

| Test | What it validates | Most relevant spec decisions |
|---|---|---|
| `test_metadata_storm` | All nodes hammer SAME 50 shared files with stat/touch/chmod/readdir | **D6, D9, D10 — most direct cross-node DLM contention test** |
| `test_file_storm` | Each node creates/deletes 200 files × 5 rounds (separate dirs) | D6, D8 (per-AG AIL drain) |
| `test_throughput` | Each node writes 50MB sustained | D8, D12 (eager flush) |
| `test_mixed_workload` | mkdir/rename/delete cycles in own subdir per node | D6, D9 |
| `test_large_dir` | One node creates many files in a single dir | Format-transition path; same as mxfs.1's dir_cache bug class |
| `test_many_dirs` | Many small dirs across nodes | D6, dir-cache invalidation |

### tests/decision_reproducers/

Focused scripts proving individual spec decisions:

- `d8_per_ag_ail.sh` — D8 per-AG AIL drain on AG token release.

## Performance benches (separate from correctness tests)

The framework above tests **correctness** (PASS/FAIL outcomes via assertions
and md5 verification). For perf benches with paired XFS/mxfs comparisons,
use the rsync bench:

- **`/tmp/mxfs1_rsync_bench.sh`** — paired XFS native / mxfs.1 / v5
  rsync sweep. Pre-staged source trees on each node:
  - test1: `/root/open-gpu-kernel-modules` (584M, 8137 files, 628 dirs)
  - test2: `/root/element-web` (584M, 4385 files, 971 dirs, deep nesting)

  Per-iter integrity: file count match + rollup md5 match against a pre-
  computed manifest (`/root/<tree>.manifest`, rollup md5s captured in
  `~/src/mxfs.1/docs/rsync_bench.md`).

- **`~/src/mxfs.1/docs/rsync_bench.md`** — full methodology document:
  why rsync, source-tree fingerprints, configurations (xfs_native /
  mxfs1_1node / mxfs1_2node), per-iter measurement protocol, dmesg
  pattern for failure detection.

This bench is the most informative one we have for cross-node metadata-
heavy behavior. Sess30's 4-test sweep with this bench (XFS / v5 1-node /
v5 2-node parallel) revealed the FUA-on-acquire architectural ceiling
that single-node tests and bulk-dd tests had been missing.

The rsync bench should be promoted into `tests/stress/` in a future
session so it runs as part of the formal suite.

## Tests-to-decisions matrix (summary)

| Spec decision | Tests that validate it |
|---|---|
| **D1** symmetric peers | All cluster/stress tests (no master-node dependency) |
| **D2** fork XFS, add cluster hooks | All single tests (XFS format compat); `xfs_repair` post-test |
| **D3** multi-class tokens | Not yet exercised (Phase 6 spec, not implemented) |
| **D4** CAW + TCP transports | `test_discovery`, `test_tcp_mesh`, transport-flag stress runs |
| **D5** layered cluster code | `test_discovery` (cluster code separable) |
| **D6** explicit cache invalidation | All cluster + stress tests |
| **D7** FUA writes on cross-release | `test_cross_write_read`, `test_sequential_consistency`, rsync bench |
| **D8** per-AG AIL drain | `decision_reproducers/d8_per_ag_ail.sh`, `test_throughput` |
| **D9** pinned-resource | `test_metadata_storm`, `test_concurrent_touch` |
| **D10** BAST yield quantum | `test_metadata_storm`, `test_dir_stress` |
| **D11** discard-not-flush on membership | `test_concurrent_mkdir`, mount/unmount sweeps |
| **D12** eager flush | `test_throughput`, sustained workloads |
| **D13** reload-from-disk after unlock+relock | All cross-* visibility tests |
| **D14** three-layer fencing | Not directly tested by suite (would need fault injection) |
| **D15** per-node journal slots | Not directly tested (would need crash + replay) |
| **D16** root-cause SCSI passthrough | Not testable in suite — engineering task |

## Known gaps in framework as of sess30

1. **No measured pass-list baseline for v5.** Every test in the table
   above has unknown current status. Establishing the baseline is a
   one-session job: run each phase against current v5 (caw_path=1
   default) and record results.
2. **`/dev/sdb` default is wrong for current setup.** Always pass
   `--device /dev/sda` until the default is updated. Related: should
   be probed at runtime rather than hardcoded.
3. **The most informative bench (rsync) lives in `/tmp/`, not in the
   tree.** Should be promoted to `tests/stress/test_rsync_bench.sh`
   with a wrapper that fits the framework's barrier/result protocol.
4. **No CI integration.** Tests are manual.
5. **Some inherited tests may have mxfs.1-era assumptions** (e.g.,
   mxfs.1 had a userspace daemon `mxfsd`; v5 doesn't). Each test
   needs to be sanity-checked once the baseline run happens.
6. **`mxfs_bench.c` (DLM lock latency benchmark) talks to mxfsd
   ctrl socket via `/var/run/mxfsd.sock`** — this is mxfs.1-era and
   doesn't apply to v5. Either retarget to v5's in-kernel DLM API
   or remove from v5 tree.

## Routine usage suggested for future sessions

Before claiming v5 is "fixed" on any workload class, run at minimum:

```bash
# Single-node correctness (must pass)
./tests/run_tests.sh --nodes 1 --phase single --device /dev/sda

# 2-node correctness (must pass)
./tests/run_tests.sh --nodes 2 --phase cluster --device /dev/sda

# 2-node stress (must pass for production claim)
./tests/run_tests.sh --nodes 2 --phase stress --device /dev/sda

# Perf bench paired against XFS native (run after correctness passes)
/tmp/mxfs1_rsync_bench.sh v5_baseline 192.168.120.186,192.168.120.182 3
```

The sess30 lesson is: ad-hoc cross-node dd stress is not enough. It
exercises bulk I/O paths but misses metadata-heavy and shared-file
contention paths. Both `test_metadata_storm` (shared files concurrent
ops) and the rsync bench (concurrent metadata-create) need to pass
before the next architecture decision is made.
