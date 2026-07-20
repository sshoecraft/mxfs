---
name: sess-testinfra-2node-harness-validated-and-crash
description: 2-node TCP harness (run.sh + MQTT coord.sh) VALIDATED; first run caught real kernel crash: do_open NULL-deref (-EISDIR) on single→multi create.
metadata:
  type: project
---

## What was built (2026-06-14, test-infra continuation)
- `tests/suite/coord.sh` — MQTT coordination primitive (broker 192.168.1.149).
  `coord_barrier/put/get/signal/wait/done`, retained-topic, director-free,
  race-free. Harness sets `MXFS_COORD_BROKER/PREFIX`, `MXFS_RANK`, `MXFS_NODES`.
  Sourced automatically by `tests/suite/lib.sh` (no-op at N=1). RANK exposed in lib.sh.
- `run.sh <N> <dlm> [test...]` — conditions-runner. Preps cluster (prep_fs on
  node1 + prep_node on all N), builds applicable test list from criteria.json
  (transport + min/max_nodes), runs coord=none on node1 / coord!=none on ALL N
  with per-test MQTT namespace, aggregates (PASS iff every node PASS), records to
  criteria.json keyed `<N>/<dlm>` + writes `.last_run.json`. Clears coord prefix
  before/after via `mosquitto_sub --remove-retained`.
- `tests/suite/cache_coherency.sh` — agnostic node-side test folding the 4
  historical subtests (cross_visibility, cross_write_read, rename_visibility,
  unlink_visibility) lifted from tests/cluster/test_*.sh, using coord_barrier
  instead of the on-FS .mxfs_barriers dir (coordinating the FS test via the FS
  under test masks coherency bugs).

## VALIDATED: harness works. `./run.sh 2 tcp cache_coherency` prepped both
nodes (fresh mkfs + TCP mount), ran coordinated, aggregated, recorded FAIL.

## BLOCKER: deployed module crashes the kernel on basic 2-node create
- Built/loaded srcversion `305641B7700544E54EB4E60` (mxfs.ko built 2026-06-14
  10:16). instr=0 dirwr=0 — crash is NOT an instrumentation artifact.
- On test1 (forming node), right after test2 joins (single→multi transition),
  first file create: `P-CREATE-ERR1 dialloc/icreate err=1` → `P-CR62 ...
  verdict=disk-read-err/badmagic` → `BUG: kernel NULL pointer dereference
  address 0x1` in `do_open+0x60` (path_openat→openat), `RAX=0xffffffeb`=**-EISDIR**.
- Signature = inode-reuse TYPE-CONFUSION (garbage i_op/i_fop ≈0x1 after create
  hands out an inode whose on-disk cluster has bad magic / incoherent inobt at
  alloc). Core cache_coherency ship-blocker family (sess24 inobt-incoherent-at-
  alloc, sess72 type-confusion / xfs_setup_iops on S_IFMT change).
- The creating task is SIGKILLed; surviving node then hangs at first barrier
  → harness 300s TEST_TIMEOUT kill, both nodes empty output → FAIL 0/2 recorded.

## Source-tree state caveat
- Live `xfs/xfs_inode.c` (mtime Jun14 09:04, 5433 lines) is a HEAVILY
  INSTRUMENTED diagnostic build (sess73/sess132 ILOCK forensics, down_write_
  trylock+busy-spin replacing down_write_nested). `.sess129fix` (Jun10, 4898 ln,
  cleaner, plain down_write_nested) and `.backup` (Jun12) are OLDER checkpoints.
- `.criteria_results.json` shows cache_coherency PASSED 2026-06-13 under the OLD
  criteria harness with a DIFFERENT (now-overwritten) build. Only one .ko exists.
- No git allowed; yesterday's passing build is not directly recoverable.

## Harness improvement TODO (deferred)
- Fail-fast: when a node's launch returns with NO RESULT line, publish a coord
  abort so peers bail their barriers immediately instead of waiting COORD_TIMEOUT
  (120s) ×N barriers. Also tighten COORD_TIMEOUT to expected (~sub-second
  rendezvous) per RULE 0 — 120s is far too generous for a 2-node barrier.
</body>
