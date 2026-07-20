# MXFS Test Suite — Design / Blueprint

**Status:** design spec (2026-06-14). No scripts yet — this is the blueprint the
test/harness/config scripts are built against. **Success = every test passes**;
there is no separate success-criteria doc (premature — not yet). Companion docs:
`TIMEOUT_BUDGETS.md` (RULE-0 per-criterion budgets), `docs/test_infra_lio_tcm.md`
(one concrete config stack), `docs/benchmark.md` (MQTT coordination protocol).

## 1. Goal

Validate MXFS **end-to-end** — substrate (shared LUN), DLM/transport, and the
filesystem itself — so that a failure localizes to a layer instead of surfacing
only as a vague top-level workload failure. The suite must be able to certify
correctness, data integrity, coherency, scale, performance-vs-native-XFS, and
robustness on 1..N nodes.

## 2. Layering — the central design rule

Three script families with a hard boundary between them. The boundary is what
keeps the test suite reusable across every infrastructure.

| Layer | Owns | Knows about |
|---|---|---|
| **Config** | transport + target stack, and per-OS setup: load `mxfs.ko` (with the chosen transport), `mkfs`, `mount` | `device`, `module`, TCP vs CAW, SCST vs LIO/tcm_loop |
| **Harness** | the *cluster* concern: which nodes participate, deploy/launch, MQTT coordination, result aggregation | `nodes`, broker address |
| **Test suite** | FS **validation only** | a **mount point** (+ an opaque coordination handle) |

**Inviolable rules:**
1. **A test script references only its mount point** (and coord calls). It never
   sees `device`, `module`, transport, target stack, node identity, or broker.
   Anything else is a layering violation.
2. **The transport "matrix" is achieved by configuration, not by test code.**
   The same agnostic test, run after the config layer sets up LIO+TCP vs
   SCST+CAW, *is* the matrix. A nice property falls out: e.g. `dlm_fairness`
   exposes the TCP straggler under a TCP config and shows balance under CAW —
   with byte-identical test code.
3. **Per-OS setup is the config layer's job**, never the test's. By the time a
   test runs, a healthy mounted FS exists.

### 2.1 Valid config combinations
Transport/stack are not free-form (see CLAUDE.md design tensions): CAW requires
SCST (LIO does not do CAW reliably); TCP runs on either.
- LIO/tcm_loop + TCP DLM  ← current build (`scripts/lio_tcm_setup.sh` + `wire_vms.sh` + `define_vms.sh` build the host/VM half)
- SCST iSCSI + CAW DLM
- SCST iSCSI + TCP DLM

## 3. The readiness contract

The config + harness layers must hand the test suite this exact state, and the
harness verifies it (skip-with-reason, never hang, if unmet):

- **R1** — N participating nodes each have MXFS mounted at the agreed mount point
  (`mount | grep ' <mount> type mxfs'`).
- **R2** — the mount is backed by the shared LUN (all nodes see the same FS).
- **R3** — required in-guest tools present for the tests being run (`fio`, `fsx`,
  `mosquitto_pub/sub`, etc.).
- **R4** — the MQTT broker is reachable (only required for coordinated tests).

Substrate pre-flights that belong to **config/harness, not the FS suite**
(they touch the raw device, pre-mxfs):
- LUN presented on every node (correct size / vendor / model / write-through).
- VM fleet uniformity (the `define_vms.sh` guarantee).
- **Raw cross-initiator coherency** — write a pattern from node A to a raw LBA,
  read it from node B (the sess36 `e1`/`e1b` check). If the *block layer* isn't
  coherent, no FS test result is meaningful. Run this before the FS suite.

## 4. Coordination primitive

Coordinated tests call one harness-provided primitive (backed by MQTT, broker
`192.168.1.149`, per the `docs/benchmark.md` `ready`/`go` protocol). Tests that
don't need coordination never call it.

| Call | Purpose | Used by |
|---|---|---|
| `coord_barrier(tag)` | rendezvous — publish `ready`, block until harness releases `go` | contention / scale tests |
| `coord_put(key,val)` / `coord_get(key)` | value-passing — A publishes a filename/LBA, B retrieves it | ordered A→B coherency tests |
| `coord_signal(evt)` / `coord_wait(evt)` | one-shot signal — A fires "fenced"/"fsync-done", B waits | fault-injection tests |
| `coord_done(status)` | report this instance's result for aggregation | all coordinated tests |

The harness owns broker address, node set, **per-run topic namespacing** (so
concurrent runs don't collide), the `go` release, and aggregation. A test body
still references only its mount point + these opaque calls.

### 4.1 Coordination classes
Every criterion is one of:
- **none** — pure single-mount; if run on N nodes, embarrassingly parallel (each in its own subdir), no cross-node ordering.
- **barrier** — all nodes must start simultaneously (real contention, or valid concurrency measurement).
- **ordered** — A does X, *then* B observes; a value is passed across.
- **fault** — a fault is injected mid-workload at a coordinated moment, then survivors are verified.

## 5. Criteria catalog

Status: ✅ have a verifier · ✏️ exists, needs update for agnostic/new-infra · ➕ new.
Each verifier encodes its own pass/fail threshold; timing budgets live in
`TIMEOUT_BUDGETS.md`. Not duplicated here.

### 5.1 Config / tooling layer (touch device/module — NOT the agnostic FS suite)
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `mkfs_timing` | none | ✅ | tool, on device |
| `chk_clean` | none | ✅ | fsck on unmounted device |
| `dkms_install` | none | ✅ | module build/install |
| `online_resize` | none | ✅ | currently offline-only |
| substrate pre-flights (LUN present, VM uniform, raw xinit coherency) | ordered | ➕ | §3; run before FS suite |

### 5.2 Agnostic FS suite — Correctness
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `posix_semantics` (1 node) | none | ✅ | |
| `posix_semantics` (N nodes) | barrier | ✅ | concurrency phase |
| `zero_silent_loss` | barrier | ✅✏️ | drop `--mode 1` CAW assumption |
| `cache_coherency` | barrier + ordered | ✅ | concurrent storm + visibility |
| `strong_consistency` | ordered | ✅ | A fsync → B reads immediately |
| `crash_consistency` | fault | ✅ | acked writes survive node death |
| `fence_during_write` | fault | ✅ | fence mid-write + journal replay |

### 5.3 Agnostic FS suite — Data integrity
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `integrity_fsx` | none | ➕ | random op + verify |
| `integrity_fio_verify` | none | ➕ | fio `verify=crc32c` |
| `integrity_filetypes` | none | ➕ | sparse/hardlink/symlink/xattr/large/many-small |
| `mmap_coherency` | ordered | ➕ | A mmap-write → B read |

### 5.4 Agnostic FS suite — Scale
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `scaling_curve` | barrier | ✅ | start-together for valid scaling number |
| `dlm_scaling` | barrier | ✏️ | was `tcp_dlm_scaling`; drop TCP/QNAP/per-initiator wording |

### 5.5 Agnostic FS suite — DLM behavior
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `dlm_lock_correctness` | ordered/barrier | ➕ | acquire/release/BAST/grant |
| `dlm_fairness` | barrier | ➕ | per-node throughput balance (straggler as a *measured* threshold) |
| `dlm_membership` | fault | ✅ | `online_membership`: join/leave while peers active |
| `dlm_journal_replay` | fault | ✅ | covered by fence/crash |

### 5.6 Agnostic FS suite — Performance (vs native XFS on the same LUN)
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `single_node_paired` | none | ✅ | mxfs ≤ ~5% over XFS |
| `rsync_paired` | barrier | ✅ | parallel start for aggregate |
| `cluster_ops_timing` | none | ✅ | mount/unmount in seconds |

### 5.7 Agnostic FS suite — Robustness / fault injection
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `wedged_unmount` | none/barrier | ✅ | unmount never wedges under load |
| `dmesg_clean` | none | ✅ | gathered per node |
| `soak` | barrier | ✅ | mixed concurrent workload over time |
| `fault_netpartition` | fault | ➕ | split-brain prevented under partition |
| `fault_io_error` | fault | ➕ | dm-error injection — sane reaction, no corruption |
| `fault_enospc` | none | ➕ | disk-full handling |

### 5.8 Lifecycle/ops (straddle config/harness)
| Criterion | Coord | Status | Notes |
|---|---|---|---|
| `lifecycle_mount_cycle` | none | ➕ | repeated mount/unmount stability/leak |
| `lifecycle_module_cycle` | none | ➕ | rmmod/insmod cycling (config-adjacent) |

## 6. Suite index & run order (the index)

The suite is driven by a **manifest** (the index) — a registry the runner reads
to know which tests exist and what order to run them in. Each entry declares:
`name, layer, coord-class (none/barrier/ordered/fault), phase (run order),
depends-on, default-enabled`. The runner executes phase-by-phase; a test runs
only if its gating phase (and any declared dependency) passed. Adding a test =
one manifest entry + its script.

**Ordering principle:** most-fundamental and cheapest first (fail fast, localize
to a layer); non-destructive before destructive; longest last.

| Phase | Contains | Gate |
|---|---|---|
| P0 Preconditions | readiness contract R1–R4 + substrate pre-flights (LUN present, VM-uniform, raw xinit coherency) | hard gate — abort the run if any fail |
| P1 Tooling/stack | mkfs_timing, chk_clean, dkms_install, online_resize | stack is sane |
| P2 Single-node correctness | posix(1), fsx, fio_verify, integrity_filetypes | cheap; fail fast before cluster work |
| P3 Single-node perf | single_node_paired | baseline vs native XFS |
| P4 Coherency/consistency | cache_coherency, strong_consistency, posix(N), mmap_coherency, zero_silent_loss | core multi-node correctness |
| P5 DLM behavior | dlm_lock_correctness, dlm_fairness, dlm_membership | |
| P6 Scale | scaling_curve, dlm_scaling | |
| P7 Multi-node perf | rsync_paired, cluster_ops_timing | |
| P8 Fault injection | crash_consistency, fence_during_write, fault_netpartition, fault_io_error, fault_enospc | destructive — after happy-path |
| P9 Soak | soak | longest; last |

Two run modes: **fail-fast** (stop at first FAIL — for iteration) and
**survey / keep-going** (run all, report everything — never a sign-off).

## 7. Pass/fail & state
- Each verifier prints one line: `RESULT: PASS|FAIL  test=<name>  measured=<v>  threshold=<v>  [reason=...]`; exit 0 = PASS.
- Each writes its entry to a results JSON (cross-session source of truth).
- **Success = every test passes in one end-to-end run.** (No separate success-criteria doc — premature.)

## 8. Timing — first class (RULE 0)
Every criterion carries a budget = infra (measured) + workload (native-XFS × 2),
recorded in `TIMEOUT_BUDGETS.md`. The budget IS the timeout; exceeding it is a
FAIL even with zero errors. Never widen a budget to make a run pass.

## 9. Cross-cutting parameters (NOT transport)
A test/run is parameterized by: **mount point**, **node count** (any N — 1, 16,
64, … — a pure runtime parameter with **NO default**), and a **timing budget**.
These never include device, module, transport, or stack. A future layer will
sweep increasing N; out of scope now — the current suite runs against whatever
N it is given.

## 10. Resolved decisions
- **Transport:** run BOTH stacks — LIO/tcm_loop + TCP DLM *and* SCST + CAW. Needs
  SCST config scripts alongside the LIO ones; tests stay agnostic to both.
- **Fault injection:** included in this build (§5.7, phase P8).
- **Node count:** a pure runtime parameter, no default (§9). The increasing-N
  sweep is a separate future layer, not in this build.
- **Prior `SUCCESS_CRITERIA.md`:** archived to `SUCCESS_CRITERIA.md.old`. Success
  is simply "all tests pass"; a formal criteria doc is premature.
