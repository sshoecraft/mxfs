# Phase 0 — Decision-Gate Results

> NEWARCH §5/Phase 0.  Goal: measure whether a *fully coherent* MXFS still
> beats GFS2/OCFS2 BEFORE building any notification layer.  This file is
> the single canonical record of the measurement; per-run logs live under
> `phase0_runs/`.  Detailed narrative is in `journal.md`.

## Builds under test

| Variant | srcversion             | Code change                                    | Result                |
|---------|------------------------|------------------------------------------------|-----------------------|
| baseline | `EED6A769B0BA85B48F6B6BC` | sess107 deploy (default)                     | reference             |
| v1 fc   | `287BA2051DF7DD51B56AEED` | force_coherent: demote cached fast-path + dir-buf invalidate | NULL deref oops |
| v2 fc   | `4C9D5DA8740D26E8CF977B5` | force_coherent: dir-buf invalidate only (lock-state untouched) | FS shutdown |

`mxfs.force_coherent` is a Phase 0 measurement instrument only.  Probe
tag `P0-FCOH-DIRINVAL` is gated behind `mxfs.instr`.

## Test environment

- Cluster: test1..test4 (this repo / v5), kernel 6.8.0-101-generic.
- Storage: SCST iSCSI target on `clyde`, `vdisk_fileio` backing
  `/home/steve/disk-1.img`, `/dev/sda` inside each VM, `/mnt/shared`.
- Transport: CAW (default).  All probe gates left at `mxfs.instr=0`.

## Run 1 — force_coherent v1 (lock-state demotion + buf invalidation)

| Field          | Value                                                          |
|----------------|----------------------------------------------------------------|
| Command        | `INSMOD_OPTS="force_coherent=1" cache_coherency --nodes 4`     |
| Log            | `phase0_runs/cache_coherency_fcoh.log`                         |
| Wall           | ~7 min before all 4 nodes oopsed                               |
| Subtests       | cross_visibility PASS, rename_visibility PASS, **test_unlink_visibility — kernel NULL deref oops on all 4 nodes** |
| Failure mode   | `xfs_dir2_sf_lookup+0x4b` reading `(%r12+1)` with r12=NULL during mkdir |
| Root           | v1 demoted `i_dlm_mode/state` on the fast path, slow-path reload clobbered `if_data` while a concurrent thread iterated SF entries |
| Implication    | The in-core lock-state machine has a release/reload race with concurrent SF-dir read.  **Phase 1 territory** (single chokepoint). |

## Run 2 — force_coherent v2 (buf invalidation only)

| Field          | Value                                                          |
|----------------|----------------------------------------------------------------|
| Command        | `INSMOD_OPTS="force_coherent=1" cache_coherency --nodes 4`     |
| Log            | `phase0_runs/cache_coherency_fcoh_v2.log`                      |
| Wall           | 244 s before criterion bailed                                  |
| Subtests       | **cross_visibility FAIL** (Nodes 1-3 PASSED all 4 content assertions; Node 4 FS-shutdown ~5s after mount, all its asserts FAIL as downstream) |
| Failure mode   | `XFS Internal error dp->i_disk_size != geo->blksize at xfs_dir2.c:287 (xfs_dir2_format+0xf4)` → `Shutting down filesystem` |
| Root           | force-invalidation of a dir buffer during a dir-format transition (block ↔ leaf) re-read a disk image whose size disagreed with the in-core `if_format` |
| Implication    | Different in-core race exposed when buffers are aggressively refetched.  Same family as Run 1 — pre-existing in-core state-machine races that default amortization hides. |

## Run 3 — default-mode (`force_coherent=0`) cache_coherency baseline

| Field          | Value                                                          |
|----------------|----------------------------------------------------------------|
| Command        | `cache_coherency --nodes 4`                                    |
| Log            | `phase0_runs/cache_coherency_default.log` + `/tmp/cache_coherency.gGI6XU.log` |
| Wall           | 126 s                                                          |
| cross_visibility | **PASS**                                                     |
| rename_visibility | **PASS**                                                    |
| unlink_visibility | **PASS**                                                    |
| cross_write_read  | **FAIL** — every reader sees empty content for node 3's file (`expected='7f1a07c9…' actual=''`) |
| Total          | 3/4 (matches the sess107 residual on this build)               |

## Run 4 — multinode metadata bench

Not collected.  Rationale: Run 2 showed v2 force_coherent triggers FS
shutdown within seconds of mount; running fio under force_coherent would
crash before producing usable numbers.  Default-mode bench numbers from
prior sessions remain authoritative (see `bench/` and per-session
memories) and the Phase 0 gate is already answered by Runs 1–3.

## GFS2 / OCFS2 reference

Not collected this session — would require a separate
corosync+pacemaker+dlm-controld+gfs2 stack on the same hardware.  Per
NEWARCH §5 the bench is only decisive for distinguishing Outcomes 1 vs 2
(passes-and-fast vs passes-but-slow); the actual outcome here is
Outcome 3 (cannot pass even fully synchronous), so the comparison is
deferred until Phase 1 lands and Phase 0 is re-run.

## Gate decision

**Outcome 3 — Cannot pass even fully synchronous → Phase 1 first.**

Per NEWARCH §5 / Phase 0:
> Cannot pass even fully synchronous → exclusion is broken below the
> notification layer → fix P106 (Phase 1) and re-run the gate before any
> Phase 2.

Evidence:

1. Two independent attempts to instrument "fully synchronous reads"
   tripped two independent in-core state-machine races, both of which
   exist in the default code path but are normally masked because the
   fast-path/amortization hides them.
2. Even the *default-mode* baseline is 3/4 on the criterion — the lone
   `cross_write_read` failure shows that read-side coherency is broken
   for at least one workload without any force_coherent involvement.
3. Building Phase 2's TCP invalidation mesh on top of this in-core
   state machine would just deliver invalidations to a holder set that
   the bitmap mis-reports — exactly the trap the prompt warned about:
   *"Reliable notification only works if the on-disk holder bitmap is
   accurate."*

### Recommended next step (Phase 1)

Per NEWARCH §4 / prompt Phase 1:

> Every path that clears an on-disk holder bit must, atomically with
> that clear, reset the in-core `i_dlm_mode`/`i_dlm_state` (and vice
> versa).  Ideally all releases/demotes/yields route through one
> chokepoint so the on-disk bit and in-core mode can never diverge.  A
> permanent, toggleable assertion/probe must fire the instant they
> diverge.

Specific work items the Phase 0 runs surfaced as urgent:

- **Race A (Run 1):** `mxfs_dlm_reload_inode` overwrites `if_data`
  while a concurrent thread on the same inode iterates SF entries.
  Reload must drain in-flight readers (e.g. acquire ILOCK_EXCL via the
  same chokepoint) before mutating `if_data`.
- **Race B (Run 2):** dir-format transitions update `dp->i_disk_size`
  separately from the buffer/format state, so a force-refetched buffer
  can come back from disk inconsistent with the in-core view.  The
  chokepoint design must couple disk_size publish with `if_format`
  transitions across nodes.
- **Probes to add up-front (NEWARCH Phase 1 §1):** every on-disk
  holder-bit clear site (`mxfs_dlm_caw_unlock`, `caw_release_all`,
  yield-clear, acquire-divergence guard, mount-time purge) logs
  `{resource, node, reason, in-core mode/state}` so the chokepoint
  refactor is driven by measurement, not code-reading.

Phase 2 (TCP invalidation mesh + version epoch) **stays gated** behind
the Phase 1 work landing and Phase 0 being re-run with clean
force_coherent results.
