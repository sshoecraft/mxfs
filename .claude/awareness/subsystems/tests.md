# tests (Test harnesses, benches, scripts, packaging)

**Owner files**: `tests/` (37 files, 3.4K LOC), `bench/` (1 file), `scripts/` (3 files), `packaging/` (5 files)
**Last updated**: 2026-05-08 (2-node bench/stress material below); 2026-07-11 (multi-node harness failure-state section added near the end); 2026-07-16 (dlm_lock_correctness unmount bug = the real "idle-trigger dir_reuse" cause + run_coord mount pre-assert — see final section)

## Purpose

Shell-based test infrastructure that drives 2-node bench/stress against test1/test2 VMs. The bulk of MXFS validation runs here, not as kernel selftest — the cluster behavior can only be tested with two real nodes attached to a shared LUN.

> **This doc is stale re: the current suite** — everything below describes
> the original 2-node bench/stress harness (last touched 2026-05-08). The
> project has since grown a separate 2-32 node, MQTT-coordinated criterion
> suite (`tests/suite/*.sh` + `run.sh` + `criteria.json`) that this doc
> never covered. See "Current multi-node suite" near the end of this file
> for the one part of that system touched today (2026-07-11); a fuller
> `/project:update-awareness` pass is still owed for the rest of it.

## Key Scripts

| Path | Purpose |
|---|---|
| `bench/rsync_bench.sh` | Primary bench. Runs parallel rsync on both nodes (open-gpu-kernel-modules → test1, element-web → test2), checks file count + md5 + dmesg per iter. |
| `scripts/cluster_reset.sh` | sysrq-safe FULL reset: unmount, rmmod (with retry for transient busy), re-mkfs on test1, mount on both. Includes 8× retry × 10s sleep for rmmod. |
| `scripts/stress_session.sh <iters> <mb>` | Stress harness, requires T1_DD_OK + T2_DD_OK markers per iter (sess23-fixed; pre-sess23 used `shutdown_check` alone, missed silent EIO). |
| `scripts/stress_session_4node.sh` | 4-node variant (not currently used; reserved for sess34+ scaling). |
| `tools/mxfs_sshpass.sh` | SSH+sshpass wrapper. Auth via `/tmp/.mxfs_pass`. All test scripts use this. |
| `scripts/probe_sweep.sh <N>` | (ccloop daf50d34) Post-run cluster sweep of the 0.10.65+ xfs_buf integrity probes (P-SEMA-OVERUP/DUALLOCK, P-WRCNT-RESUBMIT, P-BLI-DOUBLEDONE) + SYSCALL_HANG/shutdown/BUG/Oops across test1..N dmesg rings. Exit 0 iff CLEAN. Run after every criteria run, BEFORE any VM recycle (ring dies on reboot). |
| `scripts/revalidate_cell.sh <N> <full\|nodr\|dr\|g1\|g2>` | (ccloop daf50d34) One matrix-cell-group re-validation on the current build: clears rings, runs `run.sh N caw <group>` with RULE-0 TEST_TIMEOUT (600@32, 480@16, 300 else; dir_reuse auto 140*N inside run.sh), then probe_sweep. g1/g2 = the 32-node coherency/destructive split. |
| `tests/cluster/`, `tests/single/`, `tests/stress/` | Per-area test cases. |
| `tests/decision_reproducers/` | Standalone reproducers for specific past-bugs. |
| `tests/lib/` | Common shell helpers. |
| `tests/run_tests.sh`, `tests/quick_test.sh`, `tests/mxfs_test.sh` | Top-level dispatchers. |
| `packaging/mkpackage.sh`, `packaging/rpm/*` | RPM builds. |

## Test Cluster

```
test1   192.168.120.186   UTC   open-gpu-kernel-modules workload  preferred_ag=0 ish
test2   192.168.120.182   UTC   element-web workload                preferred_ag=1 ish
host    192.168.1.4       NFS-exports /src to both nodes              CDT (bench scripts handle TZ)
```

Both VMs see `/dev/sda` as a shared LIO-backed LUN. They claim disklock slots 0/1 from the 64-slot heartbeat region.

## Public API

Shell scripts; no programmatic API. Invoked from the dev host.

## Invariants

1. **Persistent scripts live in the source tree, not /tmp.** Per `/src/mxfs/CLAUDE.md` RULE 3. Test cluster reboots wipe /tmp; sess20–30 burned cycles re-creating harnesses. Keep harnesses in `tests/`, `bench/`, or `scripts/`.
2. **Bench MUST capture dmesg cursor BEFORE rsync** so post-iter `dmesg_hits` count is bounded. The script does `sudo dmesg -T | wc -l > /tmp/dmesg_cursor_${LABEL}_iter${I}` pre-iter.
3. **`shutdown_check` alone is INSUFFICIENT for stress PASS detection.** sess22 false-PASS regression: the shutdown check passed even when iter-1 had silent EIO. Fix in sess23: require `T1_DD_OK` + `T2_DD_OK` markers in addition.
4. **Benches that take >120s indicate failure mode, not slow success.** Single-node rsync of open-gpu is ~3-13s. Multi-node working should be 2-3× SOLO at worst. 1300s timeouts = "let it grind through CAW timeouts" — don't read those as success.

## Known Pitfalls

- **Mode A on simultaneous mkdir** during bench setup: when both hosts run `mkdir -p /mnt/shared/$(hostname)` in parallel (which the bench script *does* sequentially per host but rsync still hits in mkdir of iter dir), one node's view of the parent dir doesn't include the other's freshly-created entry. Workaround: pre-create both dirs from one host with sync, drop_caches on the peer.
- **rmmod transient busy** during cluster_reset: even after umount, the module can be refcnt>0 briefly while bast_poll_thread joins. cluster_reset.sh has 8× retry × 10s; usually 1-2 retries needed.
- **dd-zero before mkfs:** LIO-backed device sometimes has stale-disk content that mkfs's pwrite-O_SYNC zero doesn't durable. Run `dd if=/dev/zero of=/dev/sda bs=1M count=256 oflag=direct` first.
- **Test cluster runs UTC, dev host runs CDT.** Use `date -u` when reading journalctl across nodes.
- **rsync_bench.sh's `dmesg_hits` regex** is conservative — adds new pattern requires careful escape (it's already shell-double-quoted and grep-ERE'd).

## Historical "Bugs" in Test Infra

- **sess22 false PASS reports:** stress_session.sh's `shutdown_check` returned OK even when iter-1 had EIO. Fix: require explicit DD_OK markers per iter (sess23).
- **sess23 transient rmmod busy:** cluster_reset's `rmmod mxfs` failed intermittently because bast_poll_thread join was racy. Fix: 8× retry loop.
- **sess32 LIO stale-disk masking corruption:** Without dd-zero before mkfs, sess32 saw "Mode A" that was actually corrupt-storage masquerading. Diagnosis took most of sess32 close.

## Files of Note

- `bench/README.md`, `scripts/README.md`, `tests/README.md` — see for current usage.
- `bench.json` — historical bench results (token-rich; load only when needed).

## Current multi-node suite (tests/suite/ + run.sh + criteria.json)

Superseding the 2-node material above for coordinated (2-32 node) testing:

- `run.sh <N> <caw|tcp> [test...]` — top-level orchestrator. Launches each
  test on all N nodes in parallel over SSH, aggregates results, records
  into `criteria.json` under `"<N>/<dlm>"`. Per-test wall-clock budgets are
  workload-derived (RULE 0), not a blanket default — see the `case "$name"`
  block in `run_coord()` for current per-test overrides (e.g.
  `dir_reuse_coherency` gets `140*N` seconds on CAW because its per-round
  cost is O(N): every node writes into one shared directory each round).
- `tests/suite/*.sh` — the ~17-test criterion suite (cache_coherency,
  dir_reuse_coherency, crash_consistency, dlm_scaling, dlm_fairness, etc.),
  each sourcing `tests/suite/lib.sh` for the `ck`/`ckeq`/`finish` convention
  and, for coord-class tests, `tests/suite/coord.sh` for cross-node
  barriers.
- `tests/suite/coord.sh` — MQTT-based coordination (broker
  `192.168.1.149`), deliberately never touching the filesystem under test
  (an earlier on-FS `.mxfs_barriers/` scheme could mask/poison the exact
  coherency bugs the suite exists to catch).
- `criteria.json` — the live scoreboard; `run.sh`'s `record()` writes one
  entry per test per `"<N>/<dlm>"` condition.

### Harness failure-state protocol (added 2026-07-11)

Before this date, a coordinated test's only outcomes were PASS/FAIL via
`ck`/`ckeq`/`finish`, and a `coord_barrier` timeout was just one more `ck`
failure — the round loop kept going regardless of which node or barrier
timed out. This made a single node's genuine kernel-level hang (a syscall
that never returns — not a correctness bug) indistinguishable, in the
aggregated `nodes_pass=X/Y` metric, from every node independently failing a
correctness check, and it cost real wall-clock: rank 1's `rm -rf` wedged
D-state in `xfs_buf_iowait` (`dir_reuse_coherency@32/caw`, run61b) and the
other 31 nodes spent ~2 hours cycling through repeated 120s barrier
timeouts — one per remaining round — before the outer per-run `timeout`
killed everything with **zero** `RESULT:` lines printed by any of the 32
nodes. (Full incident + an external architectural consult on the
underlying kernel bug that caused the hang: ccmemory
`gpt-consult-dir_reuse32-architectural-review`.)

Fixed additively — nothing existing changed behavior; tests still using
plain `ck`/`ckeq`/`finish` are unaffected:

- **`tests/suite/lib.sh`**: `finish_state <STATE> [detail]` emits the same
  `RESULT: <state> | test=... | ...` line `finish()` does, but with an
  explicit non-PASS/FAIL state in the status field — `run.sh`'s existing
  `[ "$status" = PASS ]` check keeps working unmodified, since anything
  else already falls through to the failure branch. `finish_hang <op>
  [detail]` → state `SYSCALL_HANG`; `finish_aborted <reason>` → state
  `ABORTED_BY_PEER`. `run_bounded <label> <threshold_s> <cmd...>` runs an
  external command in the background, polls once/sec, and on a hang
  captures the stuck process's wchan + `/proc/$pid/stack` to `/dev/kmsg`
  and returns 1 instead of blocking forever — generalizes the bounded
  `drop_caches` idiom already used in `dir_reuse_coherency.sh` (that
  specific call site was left untouched; it has its own well-proven
  degrade-and-proceed behavior that doesn't fit `run_bounded`'s
  fail-and-report contract).
- **`tests/suite/coord.sh`**: `coord_signal_abort <reason>` broadcasts a
  fatal condition, built on the pre-existing `coord_signal` retained-topic
  primitive. `coord_check_abort` is a ~1s non-blocking poll for one.
  `coord_barrier_or_abort <tag>` wraps the existing (carefully-tuned,
  untouched) `coord_barrier` in a background job and polls it against
  `coord_check_abort`, returning early (status 2 + the peer's reason
  string) the instant any peer broadcasts an abort, instead of waiting out
  the full `COORD_TIMEOUT`. All 5 paths (no-abort, abort-detected,
  abort-short-circuits-an-unsatisfiable-barrier, genuine-success,
  genuine-timeout-with-no-abort) were verified directly against the live
  broker with a disposable topic prefix.
- **`tests/suite/dir_reuse_coherency.sh`**: rank 1's `mkdir`/`rm -rf` (the
  actual hang point) now run through `run_bounded` with a 20s threshold
  (the native op is sub-second; 20s gives >20x headroom while staying far
  below the barrier's 120s `COORD_TIMEOUT`, so a real hang is caught and
  broadcast before any peer's barrier wait would even begin timing out).
  On a hang: dumps dmesg to `/root/drc_hang_*`, calls `coord_signal_abort`,
  and exits via `finish_hang` — it does NOT try to "proceed anyway" the
  way the existing `drop_caches` wrapper does, because the directory this
  whole test depends on is left in an unknown state. All four
  `coord_barrier` call sites now go through a local `drc_barrier` wrapper
  that ends the test immediately (via `finish_aborted` /
  `finish_state BARRIER_TIMEOUT`) on any timeout or peer-abort, instead of
  recording one more `ck` failure and cascading through the remaining
  rounds.
- **`run.sh`**'s `run_coord()` aggregator now tallies a per-status
  breakdown (`state_count`) alongside the pass count, so `criteria.json`'s
  `measured` field reads e.g. `nodes_pass=1/32
  states:SYSCALL_HANG=1,ABORTED_BY_PEER=31` instead of an undifferentiated
  `nodes_pass=0/32` — verified against synthetic RESULT lines.

**Not changed**: the existing post-timeout cascade guard (kills leftover
`pkill -f '$script'` + `fuser -k -m $MNT` processes when a node prints no
RESULT line at all — that status label was renamed `NORESULT` →
`NO_TERMINAL_RECORD` for taxonomy consistency, but the guard's trigger
condition and behavior are unchanged) — it remains a useful backstop for
whatever the new hang-detection doesn't itself catch.

## 2026-07-16 (ccloop 8ba7ae5c sess1): dlm_lock_correctness unmount bug — the real "idle-trigger dir_reuse" root cause

- **`tests/caw/dlm_lock_correctness.sh` REWRITTEN — it was the cause of the
  long-unsolved "idle-trigger dir_reuse_coherency" failure** (2026-07-15
  state.md, 7 reverted kernel fix attempts). The old version did
  `mountpoint -q $MNT && umount $MNT` before its raw SG_IO probes
  (fua_verify/caw_verify) and, being the LAST test of every caw rung
  (coord=none → node1 only), silently left node1 WITHOUT the cluster FS
  while `.cluster_marker.json` still said "formed". Every subsequent
  same-formation (filtered/solo) test then ran rank1 against the bare
  rootfs mountpoint directory — invisible to peers, "sticky" until reform,
  and it needed "the full suite first" only because the unmount WAS the
  suite's last step. A month of bare-dir debris (test2: 62 entries,
  test4: 38, dating to Jun 15) shows it poisoned many historic runs.
  The old test also wrote a hardcoded scratch LBA 83886080 (40 GiB in =
  INSIDE the live XFS data area) while peers had the FS mounted.
- New version: NEVER unmounts (SG_IO needs no unmount); derives the scratch
  LBA at runtime from the device's own super via `chk_mxfs -v` →
  `disklock_offset/512 - 1` — the last sector of the mkfs 4K-alignment gap
  below the disklock region, which always exists (journal_size ≡ 4608 mod
  4096 → gap is always 3584 bytes) and nothing ever reads. SKIPs if the
  super is unreadable rather than writing a guessed LBA. `SCRATCH_LBA` env
  still overrides. `tools/mkfs_mxfs.c` Step 3b now explicitly zeroes +
  documents that sector as the formal transport self-test reservation.
- **`run.sh run_coord()` PRE-ASSERT**: before every coordinated test
  launch, all N nodes must have the cluster FS mounted (`mountpoint -q` +
  fstype match, parallel, 15s timeout each); any miss records a hard FAIL
  naming the node(s) ("a prior test broke cluster formation state") and
  skips the launch. Runs before `t0` so it never counts against RULE-0
  budgets. This turns any future silent formation breakage into a loud,
  attributable failure instead of hours of phantom coherency FAILs.
- Debugging heuristic proven here: when a multi-node test says "peer sees
  nothing", check `findmnt /mnt/shared` / `stat -f` (fstype!) on EVERY node
  FIRST. `stat` succeeding on the shared path proves nothing — a bare
  rootfs mountpoint answers stat too.
