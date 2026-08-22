# tests (Test harnesses, benches, scripts, packaging)

**Owner files**: `tests/` (37 files, 3.4K LOC), `bench/` (1 file), `scripts/` (3 files), `packaging/` (5 files)
**Last updated**: 2026-05-08 (2-node bench/stress material below); 2026-07-11 (multi-node harness failure-state section added near the end); 2026-07-16 (dlm_lock_correctness unmount bug = the real "idle-trigger dir_reuse" cause + run_coord mount pre-assert); 2026-08-02 (sess43: BOARD TRUTHFULNESS — three harness bugs that manufactured/hid flakes, FLAKY semantics, new HB diagnostics — see final section)

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
| `tools/mxfs_sshpass.sh` | SSH+sshpass wrapper. All test scripts use this. Password is resolved from the lab secrets store `~/.config/mxfslab/secrets` (via `tools/mxfs_secrets.sh`), which materializes the `/tmp/.mxfs_pass` passfile — the wrapper re-resolves it if missing, so every caller works without a password in the tree. |
| `tools/mxfs_secrets.sh` | Resolves `~/.config/mxfslab/secrets` (source of truth for test creds) → materializes the sshpass passfile. `passfile [path]` writes the node pw; `get <key> [field]` reads a field. The node root pw lives ONLY in the store (kept in sync with osimager `images/linux`) — never write it into the tree. |
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

## sess5 (ccloop-4dd7)
- tests/suite/soak.sh persists DPAT-matching dmesg lines to /root/soak_hits.$MARKER.txt on
  the node and prints SOAK-HIT samples on failure (threshold unchanged) — node journals are
  lost on virsh destroy, so a soak FAIL without this is undiagnosable post-hoc.
- scripts/wire_vms.sh accepts any DEFINED libvirt domain name (pve9-1 etc.), not just testN.
- pve9-1/pve9-2 = Proxmox 9.1 VMs (kernel 6.17.2-1-pve) for PVE-kernel verification: build
  the module ON the node from a LOCAL copy (/root/mxb) — never `make` in the NFS tree from
  a foreign-kernel node (clobbers clyde's 6.8 objects). Nodes mount 192.168.1.4:/src.

## run.sh marker validity (2026-07-25, ccloop c7ee71c6)

`.cluster_marker.json` now records `node_list` (the actual hosts prepped) and
`marker_matches()` LIVE-verifies each node's `/sys/module/mxfs/srcversion` +
`/mnt/shared` mountpoint before any filtered run reuses the cluster. Cause: a
physrig-session marker (same N/dlm/srcversion fields, different rig) matched a
VM-fleet invocation and 5 tests were recorded PASS against a stale module.
Old markers lack node_list → mismatch → forced prep. If PR register fails on
the VM rig: check clyde's `/etc/target/pr/` exists first (LIO APTPL metadata
dir; PROUTs execute-but-fail NOT READY without it, with side effects).

## sess10 (ccloop c7ee71c6, 2026-07-26, v0.11.104-108) delta
- run.sh passes MXFS_KO_MD5 to tests/setup/prep_node.sh, which copies mxfs.ko to node-local
  /root/mxfs.ko.prep and drop_caches+retries until md5 matches before insmod — NFS mixed-page
  module images are real (srcver can match while code is stale). Never revert.
- tests/withdraw_recovery_test.sh args: N [victim] [creator] — "16 tcp" sshs to host "tcp".
- 32-node chunked boards saturate clyde (load 40-64): run budget-tight rows standalone.

## sess43 (ccloop c7ee71c6, 2026-08-02, v0.11.353) — BOARD TRUTHFULNESS

Three harness bugs that were manufacturing or hiding flakes.  All fixed; read
this before trusting or "fixing" any board verdict.

1. **`reason` was dropped from cell history** (run.sh, both push sites).  The
   node-side `finish()` names every failing check in `reason=` and the live
   cell kept it — but the history push saved only status/iso/measured, so the
   next run erased the only record of WHICH check failed.  That single omission
   is why `D-DIR-REUSE-COHERENCY` sat "UNROOTED: which check failed is not yet
   captured" and why the Aug-1 23:32 cache_coherency/zsl failures could not be
   attributed afterwards.  History entries now carry `reason[0:400]`.
2. **Reconvergence gate vs the 10-minute lease.**  The gate required the
   MXFS-MEMBERSHIP beacon to equal N.  `MXFS_LEASE_TIMEOUT_DEFAULT_MS` is
   **600000 ms = 10 MINUTES** (dlm/lease.h:58) and a node that dies and rejoins
   takes a NEW node_id, so after EVERY fault-injecting test the lease reads N+1
   for up to ten minutes on a perfectly healthy cluster.  The gate called that
   split-brain and set `BLOCK_REST`, blocking every later criterion in the
   chunk — a systematic generator of the pre-assert/NOT_RUN cascades in the
   board history.  The gate now defers an OVER-count to the authoritative
   on-disk heartbeat table (`tests/hb_live_count.sh`): exactly N live writers =
   healthy; more than N = genuine split-brain and still a hard fail.  An
   UNDER-count fails immediately as before.
3. **No per-node failed-check distribution.**  Only `first_fail` + rank1 were
   recorded, so "all 32 nodes failed the same 1 check" (a shared/coordinated
   object) and "one node failed 16" (that node's own artifacts) — which need
   opposite investigations — were indistinguishable.  Now `faildist[1x31,16x1]`.

**showstat.sh FLAKY semantics** (user directive): the status column is the
current run's verdict, and a cell whose history holds a GENUINE test-detected
failure stays ⚠ FLAKY until root-caused — it is never laundered to PASS.
Excluded from "genuine" because they are rig, not filesystem: `pre-assert`,
`NO_TERMINAL_RECORD`, `run was killed`, `prep fail`; the `prep_cluster` and
`open_defects` rows entirely; and reconvergence verdicts before
2026-08-02T04:00Z (bug 2 above — a broken gate cannot produce FS evidence).

### New diagnostics (tests/)
- `hb_slots.sh` — decode all 64 disklock HB records (flags: 0 empty, 1 ACTIVE,
  2 WITHDRAWN, 3 RECOVERY_GUARD).
- `hb_live_count.sh` — authoritative live-member count.  **Two traps it
  encodes**: HB timestamps are the WRITER's MONOTONIC clock (uptime), so they
  can never be compared against local wall time — sample twice and count slots
  whose timestamp CHANGED; and the samples MUST be O_DIRECT, because a buffered
  re-read of peer-written sectors returns this node's cached copy (the first
  version reported live=0 on a healthy 32-node cluster).
- `vergate_collapse_repro.sh` — 3 arms for the version-gate/board-collapse
  question.  Detector traps found the hard way: a case-insensitive `shutdown`
  grep also matches "generic_shutdown_super" inside P199 unmount diagnostics
  (false 18-shutdown verdict), and bare `sd N:0:0:0: reservation conflict`
  notices are the normal PR-probe artifact at EVERY mount on every node — the
  real failed-I/O discriminator is `reservation conflict error, dev ...`.
- `degraded_member_cascade.sh` — freeze arm conclusive (a frozen member yields
  NO_TERMINAL_RECORD, not counted failures).  fsdown arm NOT yet conclusive:
  cache_coherency's filesystem body is only seconds long, so the degradation
  window is hard to hit; use a longer test or add a test-side pause hook.
- `orphan_audit_arm.sh` — chk_mxfs orphan audit NEG+POS arms against real torn
  state.

### Rule learned: a harness that degrades a node must kill its remote agents
before restoring.  A watcher left running on the victim fired `umount -l` AFTER
the cleanup trap had remounted it, leaving test32 unmounted and pre-asserting
the next two board tests — the same shape as the Aug-1 test32 breakage (a test
script's side effect, not a filesystem defect).


## sess44 (2026-08-02) — guard race arms + prep device-claim guard

- **tests/guard_race_arms.sh** — four arms against the recovery GUARD
  (D-DESTAGE-TEAR closure evidence, all PASS on 0.11.357/358):
  `joiner` (rejoin lands inside a stretched hold; claim must skip the guarded
  slot; in-hold certified by hold/done count deltas), `abandoned` (holder
  virsh-destroyed; peer must reclaim by change-detection), `stale_resume`
  (holder stalls without refreshing via mxfs.ubsweep_stall_ms, peer reclaims,
  resumed holder must P99-GUARD-LOST + rc=-116 + zero sweeps), `inherit`
  (dense rig REQUIRED — full prep first; rejoiner re-claims its old slot and
  inherits the deferred bucket; ordinary last close must free with zero
  P163 recovery events).  Debug knobs: mxfs.ubsweep_hold_ms (hold+refresh),
  mxfs.ubsweep_stall_ms (freeze after hold).  Arms clean up (knobs 0, victims
  rejoined) via trap, but a killed arm leaves knobs set on survivors.
- **HARNESS LESSONS burned in these arms**: dmesg persists across runs so
  every detection MUST be per-node count-growth vs a snapshot ("line exists"
  matched a previous run's line and produced a false verdict); inode numbers
  are REUSED so reap/convergence checks need count baselines too; an fd
  holder written as `bash -c 'exec 9<f; sleep 900'` TAIL-EXECS into sleep and
  loses the cmdline marker — write `sleep 900 9<&-; :` so bash stays resident
  (and the child doesn't inherit fd9), then pkill -f RUNID works.
- **tests/setup/prep_fs.sh** now refuses to mkfs a device with /sys/block
  holders (a claimed device = the condition's rig is not wired).  On this
  fleet /dev/sda is a PATH MEMBER of the caw mpath map; the legacy tcp/cawp
  default would have mkfs'd into a live path of the shared LUN but for
  multipathd's EBUSY.  tcp condition is UNRUNNABLE until the rig is rewired
  (no XML-wired disk, no /dev/mxfs-shared on host).

## sess48 — iunl_soak_sweep.sh (P53/iunlink-store soak sweeper)

`tests/iunl_soak_sweep.sh <mark> [nnodes]` — per-cycle fleet sweep for the
fossil-nu campaign.  Counts dmesg lines AFTER an `MXFS-SOAK-MARK <mark>`
stamped per node via /dev/kmsg (dmesg persists across preps; the kmsg
ring rotates marks out within hours — stamp fresh marks per cycle and
sweep promptly).  One `dmesg | tail -n 200000 | awk` pass per node, 25s
per-node timeout.  FAIL (exit 1) on any shutdown / P53 / same-gen
FOSSILWR / unreachable / missing mark; info-prints OVERLAY/WRSITE/
DISCRIM/RELLEAK/AGPURGE/LIVESKEW counts.  Companion facts: run.sh outer
timeout must be ≥580s (sequential 32×15s mount preflight before any
output); after killing run.sh externally, clean leftovers per node
(`pkill -f <test>; fuser -k -m /mnt/shared`) or the next lap wedges.

## sess376 (2026-08-19) — closure fault harnesses + the reconvergence postcondition

### `tests/closure_purge_scrub.sh` — arms
`SCRUB_ONLY=1` (suppress the publisher half), `INCLOSURE=1` (mask includes ag0,
grants must STAY frozen), and two added this session:

- `PROBE_FANOUT=<n>` — blocked probers on n REMOTE survivors, each reporting
  `rc`/`elapsed`, plus the worst remote wait against `MXFS_CAW_WAIT_TIMEOUT_MS`
  (120s). Needed because the default `PROBE_HOST` is usually the recovery-lease
  owner, whose own waiters demand-scrub at ~1ms and therefore hide the remote
  case. Measured: 8/8 remote probers released rc=0 at 62s.
- `KILLPUB=1` (+`KILLPUB_MS`) — destroy the publisher while it is parked INSIDE
  its purge scan, i.e. before it emits the terminal summary. Ruling hazard 7
  covered publisher death AFTER publish; this is its twin. It uses
  `caw_inject_closure_pause_{where=1,who=1,slot=-1}` to widen a 418ms window,
  verifies the target has `published-so-far=0` before killing it, drops the dead
  node from `survivors`/`fanout_hosts`/`PROBE_HOST`, and asserts containment
  (recovery taken over, 0 withdrawals, 0 DLM -110, all remote probers rc=0
  under 120s) — NOT the standard `refusers==1`/published-domain guard, because
  the refusing replayer is the node that was destroyed and its dmesg dies with
  it.

### `tests/closure_reuse_directed.sh` — arms
Default arm proves the **hint→authoritative-read** reuse window (slot goes
A → tombstone → B; require `P299-HINT-MOVED` on THAT slot naming A as hint and
B as found). `ABA=1` proves the **read→CAS** window with the same resource
(A → tombstone → A; require `P299-STRIP-CASMISS`). Two harness facts that were
learned the expensive way:

- `PAUSE_WHO=1` is required. With the unfiltered injection the publisher's own
  blocked waiter — the thing step 6 depends on to empty the slot — takes the
  75s pause itself.
- The re-bound resource must be **held LIVE** across the publisher's wake. A
  single read binds the slot and releases within milliseconds, and a tombstoned
  slot short-circuits `caw_closure_strip_one` at the magic check
  (`hint_vanished`) BEFORE the resource comparison that scores `moved`. The Q
  agent now appends to the file every 0.3s and reports
  `B_HELD live_samples=/non_live_samples=`.
- Backticks inside the double-quoted remote heredoc are command substitution.
  A prose comment containing `` `moved` `` executed `moved` on the LOCAL shell.

### `tests/closure_hb_slot_reuse.sh` — the node-slot incarnation interlock
The CAW bitmaps address nodes by heartbeat-slot INDEX, which is a reusable
resource, not an identity. So "the victim's bit" could in principle be re-set by
a NEW incarnation that reuses the dead node's slot while a stale strip attempt
is outstanding. This test kills the victim, forces the refusal, then really
reboots and rejoins it, and asserts off the platter (O_DIRECT, per
`hb_live_count.sh` trap 2) that the rejoined node did NOT take the quarantined
slot, that the slot is still a `flags=3` RECOVERY_GUARD record naming the
ORIGINAL node_id and epoch, and that no strip fired after the rejoin. The
interlock it measures is `recov_desc_present()` in `dlm/disklock.c`, which
requires `flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD (3)`; a live tenant writes
`FLAG_ACTIVE (1)` and cannot present a descriptor at all, so every closure gate
fails closed on its next fresh read.
Rejoining a destroyed VM is not just `virsh start`: the node comes back with no
`/src` (NFS is deliberately not an fstab automount) and often one iSCSI portal,
so `/dev/mapper/mpatha` never assembles. The test restores both and then runs
`tests/setup/prep_node.sh caw` — which insmods and mounts but does NOT mkfs, so
the quarantined descriptor is untouched.

### `run.sh wait_converged` — the reconvergence postcondition now has a shape
It used to report one boolean at the deadline. It now records
`RECONV_TRAJ` (alive/N per 2s sample), `RECONV_LAST` (nodes not answering
`ALIVE:N`) and `RECONV_WALL`; prints the full trajectory on failure and the wall
on success; and writes the last 25 samples plus the dissent list into the
criteria.json `measured` field. That turned an unattributable 2026-08-15 flake
into a named finding on first repeat: `traj=[... 31/32 ...] dissent=[test6=nores]`
— flat, not climbing, and the node had taken a corruption shutdown
(D-FDW-REJOIN-BNOBT-OVERLAPPING-FREE-SHUTDOWN-376), not merely been slow.

### Rig discipline these runs depend on
`prep_cluster` DOES `mkfs_mxfs -f` (`tests/setup/prep_fs.sh:79`) and clears
dmesg on every node, so a node's evidence is GONE after the next prep — harvest
before re-prepping. Every closure fault test leaves a durable quarantine and a
destroyed VM: restart **every** destroyed node (`sudo virsh -c qemu:///system
start testN`) before the next prep, or the prep marker records an ssh error
string as the srcversion and every later run errors out.

## sess379 — mass-unmount / hot-slot contention harnesses

Three reusable harnesses added for
D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B and
D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379.

| script | what it does |
|---|---|
| `tests/mass_umount_stall_probe.sh <N> [BUDGET_S]` | Unmounts a mounted fleet simultaneously, times each umount ON the node, and sweeps the DLM stall markers. |
| `tests/mass_umount_reps.sh [N] [DEPART_N] [REPS] [BUDGET_S]` | Repeats that storm and prints one line per rep. |
| `tests/hotslot_contention.sh <N> [SECONDS] [BUDGET_MS]` | N nodes `stat` the mount root concurrently — the read-only control. |
| `tests/lba_probe.sh <dev> <hot_lba> <cold_lba> <secs>` | Runs ON a node: times direct SCSI `READ(16)+FUA` against two LBAs alternately. |

### The env knobs are the experiment, not decoration

- `STAGGER_S=<s>` — spread the departures instead of firing them together. The
  CONTROL arm: staggered by 3 s the same fleet unmounts in 0.04-0.09 s/node
  versus 60-181 s simultaneous, which is what proved the cost is CONCURRENCY.
- `DEPART_N=<k>` — unmount only `test1..testk`, holding the observer count at
  `N`. Separates "how many leave at once" from "how many are watching".
  When `k < N` it also arms a non-departing observer node.
- `SAMPLE_AT="<s> <s>"` — in-flight `/proc/<pid>/stack` sampling of blocked
  `umount` tasks. Reads `comm` and `stack` ONLY; never `cmdline` or `maps`
  (RULE 2c — those take `mmap_lock` and wedge a sick node).

### PITFALL — a re-prep moves the hot LBA

`prep_cluster` re-mkfs's, which changes the volume UUID and therefore the CAW
slot hash, so the hot LBA differs between runs and cross-rep evidence stops
lining up. To repeat a storm against the SAME slot mapping, remount instead:
`mount -t mxfs /dev/mapper/mpatha /mnt/shared` (this is what
`mass_umount_reps.sh` does between reps). Get the hot LBA from the
`P-FUA-READ-RETRY lba=` lines of a prior storm.

### PITFALL — these harnesses can leave the volume UNMOUNTABLE

A storm that leaves a node with a dirty slice bricks the filesystem
(D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379): every subsequent
mount aborts with `MXFS mount ABORTED: slot mask 0x... still requires
recovery`, permanently, and only `mkfs_mxfs` recovers it. If remounts start
failing, run `tools/chk_mxfs -Q <dev>` from an unmounted node — a `RECOVERY
GUARD` entry with `fence certificate kind=0` is this state — then re-prep.

## sess380 — harness corrections (do not trust pre-sess380 numbers from these)

- **`tests/create_scale_curve.sh`** — its `private` arm was NOT an uncontended
  control: every node ran `mkdir -p $dirbase/r$i` INSIDE the measured window, so
  all P nodes took the same parent inode EX and BOTH arms contended on one
  directory. Both shapes are now pre-created from rank 1 and the worker refuses
  to run if its directory is missing.
- **`tests/caw_grant_wait_anatomy.sh`** — had the same in-window mkdir, AND only
  ever ran the private shape, so it censused the parent's mkdir rather than the
  directory under test. Now takes `SHAPE=shared|private` (default shared) and
  `LOCKTOTAL_MS=<floor>` (default 50), arms `mxfs.caw_locktotal_ms` on every node
  and restores it, and harvests `P139-LOCKTOTAL` / `P139-TAILCENSUS` /
  `P34-ACQ-SLOW` in addition to the per-wait probes. It prints a WHOLE-ACQUIRE
  census with the retries distribution and the `ea_claim`/`ea_compat`/`ea_regwait`
  split.
- **`tests/mass_umount_stall_probe.sh`** — `WATCH_SLOT=<idx>` arms the
  `caw_watch_*` counters fleet-wide and prints a per-node + fleet table of the
  total command load on that one sector. `LBA_PROBE_HOT=<lba>` (plus optional
  `LBA_PROBE_COLD`, `LBA_PROBE_DEV`, `LBA_PROBE_SECS`) runs `tests/lba_probe.sh`
  on the non-departing observer for the conclusive paired-CDB control.

Getting a slot index / LBA: `caw_slotdump <dev> --type inode | grep ' ino=<N> '`
gives the slot; the hot LBA is `slot_index + base`, and the base is stable for a
filesystem (derive it once as `known_lba - known_slot`). Both change across mkfs,
because the hash covers the volume UUID.

## sess380 — rig facts that cost real time

- The node device is **`/dev/mapper/mpatha`**. `/dev/sda` is one path, claimed by
  multipath, and `mount /dev/sda` fails EBUSY. Raw `sg_raw` passthrough still
  uses `/dev/sda`.
- **`prep_cluster` clears every node's dmesg.** Any failure whose evidence lives
  only in the ring is LOST the moment you re-prep. Dump the rings first.
- **One node self-shutdown blocks the whole board.** The next `./run.sh` refuses
  with `marker stale: testN live='<sv>' want='<sv> MOUNTED'` — the srcversions
  match, the node just is not mounted. Re-prep to clear it.
- Board chunk 4 (crash_consistency … ag_strand_repair) now needs **more than
  400s**; a 400s wrapper cut it mid-`ag_strand_repair` and left 3 PENDING cells.

## Fault injection for the fenced-publication wedge (sess382)

`tests/iflush_fence_wedge.sh <victim> <peer> <window>` — drives the
P-INODE-WEDGE / self-shutdown chain deterministically in ~90 s, instead of
waiting for it (three attempts with tuning knobs produced one hit).

Knobs it uses:
- `mxfs.iflush_fence_fault_ino` / `_n` — make a chosen inode's `xfs_iflush` take
  the fence shape (error=0, no `flush_seq` stamp, `i_dlm_stale` set), i.e.
  manufacture an abandoned publication on demand.
- `mxfs.reldefer_reload` — A/B lever for the release-side reload fix
  (1 = fix, 0 = pre-fix control). Flipping it at runtime gives a paired A/B on
  ONE build: `0` → WEDGED / MOUNT=DOWN, `1` → NO_WEDGE / MOUNT=UP.

Verdicts: `WEDGED` (victim's mount destroyed — **re-prep before anything else**),
`NO_WEDGE`, `MOUNT_LOST_NO_WEDGE_LINE`.

`tests/p32e_fence_ab.sh <n> <dlm> <gate> [criteria]` — forces the dir-epoch
fence precondition via `mxfs.dir_adopt_at_acquire=0` and selects the predicate
arm via `mxfs.dir_epoch_incarn_gate`. Clears rings per arm and collects per-node
probe counts with per-node rc. **Not an on-demand reproducer** — it raises the
hazard but does not control it (sess382: 1 wedge in 3 gate=0 runs).

## sess384 (2026-08-20, 0.19.7) — THE TERMINAL-RECORD GUARANTEE

`D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374`, FIXED AND VERIFIED. This
changed the harness contract, so read it before touching `run.sh`,
`tests/suite/lib.sh` or `tests/suite/coord.sh`.

### What was broken

`run.sh` runs each node under `timeout <RULE-0 budget> ssh ...` and aggregates
by grepping `^RESULT:` out of the captured stdout. The node-side rendezvous cap
(`COORD_TIMEOUT`, default 120s) was clamped to `tt-15` for **dir_reuse_coherency
only**, in a bespoke `case` in `run_coord()`. On the other 26 applicable rows it
EXCEEDED the budget — rsync_paired 120 vs 60, crash_consistency 120 vs 90,
posix_multi 120 vs 30. So a genuine stall was SIGKILLed before the barrier layer
could print `BARRIER_TIMEOUT`, and the board said only
`nodes_pass=0/32 states:NO_TERMINAL_RECORD=32`.

**BARRIER_TIMEOUT had never appeared once in criteria.json's whole history** —
that is how you tell a reporting path is unreachable rather than merely unused.

The dispatch also piped ssh straight into `grep -v`, so `timeout`'s exit status
was grep's and the harness could not distinguish a budget kill from a transport
failure from a plain non-zero exit.

**What it cost:** the 2026-08-20T20:33:36Z `rsync_paired ... NO_TERMINAL_RECORD=32`
cell was a TOTAL 32-NODE FILESYSTEM LOSS (17 nodes shut down, replay refused,
two FSWIDE quarantines imported by every survivor, `ls /mnt/shared` -> EIO on
32/32). The board reported none of it, and the ledger entry plus the state hook
actively told the next session not to diagnose the filesystem from it.

### The contract now — three delivery paths, in precedence order

1. `src=test` — the test's own `finish`/`finish_state`.
2. `src=watchdog` — this node's watchdog at the reporting deadline.
3. `src=harness` — synthesized by `run.sh` from `timeout`'s exit status
   (124/137 `BUDGET_EXHAUSTED`, 255 `TRANSPORT_ERROR`, else
   `MISSING_TERMINAL_RECORD`). **This one cannot fail** — it runs outside the
   ssh session. Paths 1 and 2 are enrichment.

Selection is by SOURCE, never by line order: `tail -1` would let a late
`BUDGET_EXHAUSTED` bury an earlier, more specific `SYSCALL_HANG`.

Every record is also spooled node-locally to `MXFS_SPOOL`; `run.sh` fetches the
spool before synthesizing, because ssh block-buffering has been measured to lose
unflushed stdout when the kill lands.

### Things that will bite you if you edit this

- **The watchdog POLLS, it does not sleep the interval.** A background subshell
  inherits stdout, i.e. it holds the ssh channel's pipe open, and sshd will not
  close the session until every holder exits. A one-shot `sleep $SUITE_REPORT_S`
  stretches EVERY passing test to its full budget whenever the test exits
  without reaching `finish()` — and several tests set their own `EXIT` trap, so
  a `lib.sh` trap cannot be relied on to stop it.
- **Liveness is `(pid, starttime)` from `/proc/<pid>/stat`, not `kill -0`.** A
  bare pid check is a PID-reuse TOCTOU; that exact trap once wedged every
  barrier criterion cluster-wide (see `coord_barrier_or_abort`'s header).
- **The watchdog cannot see live shell variables** — it is a fork-time copy.
  `ck`/`ckeq` therefore maintain a snapshot file (`suite_step`), written with
  the shell BUILTIN printf and one redirection: no fork, one `write(2)`, cheap
  enough for cache_coherency's 654 checks (that row got FASTER, 33s -> 24s).
- **The watchdog does not kill the workload.** The stall that fires it is
  normally a D-state kernel wait, which cannot take a signal at all, and blind
  process-group kills would reach processes the script does not own. `run.sh`'s
  leftover sweep still does that — and now triggers on a REPORTED
  `BUDGET_EXHAUSTED`/`SYSCALL_HANG`/`BARRIER_TIMEOUT`, not only on total silence.
  If you add a new terminal state that means "still running", add it there too.
- **Nothing widens a budget.** The kill box is still the manifest budget;
  `BUDGET_EXHAUSTED` is not PASS. The reserve is 4s, capped at `tt/3`.
- `fail_reason` is capped at 400 chars, which at 32 nodes keeps about six nodes.
  The per-node step breadcrumb therefore ALSO goes into `measured` as a census:
  `steps[injected-stall=1,pm barrier clean=31]`.

### Exercising it

`MXFS_STALL_RANK=<rank> MXFS_STALL_S=<seconds>`, passed through
`MXFS_TEST_ENV`, stalls exactly that rank at the top of the test, before any
barrier — the shape that actually happens in the field. Inert unless set, and
it touches no filesystem state (it is a `sleep`).

    MXFS_TEST_ENV="MXFS_STALL_RANK=7 MXFS_STALL_S=300" ./run.sh 32 caw posix_multi
    -> FAIL nodes_pass=0/32 states:BUDGET_EXHAUSTED=32 ...
       steps[injected-stall=1,pm barrier clean=31] [30s/30s]

`tests/d384_terminal_record_guarantee.sh` proves the node-side mechanics on a
single host in ~25s, with no cluster and no MQTT broker. Run it before any rig
cycle that touches lib.sh/coord.sh.

## sess384 — libvirt can deadlock on ONE domain and hang every `virsh`

Measured on clyde. `virsh destroy test4` -> `Failed to terminate process
1188423 with SIGKILL: Device or resource busy`; `virsh domstate test4` never
returns while `virsh domstate test5` answers instantly; `virsh list --all`
hangs because it touches every domain. The qemu leader is a ZOMBIE whose live
sub-threads are stuck in uninterruptible sleep — all five in
`ext4_buffered_write_iter+0x39 -> vfs_writev -> __x64_sys_pwritev`, i.e.
blocked writing the guest's SERIAL LOG on the host's own ext4, with MXFS
nowhere in the path.

`run.sh` now wraps EVERY `virsh` call in `timeout 60` and prints a WARN on
expiry. Unbounded, this hangs `prep_cluster` forever in an unattended ccloop
run — the exact RULE 2b/2c failure shape. **Never add an unbounded `virsh`
call.**

Recovery without a host reset: `sudo tools/recover_wedged_domain.sh <domain>`.
It clears, in the order they become visible, libvirtd's runtime state, virtlogd's
locks on the serial and qemu logs, virtlockd's lease on the disk image (by
pointing the domain at a COPY — that lease cannot be broken while the zombie
holds the fd), and systemd-machined's stale `qemu-<id>-<domain>` registration.
~3 minutes, dominated by the image copy (26 GB in 75s). Verified end to end.

## sess385 (2026-08-21) — harness/rig notes from the AG-publication campaign

**Deriving the outer wrapper timeout (RULE 0).** `run.sh` already enforces each
row's `budget_s` from `tests/suite/manifest` as that row's hard timeout and flips
PASS->FAIL on overrun, so the outer `timeout` only decides how many ROWS you get.
Derive it from summed **elapsed** walls (`./showstat.sh N dlm`) + `12s x n_tests`
+ `15s` startup, as RULE 0 says — but be aware that a row which stalls burns its
full BUDGET, not its measured wall. `dirent_durability` measures ~66s against a
240s budget; when it stalled, a wrapper sized on measured walls cut the chunk and
the remaining rows stayed PENDING. **Put historically stall-prone rows in their own
chunk** rather than padding the wrapper (padding is a RULE 0 violation and just
makes you wait longer to learn the same thing).

**Clear guest dmesg between builds.** `prep_cluster` does NOT clear it, so a probe
census greps across several builds at once and the aggregates are silently wrong
(sess385 read "P85 events: 1145" when the current build had produced 396). Do
`dmesg -C` fleet-wide after prep, before the measured lap.

**A probe on a per-AG-release path is a rig hazard at 32 nodes.** One `pr_warn`
per AG release is ~1000 lines/node/chunk; each guest's journald writes it to its
root ext4, which is a qcow2 on clyde's ext4 — the same filesystem that holds the
shared LUN. That deadlocked jbd2 and wedged 12 guests plus the host. Anomaly-gate
any such probe BEFORE running it at 32 nodes. See ccmemory
`sess385-clyde-ext4-jbd2-wedge-shared-lun-on-root-fs` and
`sudo tools/clyde_wedge_diag.sh`.

**Module params are the cheapest A/B you will ever get.** Landing the fix behind
`mxfs.publish_inodes` (default 1) allowed a control and a treatment arm on ONE
build, with no rebuild and no srcversion skew between arms — which is what made
the sess385 result attributable. Prefer this over two builds.

**A bash subshell in `run.sh`'s dispatcher segfaulted once** (line ~1164) under
32-way ssh fan-out on a loaded host. The row was correctly left PENDING rather
than falsely PASSed. If you see a chunk end early with no verdict, check the log
tail for `Segmentation fault` before assuming a node fault.

## sess387 (2026-08-21) — host-safety layer (RULE 2d)

clyde wedged unrecoverably twice in 24h.  Neither was an MXFS bug; both were
the host being driven into a state it could not return from, and both had an
observable precondition nothing was checking.  Full chains and the SCST root
cause: `docs/host-safety.md`.  Rule text: CLAUDE.md **RULE 2d**.

### New in the harness

- **`scripts/clyde_preflight.sh`** — the gate.  `run.sh` calls it immediately
  before `marker_read`; a failure aborts the run with **exit 3**.  Checks:
  kmsg-guard halt flag, kernel taint (BAD_PAGE / oops / soft-lockup / MCE),
  D-state task count, installed SCST version, SCST trace mask, kernel-log rate
  over a 3 s sample, filesystem headroom for LUN + images + journal + tree,
  journald caps.  `--report` prints without gating.
  Overrides all log loudly: `MXFS_PREFLIGHT_SKIP`, `_ALLOW_TRACE`,
  `_KMSG_MAX`, `_MIN_FREE_GB`, `_MAX_USE_PCT`, `_MAX_DSTATE`.
- **`tools/clyde_kmsg_guard.sh`** + `packaging/mxfs-clyde-guard.service`
  (installed and enabled).  Tails `/dev/kmsg`; on CORRUPTION / PRECURSOR /
  FLOOD it writes `.rig_halt`, snapshots evidence to `.evidence/guard_*`, and
  (CORRUPTION only) bound-pauses the guests with `virsh suspend`.
  `status` / `clear` / `selftest` subcommands; `selftest` injects a benign
  precursor line and proves the watcher is alive.
- **`tests/scst_pr_bounds_check.sh`** + `tests/scst_pr_fullstatus_bounds.c` —
  guard-page proof of the SCST PR overflow and of the fix, plus an assertion
  that the INSTALLED scst.ko is `+caw-abort-reclaim.4`+ and that
  iscsi-scst.ko was built against the same core.
- **`scripts/scst_setup.sh`** now resets the SCST trace mask to the build
  default on every rig build (`reset_trace`), and `status` prints the mask.

### PITFALL — a check that cannot run is not a check that passed

`kernel.dmesg_restrict=1` on clyde: `dmesg` needs root.  The first version of
the log-rate check read nothing as a normal user and reported "0 lines/s — OK".
An unreadable log looks exactly like a quiet one.  It now FAILS when it cannot
read.  Same class as RULE 10's "a disposition-critical negative is never
evidence".

### PITFALL — a fixed measurement window lets a marginal flood escape

The guard's first flood detector used one 10 s window at 100 lines/s.  A ~110/s
flood starting mid-window measured 88/s in window 1 and 70/s in window 2 and
never tripped (observed, not theorised).  Now: >60 lines/s for **two
consecutive 5 s windows**.  Verified tripping at 796 lines/s in ~11 s.
Calibration: clyde's own kernel log during a full 32-node campaign is ~1 line/s;
the 2026-08-20 flood was ~182/s.

### PITFALL — do not fork per line in a flood watcher

`grep`/`date` subshells per line would add hundreds of processes per second to
a host that is already in trouble.  The guard matches with bash `[[ =~ ]]` and
`$SECONDS` only.

### Parsing /proc/<pid>/stat safely

The state is the field after the `)` that closes `comm` — `sed -e 's/.*) //'
-e 's/ .*//'`.  Never index by whitespace from the left: comm may contain
spaces and parentheses.  (And per RULE 2c: `stat`, `comm`, `stack` are safe;
`cmdline` and `maps` are not.)

### PITFALL — allowlist the SCST trace mask, never blocklist it

The first version of the preflight's trace check looked for a flag named
`blocking`.  SCST's token for `TRACE_BLOCKING` is **`block`**
(`scst_sysfs.c::scst_local_trace_tbl`), so the check would have sailed past the
exact flag that produced 1.07M kernel lines on 2026-08-20.  It now allowlists
the union of `SCST_DEFAULT_LOG_FLAGS` for the debug and release builds
(`out_of_mem minor pid line function special mgmt mgmt_dbg retry`) and fails on
anything else — which also covers flags SCST adds later.  Verified both ways:
default mask passes, `echo "add block"` fails.

Note `function` and `line` ARE in the debug default and are formatting flags,
not volume flags — blocking them makes the gate unusable on a debug build.

### PITFALL — a wedged host's journal is not the record; read pstore

`journalctl -b -N -k` for the 2026-08-20 wedge contains **zero** `BUG:`/`Oops`
lines, which is why that incident was first read as a pure jbd2 deadlock.  It
was not: journald cannot write once the root ext4 wedges, so nothing after the
wedge reached the journal.  That boot actually reached **Oops #9**, recorded in
pstore/ERST.

`systemd-pstore.service` drains `/sys/fs/pstore` into
`/var/lib/systemd/pstore/<id>/` at boot and then clears it, so `/sys/fs/pstore`
is normally empty and proves nothing.  Read the archive, and read the first
line of each `dmesg.txt` — the ERST header carries the `Oops#N Part#M` count.
clyde's backend is `erst`.

A wedged host's journal going quiet is the wedge, not the absence of one.

## sess389 harness facts (measured 2026-08-22)

- **Standalone `run.sh` overhead is ~40 s for ONE test** (dirent_durability
  67 s test → 106 s wrapper; dlm_lock_correctness 1 s → 27 s; crash_consistency
  80 s → >117 s).  The RULE 0 `15 s + 12 s × n` formula underestimates the
  n=1 case: use `walls + 40 s + 12 s × (n-1)`.  A 100 s wrapper on the 67 s
  test ABORTED it without the test ever failing.
- **Prep clears dmesg after the mount**, so mount-time probes
  (`P-AGCOUNT-COLLISION`, slot claims) are only in `journalctl -k -b` on the
  node; a dmesg grep after prep reads 0 for them.
- **Never cap a prep under ~300 s.**  When a node did not release mxfs (after
  a shutdown) prep ESCALATES to `virsh destroy+start` of that node; a 190 s
  wrapper killed `tests/d385_publication_verify.sh` mid-escalation, but the
  child `run.sh` kept `/tmp/mxfs_run.lock` and finished the prep ~4 min later
  (fleet ended mounted).  A following `run.sh` then refuses with "another
  run.sh holds /tmp/mxfs_run.lock" — read the fuser line, check
  `/proc/<pid>/comm`, and WAIT for it; do not kill a live prep.
- `MXFS_MKFS_OPTS` (e.g. `"-d 50G"`) passes through `run.sh` → `prep_fs.sh`
  → `mkfs_mxfs` (sess389).  `mkfs_mxfs -d SIZE` caps the XFS data area to
  reproduce a smaller device's agcount on the 128 GiB LUN (`-d 50G` → 25 AGs).
  `-n` is capped at 32 (one 2 GiB internal log), so it cannot force agcount.
- `tests/fleet_pubob_counters.sh N` — one-pass per-node dmesg sweep of the
  publication-obligation probes; 24 serial `dmesg | grep` per node × 32 nodes
  blew a 40 s ssh cap (1.1 s per grep on a 110 k-line ring).
- 25-AG (agcount < nodes) is NOT correctness-supported yet: lap 2 wedged the two
  shared-AG slots (30/31) with `P-NOINO-RELFENCE-WEDGE` (#474 family) —
  evidence extract `tests/logs/ag25_incident_sess389.txt`.  The rig runs at
  64 AGs (128 GiB LUN, default `-n 32`).

## sess390 — 25-AG correctness laps (the AG-sharing geometry) and the convoy/demote probes
- Re-prep at 25 AGs on the 128 GiB LUN: `MXFS_MKFS_OPTS="-d 50G" MXFS_FORCE_PREP=1
  D385_STEP="arm_prep TREATMENT" tests/d385_publication_verify.sh 3 32` (prep wall
  77-83 s; cap 330 s — never cap a prep under ~300 s).  It deploys the tree's module.
  Verify with `tools/chk_mxfs -v /home/steve/disk.img | grep agcount` and a fleet
  `srcversion` sweep (dmesg only — `journalctl -k -b` exceeds a 25 s ssh cap on the
  long-uptime nodes).  Restore: same step without MXFS_MKFS_OPTS (→ 64 AGs).
- Laps: `CHUNK_TIMEOUT=330 D385_STEP="arm_lap TREATMENT <n>"` ONE lap per
  foreground call (264-332 s each; two laps in one call overran the 10-min cap and
  lost the post-lap sweep).  The wedge/split symptoms appear on laps 2-3 (aged FS).
- Counter sweep after each lap (one ssh per node, dmesg only): `Shutting down`,
  `RELFENCE-WEDGE`, `DRAIN-STUCK`, `P-NOINO-CONVOY`, `P-AGTRY-DEMOTING`,
  `P86-AGI-UNLINKED-PUBLISH `, `P87-TARGET-TIMEOUT`, `P88-PUBOB-UNREPAIRED`,
  `P86-AGI-UNLINKED-BADHEAD`, `P217-RENAME-DIRTYCANCEL|Corruption of in-memory`.
  Healthy 0.20.2 @25 AGs: all zero except CONVOY/DEMOTING (expected engagement).
- `P-NOINO-CONVOY ... item=0x1236 ag=N agwait_ms=` = EFI frozen behind a local
  AG-N wait (not a wedge).  `P-AGTRY-DEMOTING ag=N comm=` = a nonblock acquire
  declined during N's demote (the seam then drops ILOCKs).
- Evidence: tests/logs/ag25_sess390_convoy_demote.txt; sess389's incident
  tests/logs/ag25_incident_sess389.txt.
- RULE 0: rsync_paired at 25 AGs is 18 s lap 1, 51-58 s lap 2, >60 s lap 3 — a
  pace FAIL by design of the geometry (PACE-388); at 64 AGs 15-30 s every lap.
- 0.21.x knobs/probes (sess390): `mxfs.noino_lifecycle_requeue` (default 1) parks a
  no-inode BAST that finds the inode INEW/IRECLAIM/INACTIVATING/NEED_INACTIVE/
  VFS_TEARDOWN (`P-NOINO-LIFECYCLE ino= class=`, `P-NOINO-LIFECYCLE-DONE`,
  `-TIMEOUT`); stats line `noino_lc: inact= needinact= inew= ireclaim= vfsteardown=
  reclaimable= requeued= lc_timeouts=`.  `mxfs.ag_readopt_window_ms` (default -1):
  after a peer BAST older than the window, nonblock AG acquires get -EAGAIN
  (`P-AGTRY-BASTPEND`) and blocking ones re-adopt PINNED (`P12-READOPT-PINNED`,
  stats `readopt_closed= readopt_pinned=`).  NEVER make a blocking acquirer wait at
  that gate (arm 3 wedge: tests/logs/ag25_sess390_readopt_close_wedge.txt).
