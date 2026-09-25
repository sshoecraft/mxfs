# tests (Test harnesses, benches, scripts, packaging)

> **0.89.89: probes are dynamic debug.** Every `P...`/`PW-...` instrumentation
> line is `pr_debug` (`mxfs_probe*`, `pal/mxfs_probe.h`) and prints nothing
> unless enabled. `tests/setup/prep_node.sh` and every harness that loads the
> module pass `dyndbg=+p`; a NEW harness that loads the module itself must do
> the same, or its probe greps find nothing (and read as "absent", not as an
> error). On a packaged node loaded by modprobe: `echo 'module mxfs +p' >
> /proc/dynamic_debug/control`. Policy and which messages stay visible:
> `docs/log-levels.md`.
<!-- 2026-09-04: (1) tests/setup/prep_node.sh — the tcp transport branch now
     carries target_cache_protected=1 like the caw branch; the declaration
     describes the TARGET's cache, not the lock transport, and without it the
     0.54.0 durability gate refuses every 2/tcp prep with EACCES
     (P-DOMAIN-REFUSED fua_disable=1 target_cache_protected=0).  (2) since
     0.73.0 the production build ADMITS a TCP clustered RW mount
     (pal/linux/xfs_super.c mxfs_transport_domain_admit; 0.55.0-0.72.x
     refused it and needed KCFLAGS=-DMXFS_TCP_TRANSPORT_READY=1 — that flag
     and the mxfs_tcp_transport_lab modinfo marker are gone; a plain
     `make modules` is the TCP build).  (3) NEW tests/scsi_caw_probe.sh
     <dev> <lba>: raw-CDB target qualification (READ(16), READ(16)+FUA, CAW
     correct/stale/restore, with decoded sense).  Use it instead of sg_opcodes
     (the QNAP rejects REPORT SUPPORTED OPCODES) and instead of tools/caw_verify
     (its FUA pre-read fails on FUA-refusing targets before any CAW is sent).
     It writes one block (flipped then restored) — point it at a scratch LBA.
     (4) Running the board on the QNAP LUN from the VMs: iscsiadm discovery +
     login to 192.168.1.4 on each node, then MXFS_NODE_LIST=test1,test2
     MXFS_DEV=/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-iqn.2004-04.com.qnap:
     ts-453pro:iscsi.target-0.f35772-lun-0 ./run.sh 2 <caw|tcp> ...; set the
     path's /sys/block/sdX/device/timeout to 180 first.  Measured 2026-09-04 on
     0.70.19: 2/caw prep 50 s + 9 rows 184 s; 2/tcp (lab) prep 39 s + 9 rows
     228 s — derive TCP wrapper budgets from TCP walls, they run ~2x CAW. -->

**Owner files**: `tests/` (37 files, 3.4K LOC), `bench/` (1 file), `scripts/` (3 files), `packaging/` (5 files)
**Last updated**: 2026-05-08 (2-node bench/stress material below); 2026-07-11 (multi-node harness failure-state section added near the end); 2026-07-16 (dlm_lock_correctness unmount bug = the real "idle-trigger dir_reuse" cause + run_coord mount pre-assert); 2026-08-02 (sess43: BOARD TRUTHFULNESS — three harness bugs that manufactured/hid flakes, FLAKY semantics, new HB diagnostics — see final section); 2026-09-08 (sess559: `ghost_slot_restart_probe.sh` — see final section); 2026-09-09 (sess560: the probe as a fix ladder, tag census, `d0930_root_iget_bound.sh` — see final section)

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
5. **No verdict from an unvalidated capture (0.87.17, `tests/lib/rig.sh`, `docs/harness-capture-contract.md`).** The legacy `rs() { timeout N $SSH host cmd 2>/dev/null | filt; }` discards remote stderr and returns filt's status; a remote failure leaves an empty or partial capture, `grep -c` reads 0, and a ck/ckge prints a verdict about MXFS (s580f, s54j/s54k). Every counted measurement is acquired with `rsx` (status observed, stderr in `$OUT/rs_stderr/`, a `MXFS-RS-STATUS v=1 host= rc= err=` record appended on non-zero status) and validated by `capture_require <file> <anchored shape> <what>` AS A STATEMENT in the parent shell (an exit inside `$(...)` does not stop a harness) before any count is read; failure is ABORT (2), never FAIL/VACUOUS/PASS. `ensure_src_or_abort` checks the share and the tools on a node. **The device under test is an identity, not a path (0.87.20):** `data/rigs.json` declares each rig's LUN by SCSI WWID under the tag `tools/mxfs_rig_tag.sh` prints (`MXFS_LUN_WWID` for one run); `tests/setup/dev_identity.sh` runs on the node (shipped inline over ssh) and prints path, major:minor, WWID, the envelope superblock's filesystem uuid by a direct read of sector 0, and the node's live mxfs mount; `mxfs_dev_resolve <node>` takes the candidate (MXFS_DEV, the live mount, the declared LUN by `/dev/disk/by-id/wwn-0x<wwid>`, the transport default only with MXFS_TRANSPORT set), requires the declared WWID and — on a node with a live mxfs mount — that mount's device by major:minor, sets `MXFS_DEV_RESOLVED/_WWID/_FSID/_SOURCE` and prints a `DEVICE` line; a device with no WWID (`/dev/vda`) is refused. `mxfs_dev_check <node>` re-reads a binding before a device-consuming step after a restart, re-login or foreign format; `mxfs_dev_same <node>...` requires one LUN and one format generation. `run.sh` writes `wwid`, `fsid` and `gen` into `.cluster_marker.json`. Sites whose subject IS a rig's storage configuration carry `# device-adjudicated: <why>` (line, or script header); the lint's third class counts `/dev/mapper/mpatha`, the QNAP by-path and `/dev/sd[a-z]` (0 unadjudicated at 0.87.20). `tests/capture_fault_gate.sh <label> [--healthy] [--only h] [manifest]` drives `tests/capture_gate.manifest` (55 harnesses) through the injected-failure rejection test, with stdin closed on the harness (a harness inside the gate's `while read` otherwise drains the manifest, s58g); `--healthy-only` runs just the healthy lap and quotes its `DEVICE` line. `tests/capture_gate_sweep.sh lap|fleet|ensure <label> <harness|tag>` (0.87.22) is the one-lap driver for a delegated runner: `lap` runs one entry through the gate bounded by the manifest's own healthy timeout and prints each node's mount and a real write through it (`FLEET node= mounted= writable=`; a shut-down filesystem is still in /proc/mounts), `ensure` waits for both nodes' ssh (<=180 s) and preps once if either is not mounted-and-writable — so a kill-arm or shutdown-producing entry never starts the next lap on a broken fleet and nothing waits longer than a manifest bound. `scripts/harness_lint.py` prints the residue (unguarded counted assertions per harness, and a local `rs()` shadowing the library); `tools/mxfs_sshpass.sh` appends the same status record for legacy callers when `MXFS_RS_STATUS=1`. Adopted: `tests/lone_mount_crash_replay.sh`, `tests/d0531_stale_slice_recovery.sh`, `tests/rig_lib_contract.sh` (the contract tests). `MXFS_FAULT_UMOUNT_SRC=<node>:<stage>` in the adopted harnesses is the verification barrier: a real unmount of /src immediately before the named acquisition.

## Known Pitfalls

- **Mode A on simultaneous mkdir** during bench setup: when both hosts run `mkdir -p /mnt/shared/$(hostname)` in parallel (which the bench script *does* sequentially per host but rsync still hits in mkdir of iter dir), one node's view of the parent dir doesn't include the other's freshly-created entry. Workaround: pre-create both dirs from one host with sync, drop_caches on the peer.
- **rmmod transient busy** during cluster_reset: even after umount, the module can be refcnt>0 briefly while bast_poll_thread joins. cluster_reset.sh has 8× retry × 10s; usually 1-2 retries needed.
- **dd-zero before mkfs:** LIO-backed device sometimes has stale-disk content that mkfs's pwrite-O_SYNC zero doesn't durable. Run `dd if=/dev/zero of=/dev/sda bs=1M count=256 oflag=direct` first.
- **Test cluster runs UTC, dev host runs CDT.** Use `date -u` when reading journalctl across nodes.
- **rsync_bench.sh's `dmesg_hits` regex** is conservative — adds new pattern requires careful escape (it's already shell-double-quoted and grep-ERE'd).
- **The QNAP LUN is reachable by every LAN host that ever logged into its target, and a stale host keeps writing it (0.89.4).** `tests/setup/prep_fs.sh` dumps the heartbeat table twice 3 s apart before any PR action or mkfs and refuses under any advancing record (`FS_PREP_FAIL ... still heartbeating`). Its first firing was not a previous-lap node: serv (192.168.1.5) had an fstab `_netdev` mount of the LUN with the physical-campaign DKMS mxfs, heartbeating slot 2 with a foreign fs_gen that the rig nodes skip silently and mkfs's verify read as "storage dropped writes". A stamp that advances under a torn-down fleet is the writer's own boot clock: read it, sweep the LAN (`tools/mxfs_sshpass.sh <ip> "cut -d. -f1 /proc/uptime; lsmod | grep mxfs; grep mxfs /proc/mounts"`), and stop the host; the cluster's WE-AR reservation fences such a writer only during a tenure. Evidence `tests/evidence/20260919T134608Z_foreign_writer_serv_s67/`; the module-side blindness is a queue record. `tools/mxfs_whohas.sh` finds local holders of a file/device without the fuser/lsof mmap_lock walk. findmnt/blkid cannot read an MXFS filesystem identity (the envelope offsets the superblock): use `mxfs_dev_ident`/`mxfs_dev_field ... fsid` from `tests/lib/rig.sh`.

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
underlying kernel bug that caused the hang: `docs/rulings/dir-reuse-32-architectural-review.md`.)

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
any such probe BEFORE running it at 32 nodes. See `docs/history/clyde-ext4-jbd2-wedge-shared-lun-on-root-fs.md` and
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
  Verify with `tools/chk_mxfs -v ~/disk.img | grep agcount` and a fleet
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

## sess404 — fleet param setter + kill-lap evidence layout
- `tests/fleet_set_params.sh "<k=v> [k=v ...]" [nodes] [outfile]` — sets runtime mxfs
  module params on every node IN ORDER (parallel ssh, per-node rc + readback, SETFAIL
  -> exit 2).  Use after `run.sh 32 caw prep_cluster` to run a board with enforcement
  armed: `tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1"`
  (prerequisite first — the enforce setter fails closed without it).
- tmpfile_churn_kill.sh laps on 0.24.2: kill5e/5f/5g (auto:shared) + kill4d (auto:single)
  all PASS, evidence tests/evidence/sess404_v0242/kill5*/ + *_sweep/ (per-node dmesg
  counts EXH/CAWEXHAG/YBAG/DEMOV/AGLF).  Whether a shared-AG victim's slice carries
  REDUNDANT_CLEAN images is timing luck (5c/5f yes, 5d/5e no) — vary TCK_KILL_AFTER /
  TCK_VICTIM_GAP to get both classes.
- Board chunking walls measured on 0.24.2 are in tests/criteria/TIMEOUT_BUDGETS.md
  (sess404 section); crash_consistency on a fresh prep is the D-401 86-88 s row.
- d385 stepwise TREATMENT-only run: `D385_OUT=<dir> D385_STEP="arm_prep TREATMENT"`,
  then `arm_lap TREATMENT n` (row-wise, measured 348-379 s/lap; outer 598), `arm_collect`,
  `verdict`.  arm_collect's "(WARN: N/32 node(s) returned non-zero)" = grep rc=1 on nodes
  with no P86/P87 lines — benign.


## sess406 — recovery-manifest matrix, live-preempt test, harness gates

- `tests/rman_matrix.sh <evidence_dir> [arm...]` — arms base_single base_shared
  inject1 inject2 inject3 mutate1 mutate2 busy takeover, each one
  `tests/tmpfile_churn_kill.sh` run with its knobs; `extra_env` is a shell-quoted
  assignment list exported via `eval` in a subshell (values with spaces, e.g.
  `TCK_AFTER_KILL_CMD='tests/fleet_set_params.sh rman_inject=0 32'`); per-arm
  wrapper 260-370 s; summary in `$OUT/matrix.txt`.
- `tests/rman_prover_kill.sh` — the takeover arm's after-kill hook: finds the
  prover (`P-RMAN-INJECT mode=1`), virsh-destroys it, appends it to
  `$TCK_OUT/extra_victims.txt`, clears the knob.
- `tests/tmpfile_churn_kill.sh` gained: `TCK_TEST1_PARAMS`, `TCK_EXTRA_RECOV`
  (widens churn budget + recovery bound for arms with a second death),
  extra-victim pickup (`load_extra_victims`), a **mounted==NODES gate after
  prep** (kill6d: 5 unmounted nodes churned their local root and counted as
  survivors), sweep counters rguard/rterm/rtm/rpv/rbusy on the `rman:` line,
  `TCK_RMAN_EXPECT_TERMINAL` (terminal>=1, P240-QUAR-IMPORT>=1, frc=0; churn and
  chk reported not counted), `TCK_RMAN_EXPECT_GUARD`, `TCK_RMAN_EXPECT_BUSY`
  (>=1, <=8 per node, sealed==victims).
- `tests/fence_live_node.sh <label> idle|churn [victim=test20] [peer=test1]` —
  D-498: sg_persist `--preempt --param-rk=<peer key> --param-sark=<victim key>`
  on `/dev/mapper/mpatha` from the peer (keys == node ids from the 'claimed
  heartbeat slot N for node ID' line); asserts PR IN before/after, withdrawal
  within 75 s, <= 200 conflict commands at the target (clyde `journalctl -k`
  with explicit UTC --since/--until), mount gone, survivors recover.
- PITFALL (sess406): never rewrite `tmpfile_churn_kill.sh` while a harness run is
  in flight — bash reads the script by offset; the in-flight arm's tail executes
  from the new file's bytes. Queue harness edits until the run ends.
- PITFALL: `journalctl --since '2026-08-23 08:20'` on clyde is CDT local time;
  always suffix ` UTC` (or use ISO with Z) — a bare timestamp from the node
  clocks (UTC) queries a window 5 h in the future and returns nothing.

## sess407 — matrix read, harness expectation fixes
- The first full matrix (0.26.2, `tests/evidence/sess406_v0262/matrix.txt`): every
  arm run WITHOUT `target_cache_protected=1 foreign_replay_token_enforce=1` refused
  replay (POLICY-REFUSED rc=-117, quarantine=60, ATOMIC-SKIP) — the DESIGNED
  knob=0 behaviour (ledger #1: default 0 keeps the fail-closed refusal). PITFALL:
  the kill harness can only PASS with ENF; `rman_matrix.sh` now gives every arm
  ENF, and inject1/2 wraps are 310 s (measured non-recovery 122..143 s + the
  150 s recovery bound; the 260 s wrap killed both mid-sweep after recovery had
  completed at +117 s).
- TERMINAL arms assert PER-VICTIM accounting now: `frc < victims` and
  `frc + terminal >= victims` (mutate2: the one-shot mutation hits ONE victim →
  MUTATED-TERMINAL; the other victim's intact slice completes 5 s later).
- Survivor-complete check is `-ge`: the takeover arm's prover finishes its churn
  before `rman_prover_kill.sh` destroys it, so ok=30 against 29 remaining.
- mutate1 on 0.26.2 is the writer-guard monitor-lag finding (dlm.md sess407,
  D-RMAN-WRITER-GUARD-MONITOR-LAG-407); TCK_RMAN_EXPECT_GUARD=1 is its verifier.

## sess408 — host panic C (SCST P&A vs session teardown) + its harness
- `tests/scst_pr_abort_shutdown_race.sh <label> window|stress [X] [Y] [DELAY_MS] [ITERS]`
  verifies the SCST `+caw-abort-reclaim.5` fix for
  `D-HOST-SCST-PR-ABORT-SESSION-SHUTDOWN-PANIC-408` (docs/host-safety.md "Crash C").
  `window`: arms the TEST-ONLY host knob `scst.pr_abort_shutdown_delay_ms`, X
  registers a test key on each of its two iSCSI path sessions (`sg_persist
  --register-ignore` on the per-portal sd device from `iscsiadm -m session -P3`),
  logs one path out, Y fires `sg_persist --out --preempt-abort` at +DELAY/3
  (window A: session in SHUTDOWN with refs → host logs "PR ABORT ALL admitted on
  session … in shut_phase 1") and, for the second path, at +DELAY+DELAY/3
  (window B: refcount zero, tgt_devs still linked → "PR ABORT: registrant … is
  already released … skipping"). Asserts both lines, both P&As rc=0, keys gone,
  no BUG/Oops/CRITICAL in clyde's kernel log; re-logs X in; resets the knob
  (trap) and unregisters the test keys.  `stress`: knob off, ITERS × (register,
  logout, immediate P&A, re-login) — the natural ~ms window; informational count.
- PRECONDITION: X and Y must have NO mxfs mount (the test keys would collide with
  their MXFS PR registration and a P&A would fence a live member). Run it after a
  host reboot / before prep, or on two nodes deliberately unmounted.
- PITFALL (RULE 2d): never run it against an SCST older than `.5` — the harness
  refuses (`/sys/module/scst/version`) because the unfixed target panics the host.
  `scripts/clyde_preflight.sh` refuses a rig run while the knob is non-zero.
- PITFALL (SCST build): `make` in `/src/scst/scst/src` only regenerated
  `scst_itf_ver.h`; `sudo make install` (target `install: all`) did the real
  rebuild. Always confirm `modinfo scst | grep version` AND `modinfo -p scst`
  shows the new parameter; iscsi-scst must be rebuilt too (interface version).

## sess410 — guard FLOOD sustain rule; harness orphans
- `tools/clyde_kmsg_guard.sh`: FLOOD now = >60 lines/s sustained for FLOOD_SUSTAIN_S=60 s of consecutive hot 5 s
  windows (was 2 windows).  A 32-node prep power-cycle is a deterministic ~2270-line / 40 s burst (64 iSCSI
  sessions × 8 cmd-thread start + 8 finish + 8 negotiation lines, all SCST PRINT_INFO — not maskable) and tripped the
  old rule 1-in-3; details docs/host-safety.md.
- A rig harness launched by a rig-runner agent keeps running after the Claude process exits: check
  `tools/mxfs_pgrep.sh fence_live_node|d385_publication_verify|tmpfile_churn_kill|run.sh` before any rig work.
- fence_live_node bounds: hbpause 570 s, logioerr 490 s, preempt 555 s (TIMEOUT_BUDGETS sess409/410 section).

## sess413 — node-death board row (coord=host), D-529 harness, orphan discipline

- **coord=host dispatch class** (run.sh `run_host`, case at the coord switch):
  the criterion script runs ON CLYDE (virsh powers the in-guest harness lacks),
  prints the same `RESULT: <STATUS> ... | measured=... | reason=...` contract
  run_none parses. Env passed: MXFS_NODES/DLM/DEV/MNT/RUN_ID.
- **Terminal `death` category in criteria.json** (categories: suite, tooling,
  caw, tcp, death): run.sh's ROWS come from criteria.json category order, NOT
  the manifest — a category appended last runs last on every transport. A new
  test object MUST carry `"runs": {}` (reset/fail_stale jq crashes on null).
- **node_death_replay** (tests/death/node_death_replay.sh): two ARMED
  tmpfile_churn_kill laps — auto:shared (--no-prep, uses the board's mounted
  cluster) then auto:single (full tck prep; lap 1 unmounts the fleet). It is
  the board's ONLY node-kill + foreign-replay row (sess404 gate finding).
  Measured 32/caw on 0.27.5: shared 111s, single 231s, row 343s/470 budget.
  TERMINAL: leaves the fleet unmounted; anything after it needs prep.
- **Run-lock re-entrancy**: run.sh exports MXFS_RUNLOCK_OWNER=$$ after taking
  /tmp/mxfs_run.lock; a child invocation (host row -> tck -> d385 prep ->
  run.sh prep_cluster) that finds that pid alive as run.sh skips the lock.
  Without it the inner prep dies rc=3 "another run.sh holds the lock".
- **tests/d529_whole_txn_verify.sh**: arm A churn regression (asserts >=1
  ADMIT items>100 and per-lsn classification uniqueness), arm B injection
  (dbg_fr_taint_items_over knob forces whole-txn refusal; asserts no
  ADMIT/skip overlap). TRAP: P227 classification lines carry the probe name
  in TRAILING parens — extract name/lsn/items independently, never
  name-then-fields.
- **Relay discipline (proved sess412→413)**: a harness launched as a plain
  Bash child DIES at the ccloop relay teardown mid-run. Long rig chains must
  be `setsid nohup sh -c '...' &` with per-stage `STAGE <n> rc=` lines
  appended to an evidence chain-log.

## sess419 harnesses (2026-08-28)

- `tests/rig_after.sh <wait-log> <label> <max-s> -- <cmd>`: run a rig command after another
  chain's `DONE` line (queue rig work without polling).  `tests/d0286_race_chain.sh`,
  `tests/sess419_post_chain.sh`, `tests/sess419_purge_chain.sh`, `tests/sess419_master_chain.sh`
  are relay-proof setsid chains; the master chain PROVES a build complete (second `make` must
  compile nothing — the NFS clock-skew warning is real).
- `tests/d0286_depart_race.sh`: observer grace derived from `dead_timeout_ms` (62 s default);
  SKIPs unreachable points (CAW p3/p4, p5 everywhere).
- `tests/f2_iclus_refusal.sh` (icluster_dlm=1 reload; arm must be REFUSED),
  `tests/d0133_sb_mutation_gate.sh` (ioctls ENOTTY, sunit/swidth mount refused, uquota EINVAL,
  clean umount/mount zero refusals), `tests/crossnode_unlink_ubsweep.sh` (clean-departed slot's
  zombies freed by another node's fresh mount + chk oracle),
  `tests/d_purge_nonatomic_verify.sh <label> concurrent|midscan|prefinal` (RULE-5 ruled arms).
- TRAP: `tools/mxfs_pgrep.sh <pattern>` matches ANY process whose cmdline contains the pattern,
  including the calling shell and waiters whose ARGUMENTS name the pattern — killing by its
  output killed a rig_after waiter and the post-chain script (sess419).  Filter on the cmdline
  prefix before killing.

## sess420 harnesses (TCP tokens, no-survivor crash, zero-incarnation refusal)
- `tests/tcp_token_plumbing_verify.sh <label> [nodes] [files]` — step 1 of
  docs/tcp-authority-ledger.md: per-node P228-TOKCLASS / P239-OWNAUTH deltas
  across a private-dir small-file workload on 32/tcp; PASS = noepoch 0,
  durnoep 0, ag>0, durable>0 on every node.  Chain: `tests/sess420_token_chain.sh`.
- `tests/no_survivor_crash_replay.sh <label> [N] [remounter]` — D-OWN-CRASH-
  RECLAIM item 2: fsync'd payload on all N, virsh destroy ALL, boot one node,
  insmod + ARM enforcement BEFORE mount, expect N foreign replays complete and
  every payload md5 intact; clean umount + chk.  First measurement: record wall.
- `tests/hb_epoch_inject.py <img> <slot> show|set <epoch>` — rewrites one HB
  record's incarnation with feature + provenance crcs resealed (crc32c seed ~0,
  no inversion; verified crc_ok=1 on live records).  Only on a DEAD record: a
  live owner's next CAW heartbeat would fail its compare and self-fence.
- `tests/d_recov_zero_epoch_verify.sh <label> [victim] [N]` — D-RECOV-ZERO-
  EPOCH closure: kill, inject epoch 0, expect P238-FENCE-ZEROINC and no
  descriptor; restore epoch, expect normal replay.  Sweep must reach 31/31.

## sess421 harnesses (intent census, mount-window death)
- `tests/d_intents_undischarged_verify.sh <label> burst|clean [O] [V]` —
  D-FOREIGN-SLICE-INTENTS-ABANDONED interim (fail-before-purge).  burst: V
  builds 8 files of 4096 single-block extents (python pwrite with holes,
  fsync), removes them in parallel, is destroyed 2 s in — the last durable
  checkpoint carries an EFI without its EFD.  Expect on O: `P226-ICENSUS
  victim_slot=N ... open>=1`, `P226-FR-INTENTS-UNDISCHARGED`,
  `P241-RECOV-TERMINAL ... reason=8`, ZERO P163-RECOVERY-COMPLETE for N.
  clean: idle victim, open=0, normal publication.  Arms enforcement fleet-wide
  first (the sess407 trap).  Leaves a quarantined slot: prep after.
- `tests/d_mount_window_death_verify.sh <label> window|control [A] [B] [C]` —
  D-MOUNT-WINDOW window arm per the sess420 ruling: A unmounts, arms
  `mxfs.dbg_barrier_hold_ms` (one-shot hold at the top of the admission
  barrier, after the mphase record is armed), mounts detached; B destroyed
  once `P-DBG-BARRIER-HOLD start` shows; hold outlasts the 62 s confirm so
  A's monitor logs P233-MPHASE-DEATH for B and the barrier drains it inline.
  Asserts late=<B bit>, replayed>=1, exactly one P163 for B on A, ordering
  P233 < released < publication < barrier-complete, and ZERO election/replay/
  publication for B on all 30 other survivors.  control: B killed with A
  idle → live path, P233 absent fleet-wide.
- `tests/tauth/` (`make -C tests/tauth && ./tauth_test`) — usermode torn-write
  unit test of `dlm/tauth_store.c` over `pal/linux/user.c` on a temp file; 21
  cases, exits non-zero on any FAIL.  Standalone like `tests/net2`.
- `tests/vergate_livecap.sh <label> [probe] [arm]` — runs a vergate arm with the
  probe node's `dmesg -w` streamed to clyde (the two ENOTCONN/EIO mixed_build
  failures lost their kernel log to the next prep's power-cycle).

## sess422-424 harnesses (TCP authority ledger)
- `tests/tauth/` — `make -C tests/tauth test` runs `tauth_test` (store, 8),
  `ledger_test` (ledger layer, 15 groups incl. page-authority bootstrap/takeover
  refusals) and `dlm_ledger_test` (2-3 in-process DLM nodes on one temp-file ledger,
  11 groups: durable-before-deliver, release ACK, blocker import after master loss,
  D-0287 retention, recovery purge + successor takeover, torn/collision fail-closed,
  lost-GRANT idempotent retry, activation barrier, clean unmount).  The engine test
  links the REAL `dlm/dlm.c` (`dlm/dlm_user_compat.h` shim).  Any dlm.c change: run it.
- `tests/sess422_chain.sh` / `tests/sess424_chain.sh` — build + proof + usermode gate +
  32/tcp (mpatha, `MXFS_DEV`/`MXFS_CRIT`) token verify + d0287 + P-TAUTH sweep + 32/caw
  board.  s424 adds `tests/evidence/sess424_<label>_dmesg/<stage>_testN.txt`: per-node
  RAW dmesg lines (P-TAUTH*, membership, REMASTER status=12, lock-retry exhaustion,
  mount refusals) after every tcp prep/stage — the s422 run captured only counts and
  left its mount/unmount hangs undiagnosable.
- `tests/tauth/formation_test [ramp_ms] [run_ms]` (sess424) — NNODES=12 in-process nodes
  join one at a time while every joined node runs the mount pattern (PR, unlock, EX,
  unlock, 10 retries) on ino=128; asserts no request failed, platter record clean after
  quiesce, no DOUBLE-GRANT, EX grantable on every node.  Reproduced the 0.34.0 rig ghost
  in one lap; the mesh lives in `dlm_mesh.h` (shared with dlm_ledger_test).


## sess429 — sweeps read journald, not the dmesg ring; new reproducer
- The node dmesg ring wraps within minutes under a 32/caw board (test1: ~2 min retained after s433), so kmsg-marker-bounded sweeps read ZERO. `tests/sess429_chain.sh` (mark()/sweep()), `tests/sess416_board_0286.sh` (gate-3 sweep) and `tests/free_home_settle_repro.sh` now record the mark TIME and sweep `journalctl -k -q --since "$MARKTIME"`; each prints JOURNAL_LINES per node so a rebooted node's short window is visible. ccmemory `trap-dmesg-ring-wraps-under-board-kmsg-marker-sweeps-read-zero-use-journalctl-since`.
- `tests/free_home_settle_repro.sh <label> [node] [files] [peer]`: the s432 ino-133 sequence (dd 4 KiB + rm ×N, then drop_caches reclaim) on a prepped multi-node mount; asserts zero P237-EVICT-OBLIGATION / P-SESSION-POISON / P55C-FREE-HOME-UNSETTLED and FREE-HOME == SETTLED; ABORTs if `/mnt/shared` is not an mxfs mount (after node_death_replay the cluster is torn down and the workload would hit the root fs). Wired into sess429_chain.sh as stage `fhs` (after prep, before dre).
- `tests/free_foreign_realloc_repro.sh <label> [node] [files] [peer]` (sess430): same-node `dd; sync; rm; dd; rm` chains (records both lives' inos — same ino = the recycle path) then drop_caches, then the PEER creates 4×N files in the same dir to reallocate the numbers. FAIL on any P55C-FREE-FOREIGN whose ino is a chain ino, any P-CR62 DISK-LIVE / P-CR63-DEFER-DISKLIVE / shutdown signature on either node. Expected FAIL on 0.39.0 (the D-0351 chain defect), PASS on 0.39.1. `tests/classify_free_foreign.py` buckets a board sweep's FOREIGN lines (gen delta, per-ino cross-node tag timelines). `tests/sess430_chain.sh <label> <waitlog>`: pre-fix measure on the deployed build → build → post-fix repro → fhs → dre ×2 → board, journald sweeps with `chain_live`/`chain_written`/`disklive` verdict counters.
- `tests/sess429_chain.sh <label> [wait_on_log]`: build → build-proof → tauth usermode gate (now incl. view_format_test) → prep → chk-geometry (authority ledger + authority view) → fhs → dre1/dre2 → 32/caw board → journald sweeps with settled/unsettled/P237 verdict counts.
## sess431 — FREE-publication claim verification + wall-clock analysis
- `tests/sess430_containment_chain.sh <label> <waitlog>` (sess430/431): wait → pre-fix injector (only if fleet sv == tree sv) → build+proof → tauth gate → prep → injector (or `AB=1` → `tests/dialloc_validate_ab.sh`) → (`SHORT=1` stops here) → ffr → fhs → dre ×2 → board (`tests/sess416_board_0286.sh`) → journald sweeps. Sweep HIGHVOL now prints `fp_claim/fp_keep/fp_write/fp_durable/fp_clear_other` and the verdict line `freepub_stale=` (P-FREEPUB-CLAIM-STALE + P238 cls=freepub-stale). Launch with `setsid nohup ... & disown` (survives the relay); ~27 min for a full lap (build no-op) — RULE 0: measured s439 16:54→17:21Z.
- `tests/dialloc_validate_ab.sh <label> nodeA nodeB`: arm0 (knob off) now PASSES on EITHER pre-containment shape — P-CR62/shutdown signatures OR the silent one (X handed out to a created file; s438 on 0.39.4 measured exactly that: rc=1 sig=0 X_handed_out=1). arm1 (knob on) must contain (P-DIALLOC-DISKLIVE for X, X never handed out).
- `scripts/analyze_p_diskslive_p55c.py <evidence_dir>` (needs `<dir>/raw/testN.log` + `<dir>/all_diskslive_lines.txt`): per P-DIALLOC-DISKLIVE, the latest preceding P55C-FREE-FLUSH/CHAIN on ANY node and whether that node then had `P-CLMERGE restored bmode=00` / `P239 arm=restore` / `P56-NL-LOGGED-DIR-SKIP` within 2 s. TRAP fixed sess431: `[ secs]` stamps are per-VM monotonic — the script converts each node to wall-clock from the median of `realms=`/1000 − t (P291-EXWIN carries realms=); never compare raw stamps across nodes.
- `scripts/freepub_claim_chain.py <raw logs...>`: per FREE claim (P-FREEPUB-CLAIM ino/gen/epoch/seq) follows KEEP → WRITE → CLAIM-CLEAR why=; prints `ends:` histogram, STALE lines, and BAD claims (ended other than durable/discharge, or durable without keep+write). Exit 1 on any BAD/STALE. Journals: `journalctl -k -q --since '<MARKTIME>' -o short-monotonic | grep -a mxfs` per node into `tests/evidence/<label>_inos/raw/testN.log` (32-way backgrounded ssh with per-node rc files).
- Evidence dirs: `tests/evidence/sess430_s437_inos` (0.39.3 board, the restore-chain proof), `tests/evidence/sess431_s439_inos` (0.39.5 board, claim chain clean, residual FOREIGN class).
- (sess431) The chain's usermode gate: `formation_test` check 1 ("no lock request failed across the ramp", rc=-35/-11) is the OPEN D-0352 signature and fails ~50% of local runs; the gate prints `STAGE tauth gate: D-0352 OCCURRENCE ...` and continues for exactly that signature only — every other usermode failure still ABORTs the lap. Rate evidence lives on the D-0352 ledger record; never widen this exception.
- (sess432) `tests/lone_mount_create.sh <label> [node=test1] [nodes=32] [arm=fixed|p130|p131]`:
  umounts the whole fleet (per-node bounded, per-node rc files), mounts ONE node alone on the
  LUN (dlm_caw single_node=true), mkdir + 4 creates + sync; PASS = zero P130/P131/'in-use
  inode'/shutdown.  `p130`/`p131` arms set the 0.39.12 knobs (`single_era_hint_keep=0`,
  `false_fresh_enforce=0`) to re-create the D-0353 trigger and expect the fail-closed
  refusal instead of a double allocation.  A node that shut down dirty needs a fresh
  `prep_cluster` before it can mount alone again (D-0355) — run prep between arms.
- (sess432) `tests/vergate.sh` loop arms: set `mxfs.fence_capability_override=1` for the loop
  device (no PR since 0.15.0; restored at teardown) and issue `XFS_IOC_GOINGDOWN` ONLY after
  `/proc/mounts` shows `/mnt/vgate` as mxfs — the ioctl number is shared with
  `EXT4_IOC_SHUTDOWN` and the unguarded call shut down test32's ROOT fs three times
  (s419-s421).  mixed_build MB3 (remount after the dirty shutdown) currently FAILS = D-0355.
- `tests/freepub_platter_home_inject.sh <label> [node=test1] [peer=test2]` (sess431, 0.39.9; chain stage `fph`): arms `mxfs.freepub_drop_once=1` on <node>, frees files until `P-FREEPUB-INJECT-DROP` names X, waits ≤15 s for the re-push, then asserts the chain on X: P187-PUB-REARM → `P55C-HOME-PLATTER buf_mode=00 platter_mode=0100644` → re-push P55C-FREE-FLUSH → P-FREEPUB-WRITE → CLAIM-CLEAR why=durable, no P55C-FREE-HOME for X before that, XRELEASE=0, platter X mode 0 via dinode_inject.py show; zero DISKLIVE/FOREIGN/shutdown on node+peer; knob restored to 0. Budget 120 s.
- (sess433) `tests/lone_mount_create.sh` arms `remount_refused` (expect
  p302>=1, P305-PRESENT, mrc2!=0; teardown sg_persist CLEARs the LU) and
  `remount_snx` (single_node_exclusive=1: P305-REPLACED, replay, file=1).
- (sess433) `tests/d379b_dirty_depart_peer_fence.sh <label> [A] [B] [nodes]`
  (240 s): A departs dirty on a 2-node cluster, B fences the RETAINED key
  (P236-FENCEKIND kind=PREEMPT_ABORT_DONE(16)) and replays, A remounts
  plainly.  D-379 record item 4.
- (sess433) `tests/sess433_chain_0400.sh` — board-wait + build + prep + the
  arms above + lone_crash_replay e1/e0; log
  tests/evidence/sess433_chain_0400_<label>.log.
- (sess434) `tests/lone_rsync_bench.sh <label> [A=test1] [nodes=32]` (120 s):
  RULE 0 lone-node bench — fleet umount sweep, A mounts alone, rsyncs
  /root/open-gpu-kernel-modules (659 MB, 8714 files) into a fresh dir, sync,
  umount; prints `RESULT: PASS|FAIL ... rsync_wall= sync_wall= umount_wall=
  files= bad=`.  FAIL on rsync_wall > 60 s, files != 8714, any
  shutdown/P130/P131/P243 line.  Baseline laps on 0.40.1 (chain 2b) vs 0.41.0
  (chain 3, D-0354 candidate A).
- (sess434) `tests/d_mount_window_death_verify.sh` window arm FIXED: the
  late-mask check moved into the A-replayed branch (RESOLVED-ELSEWHERE retires
  B's bit from `drained` by design), and the cluster-wide publication count
  uses `journalctl -k --since <T0 before destroy>` — the kmsg MARK reached
  only A and C, so the other 30 nodes always counted 0 (s433e false FAIL).
  New arm `window_lone` (record item 3): unmounts every survivor first so B
  is the only other member and A MUST fold the late death and replay B's
  slice inline (late bit + replayed>=1 + A publishes once); 280 s bound;
  chain `sess434_chain2c_0401.sh` (then prep).
- (sess434) `tests/chk_guard_inprogress_verify.sh <label> [slot=5] [probe=test1] [nodes=32]`
  (90 s): D-379 item 5 — unmounts the fleet, saves slot N, forges a LIVE
  stage-1 recovery guard with `recov_forge --live --stage 1` from <probe>
  (SG_IO on the LUN), runs `tools/chk_mxfs -Q` on clyde against
  `$MXFS_SCST_IMG` (~/disk.img), asserts `recoveries in progress 1`,
  `quarantined verdicts 0`, the IN PROGRESS advice, no -376 pointer, rc=5,
  then restores the sector byte-for-byte (crc compared).  First run (s434g)
  exposed D-0358 (forge wrote descriptor v2 vs kernel v3).
- (sess434) `tests/lone_crash_replay.sh` now captures A's kernel lines
  (adopted-slice notice, P308 boundary, P309 log tail) into
  `$OUT/A_pre_destroy.txt` before the virsh destroy — A's journal is volatile.
  NOTE: the `enforce0` arm is a MEASUREMENT arm — `foreign_replay_token_enforce=0`
  is shadow-only by definition, so it can never reach 'replayed'; D-0354's
  closure criterion is the `enforce1` arm.
- (sess434) chains, each detached with setsid and gated on the previous
  log's `DONE`: `sess434_chain1_0401.sh` (node_death_replay row on 0.40.1),
  `sess434_chain2_0401.sh` (fixed mwindow window arm; also waits for
  tests/evidence/.s434_mwindow_fixed), `sess434_chain2b_0401.sh` (0.40.1
  lone bench baseline x2), `sess434_chain3_0410.sh` (build 0.41.0 + fixed +
  bench x2 + d379b + lone_crash_replay e1/e0).

### sess435 (0.41.2)
- `tests/sess435_chain8_0412.sh <label>` — build 0.41.2, prep, `lone_crash_replay enforce1` ×2 (test5/6, test7/8), prep, `lone_rsync_bench`, prep, knob-armed 32/caw board + journal sweep (adds P308/P308NA/P310 counters). Log `tests/evidence/sess435_chain8_0412_<label>.log`.
- `tests/lone_crash_replay.sh`: `quarantine=` now excludes the barrier line's `quarantined=0x0` (was a false FAIL on a real pass, s434j).
- `tests/lone_rsync_bench.sh`: aborts the node-side script on `mrc!=0` (s434j ran rsync onto a rebooted node's root fs — the module was not loaded; never run it on a node that was virsh-destroyed without a prep in between).

### sess436 additions
- `tests/cc_tenure_modesplit.py <evidence_dir> [ino]` — per-mode (EX=5/PR=3) dir-lock
  grant timeline from per-node `journalctl -k` greps (P138-ACQ/P138-BAST/ACQSUM/CCph);
  auto-picks the busiest ino.  Companion of `tests/cc_tenure_timeline.py`,
  `tests/cc_phase_walls.py`, `tests/cc_grantwait.sh`.
- `tests/suite/crash_consistency.sh`: `MXFS_TEST_ENV="CC_PRIVATE=1"` = headroom variant
  (one private subdir per node).  `run.sh` now passes `MXFS_TEST_ENV` to rank 1 too.
- `tests/d_intents_undischarged_verify.sh burst` arms `mxfs.dbg_efd_hold_ms` on the victim
  (0.41.7+: one-shot log force + EFD-transaction hold in `xfs_extent_free_finish_item`) and
  destroys it inside the hold; assertions branch on the published quarantine domain.
  TERM trap captures dmesg on a caller timeout.
- Chain scripts `tests/sess436_chain{1..7}_*.sh` (setsid; gated on the previous DONE).
  Trap: a chain's `timeout N harness` kills the harness with TERM — harnesses need a TERM
  trap or their evidence dir ends up holding only knobs.
- `inode_mht_ms` sweep evidence: `tests/evidence/sess436_chain2_0417_intents_mht_s436b/mht*/`.

## sess445 harness notes (2026-08-29)
- `run.sh` kill-time phase capture (`$tmpd/$kn.ccph`, run.sh ~1358): the remote
  `pkill -f '$script'` used to match the ssh shell's OWN command line and kill it
  before `dmesg | grep mxfs-CCph` ran — every `.ccph` was one bare newline and
  `/tmp/ccph_last` never existed on the nodes.  Fixed with the bracket pattern
  `pkill -f -- '[${script:0:1}]${script:1}'`.  Phase evidence for a
  BUDGET_EXHAUSTED row therefore lives in the retained kernlogs
  (`/tmp/run_<test>_<RUNID>/kernlog_testN`, `mxfs-CCph rank= PHASE=` stamps) for
  every run before this fix.
- NEVER edit `run.sh` or any `tests/*.sh` while a chain has it in flight: bash
  reads top-level code by byte offset, so an insertion above the running point
  makes the live instance execute mid-line garbage.  Wait for the stage/DONE line.
- `tests/handoff_anatomy.sh <label> [P] [F] [MHT] [LOCKTOTAL] ["knob=val,..."]`:
  arg 6 writes arbitrary module params on every node before the burst and echoes
  them into `testN.gate` — the single-build A/B lever.
- `tests/handoff_transfer_attrib.py <evidence_dir>`: re-derives report (g)'s
  release→grant pairing and splits it at the successor's P297-TKT sighting.
  Caveat learned: (g)'s `transfer_ms` pairs a release with the next logged
  `P138-ACQ mode=5`, but minted/adopted EX grants are not in that pool (233
  logged vs 379 releases), so its tail spans whole EX-tenure + PR-batch cycles.

## sess446 harness notes (2026-08-29)
- **A victim's slice holds only its last 2-4 transactions.**  `mxfs_destage_kick`
  (xfs/xfs_mxfs_dlm.c ~2341) log-forces + `xfs_ail_push_all` on every create,
  so the log tail follows the workload within ms.  Measured: 200 fsync'd
  creates + payload per node -> `P273-SHADOW-EVAL buf=8 txn=2` on 31/31 slices;
  24 sync'd creates + `sync` -> txn=3-4.  A crash/replay test that needs a
  specific transaction in the slice must make it the victim's LAST transaction
  (stop the workload the moment the producer probe fires / the allocation fact
  appears; never sync afterwards).  `/proc/sys/fs/mxfs/` does not exist on the
  nodes (xfs_sysctl.o excluded, Kbuild:157) — sysctl writes are silent no-ops.
  `P133-ICLUSTER-SYNCINIT` prints only for the first 20 carves per module life.
- `tests/bootstrap_full_restart.sh` NEG arm (MXFS_ICREATE_CORRUPT=testN): creates
  4 KiB fsync'd files until one returns `ino % 64 == 0` (the create that carved
  the chunk), makes that file the payload (`$OUT/testN.payf`, `.pay` has
  `PAYF= INO= K=`), corrupts `ino|63` offline.  Payload checks read `.payf`.
- `tests/d0512_sf_to_block_replay.sh`: the victim stops at the create whose
  dmesg shows `P-AUTHCAP-RETYPE-*` / `-VOID` / `-INJECT` (sf->block happened at
  create #4 on 0.53.0); NCR = files created; the survivor must list NCR entries
  and read the last one (fix arm).  inject2 on this harness: REFUSED, valid.
- `tests/bootstrap_takeover.sh` `MXFS_TK_LIVE_PROBE=1`: boots the contender
  while the owner is parked at the hold (its record HB thread keeps seq
  advancing) and asserts `P-BOOT-CONTENDER-OWNER-ALIVE`, mount refused, no
  election/fence/takeover, owner HB never LOST; the same contender boot then
  takes over after the destroy (D-0450 negative direction).  Evidence
  `live_probe.txt`, `live_probe_dmesg.txt`, `chk_live.txt`.
- Killing a chain: `tools/mxfs_pgrep.sh 'chain4''4'` — never put the literal
  pattern in the killing shell's own command line (it matches itself and the
  Monitor's tail; sess445 and sess446 both killed their own shell that way).

## sess447 harness notes (2026-08-29)

- `tests/umount_under_quarantine.sh` step 4 is now a FOUR-op namespace probe
  (create/mkdir/unlink/rename, each `timeout PROBE_BUDGET`, on test1 and the
  last survivor); unlink/rename targets `.uq_pre_unlink/.uq_pre_rename` are
  pre-created by test1 BEFORE the victim dies (a churn name the victim already
  deleted lets `rm -f` return 0 without reaching the gate).  Asserts
  `P240-QUAR-NSOP-REFUSE` ≥ 4 per probed host (`$OUT/<h>.nsop`).  Caller
  bound 660 s.
- `tests/tmpfile_churn_kill.sh` recovery-trail capture (`recov_testN.txt`) now
  includes `P-FREPLAY-`, `P97-SWEEP`, `P-DBG-SWEEP`.  `TCK_VICTIM_GAP` (s)
  spaces the two kills; `TCK_PARAMS` arms module params on every node.
- Chains: `tests/sess447_chain51_0515_nsop_verify.sh` (build in place after
  chain 50 → prep → umount_under_quarantine → prep2),
  `tests/sess447_chain52_0514_forced_repro.sh` (knob `dbg_sweep_hold_ms=30000`
  on test1, two auto:shared victims 20 s apart, prints test1's D-0514 trail).
- D-0514 proof shape: `P-FREPLAY-NOTIFY slot=B busy=RUNNING` while
  `P-DBG-SWEEP-HOLD` is in force, and B's `P238-RECOV-LEASE` only after
  `P-DBG-SWEEP-HOLD-END` with the NEXT `inv`.
- 0.54.0 production declaration: `tests/setup/prep_node.sh` caw MODARGS =
  `target_cache_protected=1` (coherence-only domain; a configuration
  declaration, not a test override) and prints `MXFS_KNOBS enforce= rpe= fua=
  tcp= iclus=` after insmod.  `tests/death/node_death_replay.sh` ARM="" (no
  harness enforce override).  `tests/domain_admission_matrix.sh <label>
  [node]` — 7 mount-time rows, bound 240 s.  `tests/tmpfile_churn_kill.sh`
  recov capture also keeps `P285-F4` and `P-DOMAIN-` lines.
  `tests/sess447_chain55_0540_default_on.sh` = build + matrix + board + NDR xN.

## sess452/453 — RETIRE_PENDING settlement harnesses + the printk-newline capture trap

- `tests/retire_pending_admission.sh <N> <victim> <joiner> [probe] [arm]` — ten
  arms (sameboot, joiner, unknown, unknownresv, trunc, slowpr, joinerunk, race,
  genmove, multipending) for the 0.59.x two-phase departure; header documents
  each invariant and RULE 0 budget.  `tests/pr_unregister_fail_restamp.sh`
  modes restamp|crash.  Chain driver `tests/sess452_chain71_retire_pending.sh
  <label> [expected-srcversion]` (aborts on a srcversion mismatch).
- **TRAP (D-0518): a `umount; sleep 1; dmesg` capture can be one line short.**
  Before 0.59.3 the kernel PAL logger emitted no trailing newline, so the last
  `mxfs_pal_log` line of a quiet period sat unfinalized in the printk ring
  until the NEXT printk anywhere on the node.  Any assertion on the final PAL
  marker of a phase (P-DBG-RETIRE-SKIP-RESTAMP, P303) was a false negative;
  any "marker must be ABSENT" assertion on such a line could be a false PASS.
  Fixed at the chokepoint in 0.59.3; when a capture must be taken from an
  older build, `echo x > /dev/kmsg` before `dmesg` flushes it.
- Harness pitfalls fixed in sess453: `prep_node.sh` needs `MXFS_DEV=$DEV`
  (default `/dev/sda` is multipath-claimed → "already mounted or mount point
  busy"); sweep files start with a `MARK=count` header that matches every
  marker name (order dmesg lines only after the `---` separator); the restamp
  lap's key read races the peers' fence (≤ 5 s monitor lap) — accept an
  absence explained by `P236-FENCE-CERTIFIED`.

## sess454
- `tests/setup/prep_node.sh` step 5c runs `tools/mxfs_admit_check.sh` before
  the mount (multipathd reservation_key gate, D-377 item 3); refusal or
  "cannot decide" fails the prep.
- `tests/fence_capability_admission.sh [node] [caw|tcp|both]` (sess505: runs
  the three arms per transport, default both; SCPs the TREE's mxfs.ko to
  `/var/tmp/mxfs_fca.ko` on the node and loads that, and mounts /src via NFS
  if the node rebooted without it): loads the module with the fleet's
  `target_cache_protected=1` (the durability-domain validator otherwise refuses
  the loop mount BEFORE the fence-capability gate); ARM 3 on a loop device =
  `P303-FENCECAP-OVERRIDE` then `P311-CAW-ADMISSION-REFUSED` (CAW) or the
  named `claim_slot failed ... refusing to derive an unclaimed slot` (TCP).
  Measured wall 52 s for six arms; budget 300 s. Its log filter shows only
  named refusal lines — a refusal for another reason reads as "refused but no
  P303 reason": read the full log. The serial console
  `/var/log/libvirt/qemu/<vm>-serial.log` (root) holds a VM's oops when its
  journal stops before the crash; the VMs have no pstore.
- `tests/vergate.sh`: the loop-arm setup gate includes `noncaw_refuse`.
- `tests/retire_pending_admission.sh` count() reads ONLY the `MARK=count`
  header — a marker not in `$MARKS` counts 0 forever (chain 74's four false
  FAILs on `P163-RECOVERY-COMPLETE`).  Add the marker to `$MARKS`.
- New: `tests/settle_token_arms.sh`, `tests/sess454_chain75_admission_arms.sh`
  (gated), `tests/sess454_chain76_retire_pending_0600.sh` (gated + go-file).

## sess456 additions
- `tests/incarnation_mismatch_probe.sh` REWRITTEN: keeps every survivor's `mxfs:`/`disklock:` line since the marker under `tests/evidence/<UTC>_incmis_<arm>/v.<node>` (journalctl fallback if the marker rolled out), saves the victim's pre-injection record (`pre.bin`), zero arm RESTORES the record after the detect window (a zero sector cannot self-heal by design) and expects P-HB-INC-ZERO + PENDING(E1) + P238-FENCE-ZEROINC + no descriptor + REDRIVE→COMPLETE under E1 within 100 s; nonzero arm expects P237-FENCE-SUPERSEDED(-RETIRED), no GUARD in the detect window, then the frozen successor expiring within 180 s.
- `tests/sess456_chain79_0612_incmis.sh`: build 0.61.2 + both probe arms (prep between). `tests/sess456_chain80_d0517_lab_postmark.sh`: LAB build + `icluster_dlm=1 dino_clobber_check=1` + N postmark_crash laps with `dmesg -w` streamed from all 32 nodes (victims' pre-kill lines) + per-lap sweeps, then production rebuild.

## sess464 harness notes (2026-09-02)

- `tests/guard_race_arms.sh` joiner arm: `boot_rejoin` now runs in the
  background with captured output; the arm polls the joiner's `claimed
  heartbeat slot` line, samples the holder's `P99-UBSWEEP-DONE` count at
  claim time, and reports two verdicts: SAFETY (claimed the guarded slot
  while the sweep was unfinished) and AVAILABILITY (no mount within
  `JOIN_BUDGET`=240 s, quoting `P300-CLAIM-*`).  At 32 nodes on a 32-slice
  volume the joiner's ONLY slot is the guarded one, so before the D-0523 fix
  the arm FAILS on availability by design (it is that defect's detector).
  Ruling note: once the claim wait exists, a 180 s LIVE hold cannot both
  exceed a measured tens-of-seconds budget and require a mount — lower
  `HOLD_MS` for the success arm or assert the timeout path.
- New `tests/selftest/dirshard_format_selftest.{c,sh}`: user-mode
  `gcc -Werror` exercise of `include/mxfs/mxfs_dirshard.h` (pure manifest /
  block checks, cookie helpers).  Runs on clyde, no rig.

## sess466

- `tests/dirshard_ioctl.py mkdir|info`: packs MXFS_IOC_DIRSHARD_MKDIR/INFO
  (272/1352 bytes, type 0xB7) by hand; JSON out.
- `tests/dirshard_hash_vectors.sh [node] [dir]`: published SipHash vector via
  chk_mxfs, and kernel INFO name_hash/name_shard == chk under the dir's key.
- `tests/dirshard_stage1_selftest.sh N1 N2`: two-node stage-1 contract
  (mkdir N=16/64, PUBLISHED, Model-A refusals, routed create/lookup/unlink/
  readdir/stat cross-node, rmdir barrier, 1500-entry listing, zero
  P-DIRSHARD corruption lines); leaves dirshard_vectors + dirshard_n64 for
  the platter check.  Chain: `tests/sess466_chain97_dirshard_stage1.sh`
  (install frozen 0.64.0, prep, selftests, fleet umount + chk, 32/caw board).
- `tests/depart_crash_cuts.sh` cut 5: S1 may already be EMPTY (a peer settles
  inside its heartbeat lap); the key-naming proof is then the peer's
  P304-RETIRE-PENDING-SEEN ... via=ident line.  Chain 96 re-runs it.
- `tests/sess466_chain96_crashcut5_rerun.sh`: cut-5 lap on the fleet module.

## sess467
- `tests/guard_race_arms.sh`: new arm `peerloss` (D-0523 ruling STOP-SHIP 4 /
  "last peer dies mid-wait -> bootstrap"): joiner shape, then every survivor is
  virsh-destroyed once NB logs P300-CLAIM-WAIT-START; asserts PEERS-LOST,
  RESTART-BOOTSTRAP, P-BOOT-SEALED and a mount within 480 s (288 s measured
  owner mount for 32 victims + two dead windows + boot), then restores the
  fleet.  Joiner-arm harness fix: the post-claim "holder finished UBSWEEP"
  loop compares against the detection baseline D0 (with the 0.63.1 claim WAIT
  the holder's DONE precedes the claim; chain 94's FAIL was this harness bug).
- `tests/intents_classless_attribute.sh <label> [node] [files]`: builds
  fragmented files on ONE live node, removes them (no destroy), harvests the
  producer's P239-OWNAUTH-NONDUR / P241-AUTHTRY lines by outcome x blft x
  comm (D-FOREIGN-SLICE-INTENTS-ABANDONED RULE-4 attribution).
- `tests/sess467_chain99_d0523_peerloss_attrib.sh`: install frozen 0.64.2,
  joiner + peerloss arms, attribution lap, preps between.  Gated on chain 98.
- Board wrapper: a full 28-row 32/caw board measures 1283-1303 s; a
  `timeout 1200` wrapper (chains 94/97 as written) kills node_death_replay
  mid-row.  Chain 97 corrected to 1320 s.

## sess472 (2026-09-02)
- Frozen builds: `tests/evidence/sess472_frozen_06414` (sv 35FBA14B), `_06415` (4F5F37A9),
  `_06416` + `_06416_lab` (D8320EFC; LAB = `make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1`,
  distinguished only by `modinfo | grep mxfs_iclus_relmark_lab`).  Scratch-build recipe
  (rsync excluding *.o/*.cmd/*.ko/*.mod/*.mod.c/modules.order/Module.symvers/tests/evidence,
  then `rm -f` the five mod files, then `make -C /lib/modules/$(uname -r)/build M=$S modules
  -j$(nproc)`): 35 s full build; verify `grep -c /src/mxfs/ $S/mxfs.mod` = 0.
- `tests/d488_unlock_exit_arms.sh`: the contender Y now **removes** X's files (rm x$i) — MXFS
  pins inode allocation AND shared-dir block growth to the creating node's own AG, so creates
  in X's directory never contend for X's AG (all chain-111 s470c arms were INCONCLUSIVE).
- `tests/inact_cert_arms.sh <arm> <node> [label] [peer]`: a peer (default test2 /
  `$INACT_PEER`) walks the directory and reads every file before the rm; without that the
  files are UNPUBLISHED and every certificate install is refused `try=7` (chain 108 s472b:
  all seven arms vacuous).  finish() fails the arm on any `installed=0 try=7`.
- `tests/dirshard_stage1_selftest.sh`: the INFO-routes sed range end is `\$p` (was `\\\$p`,
  which reached the remote shell as `\$p` → 'unterminated address regex' every lap).
- Queue launch idiom used all session: `setsid nohup env GATE=<prev log> PROD_KO=… PROD_SV=…
  bash tests/<chain>.sh <label> >/dev/null 2>&1 &`; chains without PROD_KO run the tree's
  mxfs.ko, i.e. whatever the previous chain installed — order matters.  Kill a chain that is
  still in its gate loop by pid (check `/proc/<pid>/cmdline` first; `tools/mxfs_pgrep.sh`
  also matches the calling shell).
- Chain 112/113 = `tests/sess470_chain109_dirshard_06411.sh` relaunched with PROD env; its
  dmesg captures land in `tests/evidence/sess470_chain109_dmesg_<label>/` and the selftest
  dir in `tests/evidence/<stamp>_dirshard_stage1/`.

## sess473 (2026-09-02)
- `tests/dirshard_stage1_selftest.sh` step 7: the N=64 `info` pipe now strips the tool's header
  line with `sed -n '/^{/,\$p'` like steps 1/4 (json.load raised on every lap before).
- NEW `tests/dirshard_reuse_peer_list.sh <creator> <peer> [laps]` (D-0533): per lap, arm A =
  creator sharded mkdir A + 8 files, peer lists (caches members), creator rm+rmdir A, mkdir B
  (number reuse), peer lists B — must be 8 entries, rc 0, < 300 ms (RULE 0); arm B = same with
  the PEER doing the rmdir of the reused dir D (its free path probes members it cached under C).
  Verdict needs peer `P-DIRSHARD-STRANGER=0`, `P-DIRSHARD-SHELL-UNCONVERGED=0` and
  `P-DIRSHARD-SHELL-ADOPTED>0` (0 = VACUOUS: the reuse never landed on a number the peer cached).
  Requires the 0.64.20+ module (checks the ADOPTED string in mxfs.ko).
- NEW `tests/sess473_chain115_d0533_dirshard_06419.sh` = chain-109 shape + the reuse harness on
  the frozen 0.64.20 (`tests/evidence/sess473_frozen_06420`, sv 219263724F44BF60A6D7297); dmesg in
  `tests/evidence/sess473_chain115_dmesg_<label>/`, chk in `sess473_chain115_chk_<label>.txt`.
- `tests/d0527_untrusted_iget_peer.sh`: probe-line sweep is now bounded by the peer's UPTIME mark
  (chain 110 s472k counted 5 NOREC lines from an hour-earlier run: the old sweep read the whole
  ring); reads `untrusted_imap_aglock_n` before/after; verdict FAIL on any post-mark
  UNTRUSTED-FREE/NOREC, VACUOUS if the counter did not advance; prints the cold-open wall.
- Frozen builds: `sess473_frozen_06419` (sv 9576BB1B, pre-review cut, ran once as an orphan),
  `sess473_frozen_06420` (sv 21926372, review items), `sess473_frozen_06421` (sv 006190AC,
  + D-0534 manifest-block refresh).  The reuse harness now also FAILs on peer
  `P-DIRSHARD-CORRUPT>0` and prints `blk_refresh=` exposure (D-0534 arm vacuous at 0).
- `tests/inact_cert_arms.sh` (sess474, chain 108 s473c harvest): foreign/gone arms set
  `mxfs.ifree_eager_durable=1` (`eager()` helper) for their rm so the SYNC INACT-EXREL revoke
  (knobs 2/5) is the retiring path, and fail on `P128-INACT-DEFER` for the arm's ino; new arms
  `evictforeign` (knob 6, evict cls=2) and `evictactive` (knob 7, evict cls=3), build >= 0.64.24.
  `tests/sess469_chain108_inactcert_arms.sh` takes `ARMS_NOSHUT` / `ARMS_SHUT` / `DEFER_ARM=0`
  overrides (s474a: ARMS_SHUT="foreign gone evictforeign evictactive").
- `tests/inact_cert_arms.sh` (chain 108 s472u harvest): `mkrm` now logs an `INFO mkrm` line
  (inos, peer-walk status, `rm_rc/left/ring_lines_added/unlink_trail`) and writes `$OUT/inos.txt`;
  `finish()`'s try=7 UNPUB check is scoped to those inos (the defer arm's 1100-file filler is
  removed unpublished by design); the foreign/gone arms `sync + drop_caches` with the knob still
  set (the knob-2/5 injection lives at certificate RETIREMENT, which every free defers via
  P128-INACT-DEFER — the old arms cleared the knob first, vacuous); defer's evict_ok pre/post are
  both whole-ring.  Chain `sess469_chain108_inactcert_arms.sh` runs defer LAST: the
  `P-INACT-CERT` pr_warn is capped at 96 per module load and the filler burns it.
- TRAP (repeat of sess468): a chain "waiter" whose gate has already opened is a RUNNING chain —
  `kill <pid>` leaves its `timeout N harness` child alive (own process group) and it runs
  concurrently with whatever you relaunch (this session: laps 11-20 of the orphaned reuse
  harness ran through the relaunched chain's prep and pre-filled test2's buffer cache, which
  turned the relaunched selftest's N=64 stage into a D-0534 FAIL).  Before killing, grep the
  chain's LOG for its START line; if present, also kill the harness pids (mxfs_pgrep on the
  harness name, then confirm via `/proc/<pid>/cmdline` — the pattern matches your own shell too).  Scratch dir reused across builds: an incremental
  rebuild is ~5 s; a source edit that lands AFTER the agent's rsync is NOT in the .ko — verify by
  `strings -a` for the newest marker before freezing (caught once this session).

- `tests/sess474_chain116_d0133_sb_recount.sh` (sess474): D-0133 reproducer/verification — prep, a
  2-node dirshard reuse burst (WORKERS pair rotates per lap), TIMESTAMPED parallel fleet unmount
  (`P-UNMOUNT-ORDER node start_ns end_ns rc`), every node's `P-SB-SYNC-PRE/WRITE/POST`,
  `P-SB-SUMMARY-LOCK/UNLOCK`, `P-SB-RECOUNT-DONE` lines, `FINAL-WRITER` (last unmount end) and
  chk.  0.64.26: 2/2 chk FAIL (the measurement); 0.64.28 (A+ fix) = the verification laps.
- `tests/audit_ilock_nowait_pairs.sh` (sess474, D-0532): every `xfs_ilock_nowait` ILOCK site must
  release raw (`xfs_iunlock_nodlm` / `up_*(&ip->i_lock)` / `mxfs_iunlock_rwsems_raw`) or carry an
  explicit `mxfs_dlm_ilock_begin`; exit 1 on a plain `xfs_iunlock`.
- `tests/d0535_xattr_reuse.sh` (sess474 fix): the peer evicts (drop_caches -> P141-UNLK-EXCLR)
  after its rm so the victim's dialloc no longer skips the number held by the peer's deferred
  grant; records every g_k ino and the P-CR63 shell hit.
- `tests/inact_cert_arms.sh` defer arm: `FMARK` kmsg mark before the 1100-file filler bounds the
  scoped UNPUB check (the filler reuses the arm's freed numbers).

## sess475 (2026-09-02)

- `tests/mxfs_sb_bytecmp.sh snap <img> <out> [xfs_data_offset]` / `cmp <label> <pre> <post>`: 512-byte XFS SB sector snapshot + byte-compare excluding icount/ifree/fdblocks/crc/lsn (GPT bar for D-0133).  chk_mxfs -v prints `xfs_data_offset=` (793497600 on the current image).
- `tests/sess474_chain116_d0133_sb_recount.sh` now snapshots the SB around the fleet unmount and prints `SB-BYTECMP` + `SB-CHK-MATCH`.
- `tests/sess475_chain116_d0133_sb_seal.sh` (chain 116 v2, 0.64.30): arms normal/adversarial/latedirty/holderfail; verdict = 32/32 lock rc=0 at put_super, distinct grant epochs, 32/32 P-SB-SEAL-OK, 0 seal violations, highest-epoch writer == chk, every node's last P-SB-WRITE-SUBMIT locked=1; adversarial = waiter's epoch == holder's + 1 and wall >= 0.8 x pause (+ D-0536 measurement from a bursting mounted peer); latedirty = dirty departure + peer P163 recovery; holderfail = virsh destroy inside the hold, waiter recounts fresh.
- `tests/d_intents_undischarged_verify.sh` burst arm publishes the frag files through a peer (`INTENTS_PEER`, default test2) before the rm — chain 105 s472m was VACUOUS for fix A (try=7 UNPUB).
- TRAP: a chain launched gated on a log that already has DONE starts immediately; re-gating = kill the waiter (its pid from `tools/mxfs_pgrep.sh 'bash tests/sess4'`) and relaunch.  `tools/mxfs_pgrep.sh <pat>` also matches the calling shell if the pattern appears in its command text — check `/proc/<pid>/cmdline`.

## 2026-09-03 (sess481): `suite_plan` — a run cannot pass on checks it never made

`tests/suite/lib.sh` reported `checks=N passed=N failed=0` and nothing else. That
cannot distinguish **"nothing failed"** from **"nothing was checked"**, and the
difference is not academic: the 32-node `crash_consistency` row spends its entire
90 s budget in the write phase and reaches the cross-node durable verify — 200 of
its 204 assertions — on **zero** nodes, while reporting `checks=1 passed=1
failed=0`. That record was read as a clean run for a full session.

- `suite_plan <n>` declares how many assertions this run intends to make. Call it
  once the count is known (it usually depends on `$NODES`) and **before the work
  starts**, since the watchdog can fire at any point after that.
- `suite_step`'s breadcrumb, the watchdog's `BUDGET_EXHAUSTED` record, `finish()`
  and `finish_state()` all now carry `planned=` and `notrun=`. `run.sh` passes the
  `measured=` blob through verbatim into `first_fail[...]`/`rank1[...]`, so the
  board cell shows them without any change to the aggregator.
- **`finish()` refuses to report PASS when fewer assertions ran than were
  declared** — reason `assertions_not_run planned=N ran=M`. A run proved nothing
  about what it did not check.
- Tests that never call `suite_plan` report `planned=0` and behave exactly as
  before, so this is opt-in per test.
- Pitfall found while writing it: the watchdog's `failed=` parse was
  `s/.*|failed=\([0-9]*\)/\1/p` — anchored on `failed=` being LAST in the
  breadcrumb. Appending any field after it makes the substitution leave the
  remainder in the captured value. Fixed to `...\).*`; check that sed if you add
  another field.
- `tests/suite/crash_consistency.sh` declares 204 at 32 nodes (`3 barriers +
  (cc_k+1)*NFILES verify + 1 count`), and `cc_k` moved up above the first check so
  the plan can be computed before it. Under-declaring is safe; over-declaring
  would fail a healthy run, so the conditional sharded-mkdir check is not counted.
- Verified by `tests/d384_terminal_record_guarantee.sh` (13/13, local, no rig).

## 2026-09-03 (sess480): `tests/rig_wait_free.sh` — wait on the lock, not on a log

Chains here gate on the previous chain's `DONE` line. That is not the same as the
rig being free, and on 2026-09-03 the difference cost a near-miss: four chains woke
within 30 s of one `DONE`, a board instance left parked by an earlier session won
`/tmp/mxfs_run.lock`, two chains hit "another run.sh holds" and burned their whole
launch to a one-second FAIL, and a LAB build chain began relinking `mxfs.ko` while
that board's preps were shipping it to 32 nodes. The relink was killed with seconds
to spare — `mxfs.ko`'s mtime confirmed it had not landed. Had it completed, the
board's srcversion would have split across the fleet mid-run, silently corrupting a
run being collected as closure evidence for a critical record.

`tests/rig_wait_free.sh [timeout_s]` blocks until no process holds an fd on the run
lock and no `make` is running; exit 0 = free, 1 = still busy at the deadline. It
walks `/proc/*/fd` symlinks and `comm` — never `pgrep -f` or `ps aux`, which read
every process's `cmdline`, take its `mmap_lock`, and have wedged this host before.

Three rules it encodes:

1. **A build is a rig operation.** `make modules` is exclusive with any run, because
   the preps ship the tree's module to the nodes.
2. **Sequence, don't fan out.** Independent chains racing for one exclusive resource
   is a design error, not a timing problem to narrow.
   `tests/sess480_chain122_sequencer.sh` runs the stages in one process with a
   rig-free wait between each.
3. **A script parked in its gate loop counts as running.** Editing it shifts the
   byte offsets bash resumes from. A chain-119 instance parked on its gate resumed
   into shifted code and ran its board *detached from its own logging* — the board
   executed and recorded to `criteria.json`, but its harness wrote nothing to its
   log. Check `/proc/*/cmdline` for parked instances of a script before editing it.

## sess487 — the unmount A/B harness, two node-command traps, and the create-split chain

- `tests/sess485_chain133_agfree_hoist_ab.sh` (laps 1-5, labels s485a/s486a/s487a/s487b/s487d)
  is the base-vs-fix A/B for the unmount AG-publication window. Since lap 3 the
  node command PARKS the fd holder in a fifo read, `sync`s, releases it, `wait`s
  for it and runs `umount` as the next statement, so deferred inactivation is
  pending at put_super by construction; it captures every hung node's task
  stacks and unfiltered kernel journal BEFORE anything reboots it; it counts
  `P126-XFSAILD-SKIP-AGMETA` after each node's publication line (the mutation
  observable the pre-fix ordering actually produces — the guard turns the write
  into a hang, so the submit-time counters stay 0); `LEGS="base base fix"` is
  legal. Its lap-4 closure rule is declared in the header BEFORE the run it
  applies to. Read the base leg's hang captures ONLY through a subagent digest:
  raw kernel stacks in a session's context tripped the server-side safeguard
  twice (sess485, sess486).
- Two bash facts that each cost a lap (ccmemory
  `trap-background-subshell-double-fork-and-and-list-precedence-in-ssh-node-commands`):
  under a non-interactive shell `( list ) &` forks twice, so `$!` holds no fds
  (its child does — count `$!` plus `/proc/$!/task/$!/children`); and
  `a && b && ( list ) &` backgrounds the WHOLE list, so setup raced the
  foreground and, on nodes not rebooted between legs, a stale `/run` flag from
  the previous leg deadlocked the command on a stale fifo with no umount ever
  run. "Hung" with no task in the hang capture is the harness.
- `tests/sess487_chain137_create_split.sh` builds and deploys the tree module,
  proves the `rfr_ms=` field is linked in, then runs `crash_consistency` three
  ways with `mxfs.create_cost_ms=1` arm-verified on 32/32: shared, private
  (`CC_PRIVATE=1`), and shared with `mxfs.dir_persig_flush=2` (an ablation of
  the per-modify directory flush, not a fix). It sweeps `P132-CREATE` and
  `P483-DIRTENURE` from every node's journal itself — the harness archives
  kernlogs only for a FAILING row, which is how chain 128 lost its private arm.

## sess482 — two new chains, and a harness-shape hazard worth knowing before reading any pace number

- `tests/sess482_chain129_create_ladder_F.sh` — holds P at 32 and varies **F** (files/node) over 8/16/32/64/128 via `create_scale_curve.sh`'s first argument with `LADDER=32`. It exists to falsify a reading of chain 124, not to confirm one: a spike recurring at some op index K means a **batching quantum** and K is the batch size; op1's share falling smoothly with F and no second spike means a **one-time admission** cost. It prints per-index means and flags any index whose mean is ≥10x the median, so the two predictions separate in the raw series rather than in a summary statistic.
- `tests/sess482_chain130_affine_audit.sh` — runs `node_death_replay` twice, control then armed with `mxfs.affine_audit_pct=5`, and sweeps `P165-AFFINE-AUDIT*`. Chosen because that row currently passes with real headroom (368-380 s against 470 s) *and* manufactures a dead parent incarnation every lap. Four hard gates, each guarding against a clean-looking zero: `modinfo` must expose the knob, readback must be 32/32, the **control** lap must yield zero audit lines (proves the knob gates), and the **armed** lap must yield nonzero `n` (proves it armed). The verdict rule — including that `operr` is not a miss and that a zero is a `3/n` bound quoted with `n`, never a proof — is written into the script *before* it runs.

- `tests/sess480_chain126_cc_private_barrier.sh` — the shared-vs-private A/B for the failing `crash_consistency` row. **Its freshness gate was wrong until sess483 and it discarded the experiment's own answer.** The gate asked "did the row run?" by looking for a NEW `tests/evidence/run_crash_consistency_*` directory — **which is written only when the row FAILS**. A passing row writes none, so both `CC_PRIVATE=1` legs (the outcome the chain existed to detect) were reported `NOT SCORED` while their captured output said PASS 32/32, 204/204 checks, 18–19 s of a 90 s budget. Now keyed on the `run_id=` stamp run.sh prints on **every** invocation plus the presence of a `nodes_pass` verdict row; the evidence directory is used only for per-node parked/straggler detail, and its absence prints "nothing parked" instead of refusing the leg. **Generalise this before writing any liveness gate: key it on something the step emits in every outcome, and ask what the gate does on the result you are hoping for.**
- `tests/sess483_chain132_dirtenure.sh` — tests whether the shared-directory create cost is driven by F at all, and if so whether the mechanism is a collapsing directory tenure. **Two structural lessons are baked into it and both generalise.** (1) **It runs the ladder forward AND then backward on the same un-re-prepped filesystem.** Chain 129's sweep ran 8→128 in one fixed order, so "cost rises with F" and "cost rises with how long the test has been running" fit the same numbers; the reverse pass separates them — F driving it repeats the mapping, elapsed time driving it inverts it. Any parameter ladder run in one direction on state that is not reset between points has this confound. (2) **Every figure is reported as p50/p90 with its n, never a bare mean**, because the acquire-wait distribution is bimodal (dlk_ms p50 1 ms against p90 2133 ms) and a mean moves for two different reasons. It also refuses to run unless the module carries `gap_ms` as well as `P483-DIRTENURE`: without the gap field a tenure of 1 cannot be told from grant churn under retained control, and those are opposite findings.
- `tests/sess483_chain131_agfree_window.sh` — measures the unmount AG-release window for `D-UNMOUNT-AG-GRANTS-PUBLISHED-BEFORE-METADATA-QUIESCE-0483`. Builds, freezes, preps 32 nodes, churns `FILES` (default 400) files per node in a **private** per-node subdirectory (private deliberately: the shared-directory create path costs seconds per op on this fleet and would spend the entire budget without adding one inode to the inodegc queue), then unmounts the whole fleet and reads one `P483-AGFREE-WINDOW` line per node. Five gates, in this order, each guarding a specific way the run could report a meaningless zero: (1) `strings mxfs.ko` must carry all three probe literals — **and the pattern is `AFTER-AGFREE`, not `P483-AGMETA-AFTER-AGFREE`, because that probe's format string is `P483-%s-AFTER-AGFREE` and picks its tag at runtime, so the runtime tag is not in the module at all**; (2) every node's `/sys/module/mxfs/srcversion` must equal the frozen build's; (3) per-node churn accounting, so a node that produced no files is not silently counted as a clean zero; (4) per-node umount rc **and** `mountpoint` recheck; (5) the verdict **refuses to score** unless the window line was actually printed, and prints `covered/32` as the denominator. It also sweeps `P482-UMOUNT-AGREL` for `ags_released` — **the population denominator**: an AG handed off cooperatively before unmount is never published by this path, so a fleet with `ags_released=0` has an empty window by construction and its zeros say nothing about the defect. Field extraction anchors on the space before each name because `nodlm_wr` is a suffix of `iclus_nodlm_wr`.

**The hazard, and it applies to every pace harness here.** `create_scale_curve.sh` clients are **closed-loop and start together**: a node cannot issue op2 until op1 has been admitted. So the entire 32-way queue drain, plus all cold first-touch cost (lock-resource setup, cache and journal warmup), is charged to **op index 1 by construction** — a >90% op1 share appears whether or not any reusable per-node admission state exists. Cheap ops 2-8 therefore describe *within-turn service time*, not cluster-wide concurrency, and a serialised **batched** lock produces exactly that shape with each node's wait landing on its own op1 at a different wall-clock moment. Two corollaries: a lower shared-vs-private admitted-call latency does **not** imply better parallel throughput, and the apparent "~45 ms per participant" op1 slope is about **half** a rotation (a median op1 has half the queue ahead of it), i.e. ~91 ms per preceding turn. With only 8 ops/node a run can also simply END before the holder's quantum expires — which is the whole reason chain 129 varies F.

## sess488 — the refused-item (AIL pin) harnesses, and a run.sh shape that silently skips a leg

- `tests/sess488_ailpin_inject.sh` — `D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-PIN-0487`. One leg per module build: installs the frozen ko, preps 32 nodes, then on the victim writes an AG number to `/sys/kernel/debug/mxfs/<dev>/inject_unheld_agmeta_dirty` (0.69.6+): the injector refuses (`-EBUSY`) any AG the node holds, so the harness walks a list of AGs until one is accepted and reports which. It then waits the grace period, runs a 200-create workload on two peers (unaffected = rc 0 inside 30 s), sweeps the victim's journal for `P126-XFSAILD-REFUSE`/`P126-AIL-PINNED`/shutdown lines, and attempts `timeout 50 umount` on the victim. **Leg A (0.69.6, report-only push) is expected to HANG the umount** — the harness captures the umount task's stack and the `P128-AILSTUCK` dumps (which must name the injected AGI's daddr), sweeps the whole journal before touching the node (journald is volatile), and only then virsh-destroys/starts it. Leg B (0.70.0, fail-stop) expects the umount to return, then remounts the victim and reports the slice replay's decision lines on the injected image. Node journals are swept **before** any power cycle, always.
- `tests/sess488_ailpin_fleet_umount.sh` — `D-SB-SUMMARY-LOCK-HELD-ACROSS-UNBOUNDED-LOG-QUIESCE-FLEET-CONVOY-0487`. Same injector on one node, then all 32 unmount at once, each timed on the node (`UMOUNT_MS`); reports the 31 peers' umount_ms distribution and the fleet-wide `P-SB-SUMMARY-BAST` (refused-while-held) count. Leg X = 0.70.0 (peers stall up to the grace period behind the victim's lock), leg Y = 0.70.1 (pre-lock push: peers unaffected, victim's `P126-AIL-PINNED` precedes any lock line).
- **`run.sh 32 caw <rows>` with a test filter never preps.** If the fleet marker's srcversion differs from the tree's it refuses outright ("Run './run.sh 32 caw' or prep_cluster first", rc 1 in ~8 s); if it matches it runs no prep at all, so `MXFS_EXTRA_MODARGS` never reaches insmod. Chain 139's first attempt (s488a) lost both legs to this in 8 s each and its readbacks then reported the *previous* chain's fleet state. Every A/B that ships a module argument must `./run.sh 32 caw prep_cluster` per leg and read the parameter back from all 32 nodes **before** the rows (the s488c version does).
- **A chain's cleanup can change the tree's module.** `tests/sess485_chain133_agfree_hoist_ab.sh` ends with `install_ko "$FIX_KO" restore`, which copied the frozen 0.69.3 ko over `mxfs.ko`; the next chain read `ko_sv` at its START line from a different module than the one it later found after its gate, and its `strings` probe gate aborted. Read the ko identity **after** the gate and the rig wait, and re-check it against what the harness needs — `STAGE install_ko` lines exist for this.
- `tests/sess487_handoff_coldread.sh` round 2 of every kill set printed `SETUP FAIL (mkdir on test1)` with no artefact: the mkdir check discards stderr (`2>/dev/null | grep -q MKDIR_OK`). The holder of the previous kill round was virsh-destroyed and test1 was its peer; whether test1's mount was briefly unwritable or the ssh timed out is not recorded. Capture stderr to a file in that check before reading anything into it.

## sess493 — leg S, the remount stage, the crash-durability harness, and a silent check

- `tests/sess488_ailpin_fleet_umount.sh` legs **Z** (under-lock injector, `mxfs.dbg_sb_inject_unheld_agno`) and **S** (= Z prepped with `MXFS_EXTRA_MODARGS=closure_skip_publisher_purge=1`, readback-gated on test2, so the survivor demand scrub is the only repair path). Both print a `D0487-BAR:` line — publisher/scrub strip counts, `P487-SBSUM-OUT-OF-CLOSURE`, `P240-QUAR-IMPORT`, peer `P277-`/`P302-` counts (the departure-side proof that only the victim departed dirty), peer `P-SB-SEALED` count and max epoch against the victim's grant epoch — then **remount test2 alone** (`/dev/mapper/mpatha`, 120 s) and list which slots that mount fences/recovers. The remount is where D-0493 surfaced: after a quarantined victim the bootstrap refuses (`P-BOOT-KEY-UNCLASSIFIED ... carry no identity block`), so `slots=` is empty and `MOUNT_RC=32`; read `remount_test2.txt` before calling the leg's bar unmet.
- `tests/sess493_d0492_superset_harvest.sh <evidence dir>` — parses `P491-NEWTENURE-RETIRE-UNDEST` lines (0.70.8/0.70.9 only) into superset/missing histograms split by `new_tenure`, `wseq`, `ops`, and by which arm matched (`b_epoch==cur_mep`, grant-gen). Uses python3 for the field parse: the system grep is ugrep and rejects long regexes.
- `tests/sess493_d0492_crash_durability.sh` — the crash-after-fsync test D-0492 needs: preps the fleet with `KO=` and `MODARGS=` (default `dir_persig_flush=0`, the release-only direction; the production default is 1), then B and A (`B=test2`, `A=test3`) alternate `R=6` rounds of `NF=10` fsync'd creates in one shared directory so every A round is a new tenure, A keeps the directory after its last round, logs `TAILN=300` unrelated fsync'd creates in a private directory so its log tail moves past the retired records (a slice holds only its last few transactions), and is `virsh destroy`ed. The survivors fence and replay; B and C (`test4`) drop caches and compare `ls` against the expected name list; `AT-RISK` names the victim's last round. `RESULT PASS` iff missing=0 on both and a `P163-RECOVERY-COMPLETE` was seen. A is restarted and the script waits for ssh (≤150 s) so the next chain's prep finds it. Control lap s493c on 0.70.9 (expect the loss), fix lap s493d on 0.70.11.
- `tests/suite/crash_consistency.sh` rank 1's **"cc total durable file count"** was the one check that could fail without naming anything (s493a lap 1: test1 203/204, zero `mxfs-cc-FAIL` on any node). On a mismatch it now prints `mxfs-cc-COUNT reader=r1 exp= act= absent=[...] extra=[...]` to kmsg and the forensic file — absent = expected names readdir did not return, extra = names no node created.
- `tools/scratch_build.sh` now removes its scratch copy after the freeze (`KEEP_SCRATCH=1` retains it) and copies the build logs into the frozen dir: eleven forgotten copies (15 G) on clyde's root filesystem were the sess492 preflight refusal.

## sess494 — the crash-durability shape that actually loses, and the D-0493 bar

- `tests/sess493_d0492_crash_durability.sh` `SHAPE=single` (s493c/s493d) is NON-DISCRIMINATING: a one-block shared directory is re-logged by every create, so the last create's surviving log item writes the whole block and missing=0 on the buggy build too. `SHAPE=multiblock` (now the default) is the shape that loses: B prefills `NPRE=220` 24-char names (three data blocks, leaf format — `xfs_dir2_leaf_addname` places a new entry in the LOWEST data block whose bestfree fits), and the victim's last round is `NPAIR=5` triples: unlink `pre_0001/0011/0021/0031/0041` from block 0 (40-byte holes, non-adjacent so they never coalesce), fsync'd 24-char create into that hole → block 0, fsync'd 100-char create → block 2. The second create's modify-refresh evict runs with block 0 committed-unwritten and nothing re-logs block 0 afterwards. Prints `LASTROUND dir_ino= retire_undest= keep_undest= per_daddr=` from a kmsg-marked window so a lap whose arm never fired is visibly inconclusive, and `AT-RISK: short(block0) missing / long(block2) missing / unlinked-reappeared`; `RESULT` also requires extra=0 (an unlink undone is a durability loss). s493f on 0.70.9: 5/5 shorts missing, 5/5 unlinks reappeared on both verifiers, longs all present — the D-0492 hazard demonstrated.
- `tests/sess488_ailpin_fleet_umount.sh` legs Z/S: the remount stage now prints `D0493-BAR test2:` (`scan_terminal`, `scan_frozen`, `unclassified`, `quar_import`, `admitted_mask`, `import_before_admit` = journal order of `P240-QUAR-IMPORT` vs `mount ADMITTED with AG mask`, `claimed_slot`, `slot0_fence_or_replay`, `departure_unheld`), then `STAGE fleet_remount` (all 32 mount in parallel, per-node files `fleet_remount_test*.txt`, 150 s inner / 200 s budget: mounted, quar_import, admitted_mask, import_before_admit, slot0_claimed, unclassified, ag_mask histogram) and `STAGE fleet_umount rc0=`. The bar for 0.70.12 is in the VERDICT block.

## sess506 — `tests/tcp_death_replay.sh` RECOVERY_BLOCKED arm; the D-state readiness probe

- `TDR_BLOCK_INJECT=1` (`TDR_BLOCK_AFTER_MS`, default 20000): before the
  kill the survivor gets `fence_gate_inject_refuse=1` and
  `fence_blocked_after_ms`; after the kill the lap asserts the bounded
  transition (`P238-FENCE-BLOCKED` within 120 s, exactly one, the durable
  line, the inject line, `P304-FENCE-RETRY` count <= 6 + after/6000 + 2, no
  replay, debugfs `reason=FENCE_BLOCKED`), the fail-fast (`stat` of the
  victim's directory returns EIO within 20 s, `P240-RBLK-*` / `P-RBLK-DENY`
  fired, no shutdown), then clears the injection and requires
  `P238-FENCE-UNBLOCKED`, the replay verdict within 150 s of the clear, the
  `stat` succeeding, and the normal md5 oracle. The replay bound runs from
  the clear on this arm (`tref`), from the kill otherwise. It restores
  `fence_blocked_after_ms` at the end. Chain wrapper:
  `TDR_LAP_BOUND=400 TDR_BLOCK_INJECT=1 tests/tcp_2node_death_chain.sh <label> 1`.
- `tests/suite/precond_readiness.sh`'s D-state probe is a single `ps`
  sample: a kernel thread in a bounded `msleep` IS D state and fails it.
  That is the probe doing its job (0.73.3 fixed the thread, not the probe):
  a permanently-D worker inflates load average and is indistinguishable from
  a wedge to every detector on the rig. Do not widen the probe to ignore
  `msleep`.

## sess507 — 2-node TCP death laps, transport conformance, verifier arm

- `tests/tcp_death_replay.sh` asserts `drain_deferred >= 1` whenever the
  replay completion line reports `buflsn_overrides > 0` (0.74.1). A lap
  whose replay applied no override says nothing about the drain fix.
- **Trap: a lap killed by `TDR_LAP_BOUND` (240 s) dies BEFORE the oracle's
  final `virsh start <victim>`**, so the victim VM stays off and a survivor
  whose FS was shut down keeps `mxfs` loaded; `run.sh` prep then REFUSES to
  power-cycle because `MXFS_NODE_LIST` marks the nodes external, and every
  following lap aborts in 20 s with "unusable after power cycle". Recover
  by hand: `sudo virsh -c qemu:///system destroy/start testN`, wait for
  ssh, `mount 192.168.1.4:/src /src` on the rebooted node (NFS is not an
  fstab automount), then re-run the chain.
- `tests/transport_conformance.sh <label> [A] [B]` (0.75.0): from a live
  2/tcp cluster, arm A (B rejoins with default modargs → adopts TCP; A
  discovers it; B's clean umount is seen as `P163-CLEAN-DEPART`), arm B (A
  re-forms on CAW, B `force_transport=1` → `P-TRANSPORT-MISMATCH-REFUSED`,
  not mounted), arm C (B default → joins CAW, `P-TRANSPORT-CONFORMED caw`),
  arm D (both leave; re-prep after). Evidence dir
  `tests/evidence/<ts>_transport_conformance_<label>/`.
- `tests/sameboot_remount.sh <label> [A] [B]` (`ARMS=1,2,3`, `MXFS_MODARGS`
  default `target_cache_protected=1 force_transport=1`): arm 1 = whole-cluster
  clean stop + A remounts first then B (D-0905/0906/0907 assertions: zero
  `P-TAUTH-PAGE-PARKED`, zero imported EX naming A's predecessor, zero
  `P-LKTIMEOUT-HOLDER`, `P-TAUTH-TAKEOVER departed=`); arm 2 = A cycles alone
  twice (2c mount → 2d umount within ~2 s: the D-0907 put_super lock case) then
  B joins (2f); arm 3 = both leave. 20 s join bound, 7 cycles ≤ 200 s.
  `tests/rejoin_residue.sh <label> [A] [B]` (`RR_DELAY_MS` 15000, `RR_HELD_ARM=1`
  adds arm 4): B leaves/rejoins into the same slot with `node_id_override`
  low/high (masters even/odd pages) while A's purge is held; arm 3 plain; arm 4
  keeps the residue as B's own grant (`tauth_import_residue_release=0`) so the
  P109-EDEADLK-NL arm must heal it. Since 0.75.13: `RR_ID_HIGH` default
  4294967294 (a random id above the old 4000000000 failed the precondition),
  and whenever `P109-EDEADLK-NL ino` fires on a plain arm the harness asserts
  ONE lap and a `P109-EDEADLK-NL-RELEASE ... nak_rc=0` line (D-0904 heal); the
  zero assertions stay as the D-0908 detector. sess514: every join asserts
  that a `P142-BWORK-STALE` on ino=128 is single and followed by `P70-BP
  ino=128 EXIT=full` (the joiner-mount self-BAST bail, honored by the MHT
  work ~18 ms later — it fires on EVERY joiner mount, so 'zero P142' was
  never a discriminator); `leave()` now captures the departing node's journal
  (`<tag>_leave_journal.txt`) and prints its `P-RELALL-LEFT` census. Since
  0.75.16 arms 1-3 assert the fix (zero `P-TAUTH-IMPORT-RESIDUE` on B, A's held
  purge `cleared=0 cand=0`, `P-RELALL-WIRED held_after=0` on every leave) and
  arm 4 (`RR_HELD_ARM=1`) is the PLANTED lap on BOTH parities (ids ID_LOW+1 /
  ID_HIGH-1; B leaves with `depart_wire_release=0`, rejoins with
  `tauth_import_residue_release=0`): the parity where B masters ino=128's page
  (per-mkfs) keeps the residue (RESIDUE-HELD) and must heal it in one P109 lap;
  the other parity is the dead-holder wait (mount ~DELAY_MS) and is accepted
  as INFO. Step 11 bound 400 s (measured 165-173 s). Driver:
  `tests/sess511_chain_0756.sh <label> [steps]` = prep, sameboot arm 1, vm_cycle,
  prep, sameboot all, vm_cycle, prep, transport_conformance, prep,
  rejoin_residue (measured 432 s on 0.75.14; `tests/evidence/sess511_chain_0756_<label>.log`).
- `tests/d513_write_eio_containment.sh`: `D513_ARM=verify` uses
  `freplay_inject_verify_fail` and asserts `P227-FR-INJECT-VERIFY-FAIL`,
  `P227-FR-VERIFY-FAIL`, zero `Corruption of in-memory data`, no
  `P227-FR-UNWIND` expected (the refusal is at the end-of-pass submit);
  `D513_SKIP_CONTROL=1` skips the live-write control (2-node fleets have no
  control node). The victim is destroyed and NOT restarted by the harness.
- `tests/domain_admission_matrix.sh` on a TCP rig: run it with
  `MXFS_DEV=<the QNAP by-path>` (its default is the mpath map, which does
  not exist on the QNAP nodes: every row then fails in 0 s with no journal
  lines). Before 0.75.0 its row R6 (default modargs) silently joined the
  live TCP cluster as a CAW node — the shape that filed the transport
  defect; after 0.75.0 R6 adopts TCP.

## sess496 — a chain's sweep directory is not the run's log; the bogus-i_mode producer chain

- **Trap: `tests/evidence/<chain>/<leg>/kernlog_testN.gz` written by a chain's `sweep()` is a FILTERED journal extract** (the `grep -aE 'P132-CREATE|...'` in `tests/sess495_chain141_adopt_skip.sh` and `tests/sess494_lkp_attrib.sh`), typically ~1000 lines against ~100 000 in the same row's `tests/evidence/run_<row>_<RUNID>/kernlog_testN.gz`. Counting any probe the sweep did not keep (sess496: `P26-DSCAN` read 0 there and 68-171 in the run directory) is a vacuous negative. Count in the `run_*` directory; the sweep directory is for the fields its own summary prints.
- `tests/sess496_bogus_imode_joiner.sh` (`GATE=<log> KO=<frozen ko> WANT_SV=<sv>`): gate + `rig_wait_free` + frozen-ko install + `prep_cluster` + fleet identity, then per-node journal snapshots of `bogus i_mode` / `P116-ZOMBIE-ADOPT` / `P-RELOAD-IOPS-REWIRE`, `tests/guard_race_arms.sh joiner test2 test1` under its own 560 s cap, snapshots again and prints the GROWTH per node (`STAGE growth bogus_i_mode=+N on M nodes; P116-ZOMBIE-ADOPT=+N ...`). The positive control is part of the verdict: P116 must grow on the fd holder (test1) or the freed-shell adopt never ran and the zero is vacuous. Raw lines kept in `tests/evidence/sess496_bogus_imode_<label>/kernlog_testN.gz`. Budget ~17 min (prep 300 + joiner 560 + two 90 s sweeps).
- `tools/p13_release_shape.py --files <list> --workers 8 --out <json>` correlates every `P-ICD-TENURE-REFUSE` / `P13-SFPARENT-DURABLE-FAIL` event with its pipeline entry (`P70-BP ENTRY`), orphan-proceed, `P146-RELDUR` dirty state, `P51-REL`, the ledger markers and the follow-on reload; `tools/xfs_dahash_collisions.py --cc T N` (or names on stdin) prints the `xfs_da_hashname` bucket-size histogram of a name set — how many data blocks a hashed lookup can legitimately read.

## sess552 — the cross-grant unmount workload and what the unload check now reports

- `tests/cross_grant_workload.sh <label> [COUNT=300]` — a WORKLOAD for `tests/unload_laps.sh` (`WORKLOAD=tests/cross_grant_workload.sh tests/unload_laps.sh <label> N parallel 10`): each node creates COUNT one-block files in its own directory (an EX grant per inode) and stats every file the peer created (a PR grant per peer inode), removes nothing, so ~COUNT live grants per node — half of them peer-mastered — are still held when the unmount starts. This is the shape that makes a concurrent unmount exercise the release-at-a-tearing-down-master path (D-0925 mechanism 2); an idle mount or the agleak workload leaves one or two. Healthy wall ~10 s; measures `XGRANT-MEASURE` per-node create/stat walls. Verdict lines only assert the workload ran (both mounted, every create returned, each node sees all COUNT peer files).
- `tests/fleet_unload_check.sh` prints, per node, `departure releases: released= ack_rc= held_after= teardown_releases_served= teardown_local_basts_dropped=` (from `P-RELALL-WIRED` and the 0.75.66 `P-GOODBYE-SENT` counters). `ack_rc` is the count still unacked after the 3 s bound; `teardown_releases_served` is how many of the PEER's releases this node retired after its own `mounted` cleared.
- `umount_rc=141` in the UNLOAD line = the umount process killed by SIGPIPE (D-0926: kernel PAL TCP send without MSG_NOSIGNAL, the goodbye broadcast hitting a peer socket that closed first). The unmount itself completed (rmmod ok, loaded=0); the harness FAILs the lap on the rc, which is the right verdict — a script's `umount && ...` fails the same way.

## sess559 — the ghost-slot restart probe (D-0928 / D-0929)

- `tests/ghost_slot_restart_probe.sh <label>` (env `VM_RESTART=1` default,
  `JOIN_BOUND=300`, `MXFS_NODE_LIST`, `MXFS_DEV`, `MXFS_MODARGS`): both nodes
  come back onto a LUN that still carries dead ACTIVE heartbeat records of
  earlier boots, with no mkfs.  Steps: virsh destroy + start both VMs and wait
  for `/run/nologin` to clear; NFS-mount `/src` on each node (a fresh boot has
  none) and copy the tree's `mxfs.ko` to `/root/mxfs.ko.prep`, verified by
  md5 (`modinfo` refuses a file without a `.ko` suffix, so the srcversion
  cannot be read from the copy); `tools/disklock_hb_dump.py` before; concurrent
  insmod+mount with the join bound; each node's kernel journal since its MARK;
  the dump after; counts of P-HB-GHOST-DEAD, 'no longer responding',
  P163-RECOVERY-PENDING, P236-FENCEKIND, P304-FENCE-RETRY, P238-FENCE-BLOCKED,
  P238-FENCE-ABSENT, P163-RECOVERED, 'foreign replay of slot',
  P-TAUTH-ORPHAN-SWEEP, P-TAUTH-TAKEOVER, P-TAUTH-PAGE-PARKED, 'lock request
  failed after'; verdict = both MOUNTED inside the bound, zero lock failures,
  zero shutdown/BUG.  RULE 0: ~420 s plus ~150 s for the VM restart.  A mount
  parked on an unreachable page is unkillable (D-0930): the harness's own
  `timeout` cannot end it and the join file then has no MOUNT_RC line — that
  absence is the D-0930 signature, not a harness fault.

## sess560 — the probe as a fix ladder (0.75.73-0.75.77) and the D-0930 arm

- The probe run six times in one session against the LUN a failed lap left
  behind (s561-s566) measured one blocker per lap, each fixed in its own build
  before the next lap: barrier publishes only at a clean cut (D-0931,
  0.75.73), certified incarnation never REVOKED (D-0932, 0.75.74/0.75.75),
  no frozen victim key for a victim found dead at admission + node id written
  as the intent key (D-0933, 0.75.76/0.75.77).  s566 PASS: both MOUNTED in
  ~80 s, six stale slices fenced (kind 21) / replayed / published.  The
  counting list above misses the tags those laps needed — census with
  `grep -ao 'P[0-9]*[A-Z]*-[A-Z0-9-]*' | sort | uniq -c` before concluding a
  path logged nothing (a `P-PR-` pattern missed `P-PRKEY-FENCE-REFUSED` x36).
  Useful probes now: P-ADMIT-VICTIM-FROZEN/UNFROZEN, P238-FENCE-HOLDER-STATE
  (why the attempt is not taken over), P238-FENCE-HOLDER-SLOT (the platter
  verdict on the holder), P238-FENCE-TAKEOVER[-REFUSED|-NOKEY], P-DEAD-INC,
  P-BARRIER-SLICE-PUBLISHED, 'mount recovery barrier complete'.
- The probe's state is the LUN's: a PASS leaves both mounted and the table
  clean, so the next VM_RESTART lap is the production crash shape (2 dead
  ACTIVE records → P-HB-GHOST-DEAD → kind 21 → replay → publish).  A failed lap
  leaves FENCING descriptors whose prover is the lap's own dead incarnation;
  `tools/disklock_hb_dump.py` (descriptor lines) is how to read that.
- `tests/d0930_root_iget_bound.sh <label>` (env `BUDGETS=2`): the D-0930
  negative arm.  Both leave → deploy → B joins normally (A's mount must be
  multi-node; a single-node mount skips the bracket) → A insmods with
  `untrusted_aglock_budgets=$BUDGETS untrusted_aglock_inject_eagain=100` and
  mounts: expects MOUNT_RC != 0 inside 60 s, `P-IMAP-UNTRUSTED-AGLOCK-INJECT`,
  `P-IMAP-UNTRUSTED-AGLOCK-GIVEUP budgets=N`, 'Failed to read root inode', no
  `mount` process in D state (`ps -o stat= -C mount`), UNLOADED, then a normal
  join MOUNTED, then both leave.  Bound 300 s.  The injection is the only
  deterministic route to the bound: the natural shape (AG 0's page with no
  reachable authority) is resolved by the recovery fixes, and a refused fence
  fails the mount in the barrier before the root iget.

## sess571 (2026-09-10) — three harness lessons, each of which had already cost a wrong reading

### `tests/d0946_disklive_knob_vs_aging.sh <label> [ROUNDS] [FILES] [MODE=peer|local]`

Asks whether the D-0946 inode double-allocation depends on
`unpub_publish_owned_meta` or only on filesystem age. **Flips the knob IN PLACE
between alternating rounds** — it is a 0644 module parameter, so both arms run
on one filesystem, at one age, with no mkfs, no remount, no death.

That matters because the A/B it came from could not answer the question at all:
every control lap re-prepped (its victim kept failing to rejoin) while the fix
arm ran five laps on one aged filesystem, so *"only in the fix arm"* and *"only
on an aged filesystem"* were the same observation. **A per-lap `prep=` field is
not bookkeeping — it is the confound.** Read it before comparing arms.

Rounds alternate `1,0,1,0` rather than running blocked, because a blocked order
re-confounds the knob with elapsed age (the second block is always older).

`MODE=peer` has node B free what A created before A recreates, because the
observed failure logged `P-CR63-SHELL … src=7` / "peer-freed dead shell". Both
modes returned NOT REPRODUCED (8 rounds each, 3200 peer-frees) — the harness
says exactly that rather than "clean".

**The sole-survivor laps (D-0955, 0.83.3).** `MXFS_D0946_SOLE=umount|death`
ages both nodes, removes B (clean unmount or `virsh destroy`), waits for
`P-SOLE-SURVIVOR` on A, then runs the rounds on the survivor; the knob under
test is named by `MXFS_D0946_KNOB` (`partial_iwrite_sole` for D-0955), and
`MXFS_D0946_ARM=1` pins every round to the fixed path — an alternating A/B
lets the pre-fix whole-write arm rescue what the fixed arm left unpublished
(s583c's root directory only landed that way), so an omission bug is verified
with the arm pinned. Modes: `tight` (the survivor's own churn), `touch` (the
survivor re-dirties its files beside the peer's live ones), `stalesrc` (A
caches directory S, B adds names and leaves, A adds names — the consult's
counterexample to "logged this round is authorised while single"). Verdict
lines: `SOLE-DURABILITY-READ` (`P56-NL-LOGGED-DIR-SKIP` and
`P34H-INCARN-POISON` over the whole survivor phase from the departure mark,
because the round prime runs before the round marker), `MASK-READ`
(`P218-PASSENGER-SKIP` on the fixed arm), `PLATTER-READ` (the clobber probe,
whose `P-DINO-CLOBBER-REALLOC` line is its liveness), `COLD-READ` /
`STALESRC_READBACK` / `READBACK_B` read the survivor's namespace back cold —
from the remounted peer after a clean departure, from the survivor itself
after an unmount and remount after a death (a destroyed peer comes back
unmounted, so a readback from it is NO OUTPUT, never a verdict). Every
round's `cerr`/`derr` is summed into `operation_failures`: s583c reported
`cerr=799` on a line nothing read.

### `tests/d0945_chokepoint_positive_control.sh <label>`

**A silent instrument and a clean system are the same observation.** Ten death
laps produced zero `P945-RELEASE-WHILE-POISONED` lines, which is either "every
release path is gated" or "the probe is dead". This harness decides it, using an
existing knob as the control: with `poison_gate_ino_free=1` the wrapper returns
before `mxfs_dlm_unlock_gen`, so the choke point *should* stay silent; with it
at 0 that same free falls through into the primitive while poisoned, so the
choke point *must* fire. Both directions have a defined right answer — that is
what makes it a control and not another measurement.

It checks vacuity first (no free while poisoned ⇒ the lap decides nothing) and
restores the knob from an `EXIT`/`INT`/`TERM` trap, since leaving a node with
its poison gate disabled would arm the defect under study for every later run.

This is the second time this exact ambiguity appeared: `v5_tcp_release_gate`
logs only when it refuses, so with the gate off the log is silent and "did not
refuse" reads identically to "was never reached" — which is why D-0945 sat
unreproduced for a session. **Any gate whose only output is on the refusing path
needs a probe on both paths.**

### `agmeta_shutdown_retire.sh` — a shutdown by the WRONG route is a finding

It scored the injected death by grepping for the log-error text, so when the
filesystem died of an EFSCORRUPTED dirty `trans_cancel` in `xfs_create` *before*
the injection could fire, the lap scored "no shutdown" and was written off as
vacuous. That buried D-0946 for a session. It now asserts separately on
`P-CR3-CANCEL` / `Internal error xfs_trans_cancel` / `Corruption of in-memory
data` and reports **"shut down by an UNEXPECTED route … this lap is not vacuous,
it found something"**, which caught the third occurrence on its first outing.

Corroborating signals for "did the injected death actually happen":
`left=` on the churn line is the injection budget remaining — `left=4` of 4 means
nothing was ever consumed. And the setup chain
`mkdir && fallocate && sync && s=$(date +%s%N)` short-circuits when the create
fails, leaving `s` unset, so `wall_ms` prints an epoch (`1789022478026`) and
`op_errs` exceeds `ops`. **A lap whose SETUP died must abort, not run workers
against a dead filesystem and report counts.**

### PITFALL — an evidence file named after a lap is not windowed to that lap

Counting `ATOMIC-SKIP` across `tests/evidence/<lap>/…txt` gave 16 for an arm the
driver scored `atomic_skips=0`. Those captures are `dmesg` TAILS carrying earlier
laps' and earlier boots' lines. **Trust the driver's own per-lap windowed
counters** (each lap opens a `$MK` marker and reads `sed -n '/$MK/,$p'`); a grep
across evidence directories is a different, larger population.

## The fence-evidence harness family, and where each one cuts

Five harnesses share one subject — can a survivor prove it may replay a dead
peer's journal slice — and they are NOT interchangeable. Picking the wrong one
measures a different gate and passes.

| harness | stimulus | what it grades |
|---|---|---|
| `fence_crash_cuts.sh` | prover parked at a cut, then `virsh destroy`d | the durable state at each crash point, and that the successor recovers |
| `fence_lost_response.sh` | the P&A really executes, its result withheld; prover stays ALIVE | the ambiguous leg end to end |
| `fence_strong_basis.sh` | victim alive-but-silent, registration still in the table | that the path which SHOULD certify still does |
| `fence_gate_basis.sh` | victim power-cut, registration purged with its session | that the absent-registration route refuses, and that no operator parameter re-opens it (`snexcl` arm) |
| `fence_kind_matrix.sh` | `tools/recov_forge` writes a durable certificate of any class | what the CONSUMING side does with each class and binding |

### The victim arm decides which gates are reachable

On this rig the target purges a registration with its iSCSI session
(`data/rigs.json pr_registration_on_session_loss=purged`), so:

- **`VICTIM=destroy`** → the victim's key is gone before any fence. Nothing is
  left for a PREEMPT AND ABORT to name, the absent-registration kinds that used
  to certify from that are revoked, and **no certificate can be reached at
  all**. That refusal is `fence_gate_basis.sh`'s subject. Any harness needing a
  certificate — and therefore a replay — cannot use this arm.
- **`VICTIM=silent`** (`dl_inject_hb_pause_ms` parks the heartbeat while the
  session, the mount and a writer stay up) → the registration is present, the
  P&A names it and completes, and the whole certify → seal → claim → replay
  chain runs. This is the only arm that reaches a replay.

`fence_crash_cuts.sh` cut 7 refuses `VICTIM=destroy` up front for exactly this
reason, rather than burning its budget to report VACUOUS at the marker wait.

### Cut 7 cuts inside the replay, and it could not be a cut number

A foreign replay does **not** write incrementally: every image is held in core
and submitted once at the end of the pass, because a mid-pass write can put an
intermediate image of a block on the platter ahead of the head transaction that
overlays it and get the slice refused. There is also no durable progress cursor
anywhere in `dlm/` or `xfs/` — replay is LSN-gated and idempotent. So the only
reachable "durable prefix, unissued suffix" state is inside that final
submission, which is where a real crash leaves it. Cut 7 splits the list there
(`dbg_replay_cut_prefix`/`_slot`/`_epoch`/`_hold_ms`), submits and flushes the
prefix, leaves the suffix unissued and parks.

### PITFALL — a kind name with a version digit, and a parser that stops at it

`fence_crash_cuts.sh` predicted `PREEMPT_ABORT_DONE` long after 0.89.16 retired
that code point; a completed operation has earned `PREEMPT_ABORT_PROVEN_V1`
since. Worse, its parser was `grep -ao 'fence_kind=[A-Z_]*'`, which truncates
that name at the `1`. Both would have failed a certificate that is exactly
right. **When a durable enum's names gain a digit, every `[A-Z_]*` parser in
the harnesses becomes wrong silently** — it returns a prefix, not an empty
value, so the assertion reports a mismatch rather than an empty measurement.

## 0.89.20 — the authority-lease harnesses, and the three knobs they need

Three harnesses cover the local authority lease (see `subsystems/dlm.md`
invariant 7 for what the lease is). They divide the subject cleanly and the
division is worth keeping.

### `tests/fence_late_detection.sh <label>` — does containment need detection?

The lap that proved the defect and now certifies the fix. A victim that runs NO
workload and whose two LUN-dependent detectors are held off is fenced by a real
completed PREEMPT AND ABORT; the prover is then power-cut and the appliance
purges the last registration and the reservation with it. The victim then
writes three ways — buffered + `fsync`, `O_DIRECT`, metadata create — and all
three must be refused.

- **The decisive evidence is a raw-block read, never a return code.** The probe
  file's physical extent is captured by `FS_IOC_FIEMAP` **while the filesystem
  is still healthy**, and the block is read off `/dev/sda` with `iflag=direct`
  before and after. `rc=0` from `fsync` is not evidence anything landed, and
  reading the file back through the mount returns that node's own page cache.
- **It carries a CONTROL**: the identical probe on a healthy, unfenced node,
  which must SUCCEED. Every other assertion in the lap is that a write fails,
  and a harness that has broken its own probe satisfies all of them.
- **`AUTHPUMP=<ms>`** (default 600000) parks the periodic evaluation of the
  lease, so only a mutating submission can discover the expiry. That is the
  stronger form: a fix that needs a worker thread to have been scheduled is
  detection again under a new name. `AUTHPUMP=0` grades the periodic half.
- **It power-cycles BOTH nodes at the end**, because its heartbeat park is an
  injected sleep no knob can shorten and one that outlives the lap costs the
  next lap its whole prep budget.

### `tests/auth_lease_resurrection.sh <arm> <label>` — can a closed lease come back?

Four arms, all needed, because each is a different way `CLOSED` could stop being
terminal: `resume` (the heartbeat thread returns from a stall), `staleanchor` (a
renewal whose beat was ISSUED after authority lapsed), `resvgone` (the heartbeat
returns to a LUN with no registrants and no reservation, which a CAS would
succeed against), `latecompletion` (the beat reaches the target and its
completion is withheld). The first two need no fence; `resvgone` builds the real
permissive LUN and leaves the prover destroyed.

### `tests/auth_lease_unmount.sh <label>` — can a contained mount still be taken down?

The lease refuses the journal too, so a withdrawn mount cannot write its own
unmount record. This bounds the unmount and the module removal separately and
requires both to finish — a mount that can be contained but not taken down would
trade one release blocker for another. Measured: `umount` 1 s, `rmmod` 0 s.

### The knobs, and what each is for

| knob | one-shot | what it removes |
|---|---|---|
| `dl_inject_hb_pause_ms` | yes | parks the heartbeat thread — what makes a peer declare this node dead, and what a genuinely stalled node looks like |
| `dbg_resv_health_pause_ms` | yes | the proactive PR IN detector |
| `dbg_auth_pump_pause_ms` | no | the PERIODIC evaluation of the lease AND the withdrawal pump, leaving only a mutating submission to find the expiry — the "blind victim" knob |
| `dbg_auth_withdraw_pause_ms` | no | (0.89.66) ONLY the withdrawal pump; the lease is still evaluated every tick, so a closure lands on time and nothing converts it into the shutdown that wakes a parked log waiter |
| `dbg_hb_skip_auth_check` | yes | the heartbeat's pre-issue authority check, for exactly one cycle — the only way to reach the renewal guard, which no live path can |
| `dbg_hb_completion_delay_ms` | yes | withholds a LANDED beat's completion, so the renewal must still derive its deadline from the issue instant |

**None of them weakens a gate, a refusal or a write path.** Every one removes a
DETECTOR or a CHECK ABOVE the thing under test, which is what makes a passing
lap mean something: the refusal that fires is the one being graded.

### PITFALL — a fix that adds an expected signal breaks the lap that proved the defect

`fence_late_detection` asserted "the victim noticed nothing" and "zero
shutdowns". The fix makes the victim notice — locally — and withdraw, so both
assertions fail on a lap where everything worked. The repair is to **split them
by cause**, not relax them: `DETECT` keeps every LUN-dependent detector and
excludes the new one **by its reason string** (it reuses the same
`P131-SELF-FENCE` line, so excluding by name would hide the old detectors too),
plus a positive assertion that the local one fired with the expected reason; and
the shutdown count exempts exactly one **call site**, `mxfs_dlm_fence_notify`.
The lap came out stricter: it now asserts WHICH mechanism contained the node.

### PITFALL — the stimulus that makes the victim's clock observable can be the peer's detector

`authority_handoff_phase.sh` ran a writer on the victim so the gate would close
at the deadline. The closure withdraws the mount, the withdrawal stamps the slot
WITHDRAWN, and the peer fires on the stamp (`P163-WITHDRAW-SEEN`) at its next
2 s pass — so four laps reported a ~1 s "margin" for a 62 s silent window that
was never reached. The lap now classifies the peer's death path from line order
(`path=withdrawn|certificate|epoch|silent` on the MARGIN line) and `SILENT=1`
runs no writer, takes the deadline from `P-HB-INJECT-PAUSE ... deadline_ms=`
(0.89.66) and is VACUOUS unless the path was silent. The monitor's death line
prints `threshold= last_stamp_ms= last_seen_ms= now_ms=` so the window's real
start and length are on the console.

### The authority-lease lap family (which lap answers which record)

| lap | record | the knob-free fact it needs |
|---|---|---|
| `authority_handoff_phase.sh` (+`_sweep.sh`) | resurrection, measurement (2) | peer death from SILENCE (`SILENT=1`), never from the victim's stamp |
| `parked_log_waiter_across_closure.sh` | blocked waiters, item (3) | a closure that lands with the pump held: `dbg_auth_withdraw_pause_ms`, not the blind knob |
| `admitted_write_parked_across_unmount.sh` | unexpired lease, step 2 | `SITE=data` is the descriptor-free arm; `SITE=log LOG_FSYNC=0` is the other one — the fsync arms are refused at the VFS (`order=vfs-busy`) and never reach put_super |
| `admitted_write_parked_across_fence.sh` | old-epoch, schedule (A) | the module's own park between gate and bio |
| `delayed_write_across_fence.sh` | old-epoch, schedule (B) | the request held BELOW the module in a single-path dm-multipath map (`queue_if_no_path`, the path failed by `dmsetup message`); NOT dm-delay — its `iterate_devices` hands `dm_pr_register` the same path three times, so the module's REGISTER conflicts with itself and is rolled back (s147c); the heartbeat FUA write is a bio too, so park it by the knob before the path is failed |
| `post_closure_renewal_at_peer.sh` | post-closure renewal | `SUSPECT_FIRST=1` drops UDP 7603 inbound on the peer until the lease marks the sender SUSPECT (360 s, a module constant) |
| `nonfallible_transition_stall.sh` | stalled transition | the page's MASTER must stay alive; the victim is chosen by `P-SB-SUMMARY-LOCK ... master_self=` |
