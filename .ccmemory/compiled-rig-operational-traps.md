---
name: compiled-rig-operational-traps
description: Chronological log of rig/harness operational traps on clyde: data loss, wedges, silent log filtering, stale builds, wrong board conditions, shutdown-…
metadata:
  type: project
tags: [compiled, rig, clyde, host-safety, harness, traps]
---

## Topic

Operational pitfalls specific to running the MXFS test rig/harness on clyde —
not filesystem defects, but ways of *operating the rig* that destroy evidence,
wedge the host, silently corrupt verdicts, or misdirect diagnosis at the wrong
layer. Each was found once, cost a rig rebuild or a diagnosis detour, and got
a standing rule. Chronological.

### 2026-06-14 — never `find /` on clyde
[[never-find-root-nfs-mounts]]: `find /` crawls clyde's NFS mounts (`/src`,
`/data` on QNAP 192.168.1.4) and hammers the NFS server for the whole
cluster. Absolute, unconditional ban — no "scoped" exception. To find a
binary: `command -v`/`which`/`dpkg -L`, or look in the VM that actually needs
it, never the host root.

### 2026-07-05 — `/src` must not be an fstab auto-mount on test VMs
[[feedback-src-nfs-not-fstab-automount]]: guest `/etc/fstab` entries for
`/src` (QNAP NFS) default to a `hard` mount; if the QNAP is unreachable at
boot the mount retries forever and can hang VM boot. `/src` must be mounted
only by the buildup/prep step (`tools/prep_node.sh`,
`tools/prep_tcm_node_scst.sh`, `tests/criteria/lib.sh` ENSURE_NFS), never by
fstab. As of that date the fleet was inconsistent (~16/32 auto-mounted) and
had to be swept clean.

### sess25 — `prep_cluster` misreads host load as a wedged node and power-cycles it
[[rig-prep-spurious-powercycle-under-host-load]]: `prep_cluster` requires
both `MXFS_CLEAN` and `SRC_OK` inside a 150 s per-node ssh window; under
unrelated clyde host load (measured loadavg 8-29, per-ssh latency
669-1101 ms) 32 parallel connections push the script past 150 s, prep treats
the empty result file as a wedged node and escalates to `virsh
destroy+start`. Because `/src` is deliberately not an fstab auto-mount (see
2026-07-05 above), the power-cycled node comes back *without* `/src`, which
re-triggers the same escalation — a self-sustaining flap loop. Confirmed the
node was never broken: running prep's exact teardown by hand returned
`SRC_OK`+`MXFS_CLEAN` immediately. Break it by checking host load first
(`uptime`), killing stale prep trees by anchored pattern
(`pkill -f '^/bin/bash \./run\.sh'` — never `pkill -f "run.sh 32 caw"`, which
matches your own wrapper and kills itself), remounting `/src`
(`mount -t nfs4 192.168.1.4:/src /src`), and never running a parallel
"keep /src mounted" watcher while prep runs (it contends with prep and makes
it worse). Prep should distinguish "ssh timed out" from "node reported dirty"
and re-establish `/src` as part of power-cycle recovery — not done as of this
writing.

### sess26 — kernel-log retention varies ~60x per NODE, not by source
[[kernel-log-retention-varies-per-node-pick-best-source]]: corrects an
earlier same-session claim that `journalctl -k` is always longer-retention
than `dmesg`. Measured on two nodes minutes apart: test19 dmesg 112 s /
journalctl ~50 min (journalctl wins); test5 dmesg 1407 s/17 MB / journalctl
shorter (dmesg wins) — both are size-capped rings and nodes log at wildly
different rates. Rule: per node, pick whichever source still has the most
lines after the run's marker and report `win_src=`; never hardcode one
source, and never concatenate both sources to scope a window (mixes two
different windows presented as one measurement — caught before running it).
`tests/dd_loss_differential.sh`/`dd_loss_capture.sh` do this now. This is the
same failure family sess429 hit again at board scale — see below.

### ~2026-08-03 — recovering the 32-node CAW rig after a clyde reboot: `scst.service` is a red herring
[[rig-recovery-after-clyde-reboot-scst-mpath]]: post-reboot,
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` power-cycles all 32 nodes
and fails with `/dev/mapper/mpatha never appeared` — host-side, not an MXFS
or node fault. `systemctl status scst` looks like the cause (fails at boot
over a stale `/etc/scst.conf` naming long-deleted `disk-1.img`/`disk-2.img`)
but is a dead end: the 32-node CAW rig doesn't use the systemd unit at all.
The actual recovery is `scripts/scst_setup.sh setup` (vdisk on
`/home/steve/disk.img`, the live MXFS envelope) → `sudo -E
scripts/mpath_up.sh up 32` (second portal + 32 guest logins, idempotent,
prints `MPATH_OK 2` per node as the readiness gate) →
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`. Run `mpath_up.sh` even if
`scst_setup.sh` alone already succeeded — it only pins the single-portal
condition-3 rig; CAW's condition-4 board needs both portals.

### sess386 — `sudo mpath_up.sh` leaves a root-owned passfile, sshpass hangs silently
[[trap-sudo-mpath-up-leaves-root-owned-passfile]]: `tools/mxfs_secrets.sh
passfile` materializes `/tmp/.mxfs_pass` as whatever user calls it first.
`sudo -E bash scripts/mpath_up.sh up 32` — the documented post-reboot rig
recovery step — creates it `root:600`; the unprivileged harness's sshpass
then can't read it and falls through to an interactive password prompt that
never returns, so `./run.sh N caw ...` (or a bare `mxfs_sshpass.sh`) hangs
with ZERO output. After a clyde reboot `/tmp` is empty, so the recovery
sequence's own `sudo mpath_up.sh` call is usually the first creator. Cost one
400s silent prep timeout before diagnosis. Fix: `sudo rm -f
/tmp/.mxfs_pass && tools/mxfs_secrets.sh passfile` (as the normal user) before
any harness call, and verify with `ls -la /tmp/.mxfs_pass` (must be
`steve:steve 600`) whenever recovery started with a `sudo` step.

### sess396 — `make clean` silently deletes the userspace tools
[[trap-make-clean-removes-userspace-tools-run-make-tools]]: the top-level
`clean` target also runs `make -C tools clean`, removing `mkfs_mxfs`,
`chk_mxfs`, `resize_mxfs`, `fua_verify`. `run.sh ... prep_cluster` then fails
with `FS_PREP_FAIL: mkfs tool not found` only after the fleet has already been
rmmod'd — costing a full rig-agent round. Rule: any `make clean && make
modules` chain must end with `make tools` (2s) before deploy/prep.

### 2026-08-07 — `pgrep -f`/`ps -e` host-locally wedges clyde unkillably
[[never-pgrep-f-on-clyde-mmap-lock-wedge]]: `pgrep -f`/`ps -e`/`ps aux` read
every `/proc/<pid>/cmdline`, which takes that task's `mmap_lock`. One task
wedged while holding its own `mmap_lock` (root cause here: an orphaned bio in
a `dm-delay` device from the fence harness, cascading through jbd2 →
`__lock_buffer` under THP compaction) makes every later `pgrep -f`/`ps -e`
block forever in D-state — not killable by SIGKILL or `timeout`. This
accumulated to loadavg 583 (~580 stuck watchers, one per ccloop session
launched) before a manual host reset was needed. The obvious recovery
(`dmsetup suspend/wipe_table/resume` to swap in an error target) does NOT
work: it needs the same `md->suspend_lock` the wedge holds, so the attempt
adds another stuck task and *consumes the escape hatch* — never retry it.
Fix in tree: `tools/mxfs_pgrep.sh` checks `/proc/<pid>/stat` for D-state
first and skips before touching cmdline; patched into the host-local pollers
in `tests/drc_autocapture.sh`, `drc_progress_watch.sh`,
`dd_loss_differential.sh`, `rank1_stall_stacks.sh`. Diagnosing a wedged host:
`/proc/*/comm`, `/proc/*/stat`, `/proc/<pid>/stack` are safe; `cmdline` and
`maps` are not. This trap is why `never-pgrep-f-on-clyde-mmap-lock-wedge`
itself, plus CLAUDE.md RULE 2c, exist.

### sess400/401 — long rig-run evidence in the session scratchpad is lost to a host reboot
[[trap-long-rig-run-evidence-in-scratchpad-lost-to-host-reboot-sess400]]: a
6-lap verification board pointed its output dir (`D385_OUT`) at the session
scratchpad (`/tmp/...`). clyde was cleanly rebooted ~15 min into the board;
the session, its in-flight agent, the scratchpad and every lap log died with
it, forcing a full rig rebuild (`scst_setup.sh setup` → `virsh start` ×32 →
`mpath_up.sh up 32` → preflight → `prep_cluster`, ~7 min) and a full board
re-run. Rule: anything a rig run writes that a *later session* must read —
board logs, dmesg harvests, probe sweeps, churn output — goes under
`tests/evidence/<sessNNN_topic>/` (NFS, survives a host reboot) from launch,
not copied there afterward. Applies to `D385_OUT`, `AGIFC_OUT`, `TMPC_OUT`,
`FTR_OUT` and equivalents. Corollary: session self-numbering can collide with
ccloop's own numbering across a reboot — disambiguate evidence dirs by
transcript/session id when in doubt.

### sess402 — `grep -v authorized` deletes the evidence it was filtering for
[[trap-grep-v-authorized-deletes-unauthorized-image-kernel-lines]]: every
harness pipeline stripped the ssh login banner ("Unauthorized access...")
with `grep -v authorized`, which also matches **un**authorized — silently
deleting the one kernel line that named the actual mechanism
(`P227-FR-ATOMIC-SKIP ... unauthorized image(s)`). Cost ~1 hour chasing "which
silent path counts refusals" before finding the notice was never missing,
just filtered. Rule: anchor banner filters to the banner's own line shape
(`grep -av '^Unauthorized\|^Warning:\|^If you'`), never filter kernel logs by
a bare substring that can legitimately appear inside a kernel message
(authorized, warning, error, failed...). When a counter reports N events and
the notices are absent, suspect the pipeline before the kernel — `grep -c`
on the node with **no filter** first. Fixed across 22 call sites
(`tmpfile_churn*.sh`, `ag_handoff_lap_sweep.sh`, `agifc_churn_experiment.sh`,
`iunl_mismatch_negative.sh`, etc.).

### sess403 — rebuilding mxfs.ko while a rig run is in flight splits srcversion
[[trap-never-rebuild-mxfs-ko-while-rig-run-in-flight]]: `prep_cluster` insmods
`/src/mxfs/mxfs.ko` from the NFS-shared tree on every node. Running `make
modules` again while a dispatched rig-runner/agent is still prepping means a
node mid-insmod (or the run's second arm) can pick up the new `.ko`, splitting
an A/B test across two srcversions or reading a truncated file during relink.
Rule: once a run is dispatched, the tree's `mxfs.ko` and `tools/` are FROZEN
until it reports; queue edits and build after, or build into a scratch
worktree copy. Always cite the per-run srcversion the harness/agent reports
(`test1 /sys/module/mxfs/srcversion`), never the tree's `modinfo`.

### sess405 — sub-sector-length PAL bio writes hang (not fail) on dm-multipath
[[trap-pal-bdev-write-must-be-sector-aligned-subsector-bio-hangs-dm]]: a
`mxfs_pal_bdev_write` of a non-sector-multiple length (96 B) hung in
`submit_bio_wait` on `/dev/mapper/mpatha`, in D-state, on 6/30 nodes — and
critically, on the disklock heartbeat thread (`disklock_hb_fn` →
`v5_handle_node_death` → `v5_pr_fence_prove_locked` →
`mxfs_disklock_recovery_manifest_write`), so the stall froze that node's own
heartbeat until peers fenced it, cascading into further hangs and a 7-VM
`virsh destroy/start`. Unlike the SCSI PAL paths (READ(16) FUA, write_fua),
which reject sub-sector lengths with `-EINVAL`, the plain bio path on dm does
not fail fast — it hangs. Fixed 0.26.1: PAL entry-area I/O rounds up to 4 KiB
(`MXFS_RMAN_IO_ALIGN`) with a zero-padded buffer, CRC still over the real byte
length. General lesson: anything on the `v5_pr_fence_prove` path runs on the
heartbeat thread — any stall there past the lease turns the prover into the
next fencing victim, so keep that path's I/O bounded and aligned.

### sess413 — a rig harness launched as a Bash child dies at relay teardown
[[trap-harness-survives-session-exit-check-mxfs-pgrep-before-rig-work]]:
corrects the sess410 assumption below. A harness launched as a plain Bash
child of the claude process — foreground OR `run_in_background`, directly or
via a rig-runner agent's Bash — DIES when the session is torn down at a relay
boundary. Proven 2026-08-24: sess412's full board (`run.sh 32 caw`) died at
the exact relay teardown moment, 3 minutes into a ~17-minute run, mid-board,
with no summary row in criteria.json and the chained second job never
starting; a comm-based `/proc` sweep found zero surviving harness processes.
Fix: launch long rig work with `setsid nohup sh -c '...' &` — setsid detaches
it from the session's process group so relay teardown cannot kill it — and
append per-stage `STAGE <name> rc=N` lines to an evidence chain-log (under
`tests/evidence/`, never scratchpad — sess400 trap above) so the next session
can harvest it. Original sess410 finding, still true for work that IS
detached (setsid'd, or running on the test nodes via ssh): it keeps running
invisibly after the session ends, so at session start — before any rig work,
especially rebuilds (srcversion-split trap above) — check for a live orphan
with `tools/mxfs_pgrep.sh` and harvest its evidence first. Corollary:
`mxfs_pgrep.sh` output is a point-in-time snapshot with no liveness
guarantee — always confirm `/proc/<pid>` still exists before treating a pid
as a live run.

### sess414 — cumulative/unbudgeted dmesg sweeps corrupt board verdicts three ways
[[trap-tck-sweep-cumulative-dmesg-false-verdicts-sess414]]: `tests/tmpfile_churn_kill.sh`'s
tck dmesg sweep produced two consecutive FALSE FAILs of the node_death_replay
board row on 0.27.7 while the FS behaved correctly, from three compounding
flaws. (1) Per-node `timeout 60 $SSH ...` on an ssh timeout wrote rc=124 with
no counters in the header, and `sum()` silently treated that node as
all-zeros — undercounting a real pass (false FAIL, one board run: 5 nodes
timed out including the replayer, whose ring provably held both victims'
replay-complete lines) or masking a real miss (false PASS). Fix: fail-closed
— hoist the sweep command, retry once for unreported nodes, then
`SWEEP_MISSING` fails the lap; an evidence gap is a verdict, never a zero.
(2) A `--no-prep` lap greps dmesg without clearing the ring first, so it
counts the PREVIOUS run's replay-complete lines and releases the recovery
WAIT before HB expiry (~62s vs the real ~21s), unmounting the fleet
mid-death-window — shaped exactly like a real no-replay defect. Fix: `dmesg
-C` on every node at `--no-prep` lap start. (3) 36 separate full 16MB-ring
greps per sweep on a pegged 1-2 vCPU VM right after churn caused the ssh
timeouts in (1). Fix: dump the ring once to a file, grep the file. General
rule: any harness summing per-node counters must fail-closed on a missing
report, and any cumulative-dmesg grep must be windowed (ring clear or
marker) — other harnesses with the same cumulative-grep shape are suspect
(`d526_mass_unmount_verify`, `fr_mount_barrier_fail`, `rman_matrix`).
Also: `run.sh` retains fail logs at `/tmp/run_<name>_<RUN_ID>` — the `logs:
/tmp/tmp.*` path it prints is deleted at exit, harvest the `run_*` copy
instead. And `rman_matrix.sh`'s `$1` is the evidence dir, not an arm name:
`rman_matrix.sh base_shared base_shared base_shared` runs two arms both
writing into `./base_shared`.

### sess418 — the `tcp` board condition is wired to a rig that no longer exists on this fleet
[[trap-32-tcp-condition-device-is-xml-sda-use-mxfs-dev-mpatha-and-mxfs-crit]]:
`run.sh`'s `tcp` condition (condition 1) targets TCP DLM over the old LIO
tcm_loop rig with the shared LUN XML-wired as `/dev/sda` in the guests;
`caw` (condition 4) targets CAW over dm-multipath. The fleet today is the
multipath rig, so `./run.sh 32 tcp prep_cluster` dies in prep_fs:
`/dev/sda ... is claimed by: dm-1` — the 32/tcp board column's PASS cells are
from the old rig, not this one. To exercise TCP DLM on the current fleet:
`MXFS_DEV=/dev/mapper/mpatha MXFS_CRIT=/src/mxfs/criteria.tcpmp.json
./run.sh 32 tcp prep_cluster` — `MXFS_DEV` overrides the per-condition
device, `MXFS_CRIT` keeps results off the primary board (cells are keyed
`<N>/<dlm>` with no rig dimension, so running a condition on the wrong rig
silently overwrites the column in place — `run.sh:103-107` documents this).
The transport gate the tests read (`/sys/module/mxfs/parameters/
force_transport==1`) is transport, not rig, so it's satisfied either way —
nothing stops you from silently measuring the wrong rig.

### sess428 — never write source into a /tmp scratch copy, even to dodge a build race
[[feedback-never-write-source-in-tmp-scratch-copy-even-during-rig-runs]]:
to avoid racing an in-flight rig chain's build (sess403 trap above), a
session kept a modified copy of the tree in the session scratchpad
(`.../scratchpad/w038`) and wrote NEW source there (`dlm/tauth_view.{c,h}`,
`include/mxfs/mxfs_sha256.h`, a new test, header edits) instead of editing
`/src/mxfs` directly. User, emphatically: this loses the work on the next
server reboot, and it's unknown how much else has been silently routed the
same way. The build-race concern from sess403 is real but has the wrong fix:
handle it by SEQUENCING (don't run `make` in the tree while a chain's
build/proof stage is running; editing sources while a chain is at
prep/test stages is safe — it insmods the already-built `.ko`), never by
relocating sources to `/tmp`. A scratch *copy of the tree* is the identical
RULE 3 violation as any other file in `/tmp`, just less obviously so because
the motive (avoiding a race) sounds responsible.

### sess429 — the dmesg ring wraps within minutes under a 32-node board; marker-bounded sweeps silently read zero
[[trap-dmesg-ring-wraps-under-board-kmsg-marker-sweeps-read-zero-use-journalctl-since]]:
after a 22-minute 32/caw board, test1's dmesg ring held only its last ~2
minutes (22,703 lines starting at monotonic 1353s); the kmsg marker written
before the board was already gone, so `dmesg | sed -n '/MARK/,$p'` printed
nothing and every verdict counter read 0 on all 32 nodes — a FALSE clean
sweep, not a real one. Nodes rebooted by node_death_replay lose the marker
even faster (short/empty ring post-reboot). This is the sess26 lesson
(`kernel-log-retention-varies-per-node-pick-best-source` above) recurring at
board scale, now against journald instead of a second dmesg read: journald
on these nodes retains the kernel facility persistently (79,010 lines for the
same window `dmesg` had reduced to 22,703 of stale data) and held the
evidence the ring had already overwritten. Fix: record the mark as a WALL
TIME (`date -u '+%F %T'`, nodes are UTC) and sweep with `journalctl -k -q
--since "$MARKTIME" -o short-monotonic`; print `JOURNAL_LINES` per node so a
short window (a rebooted node) is visible rather than silently trusted.
Fixed in `tests/sess429_chain.sh`, `tests/sess416_board_0286.sh` (same flaw
present since sess416), `tests/free_home_settle_repro.sh`. Related, same
session: a reproducer must verify the mxfs MOUNT before its workload — after
`node_death_replay` tears the cluster down, `/mnt/shared` is a plain root-fs
directory, so `dd`/`rm` "succeed" and every dmesg assertion passes vacuously.

### sess432 — a shared shutdown-ioctl number fired on the wrong filesystem, not on mxfs
[[trap-vergate-goingdown-ioctl-shut-down-node-root-fs-sess432]]: `vergate.sh`
issued `XFS_IOC_GOINGDOWN` (`0x8004587d`) on `/mnt/vgate` unconditionally
after a loop mount, without checking the mount succeeded. The mount had
actually failed (`P303-FENCECAP-NOCAPS` → CAW refused with `-95` → mount(2)
`ENOTCONN`) because the harness predated the 0.15.0 rule that a device with
no SCSI PR needs `mxfs.fence_capability_override=1` (`single_node_exclusive=1`
does NOT waive it). `/mnt/vgate` was therefore still a plain dir on the root
ext4 (`dm-0`), and `EXT4_IOC_SHUTDOWN` shares the SAME ioctl number —
`fcntl.ioctl(..., 0x8004587d, 2)` shut down the node's *root filesystem*,
producing "Aborting journal on device dm-0-8" root-fs EIO and forcing a
power-cycle. Every post-mortem dmesg capture from that node was empty as a
direct result — the same "silent, empty evidence" shape as the sess400/402/429
traps above, this time from the harness disabling the very node it was
diagnosing. Fixed in `tests/vergate.sh`: set the fence override for loop
arms (restore at teardown), and gate the shutdown ioctl on `/proc/mounts`
actually showing `/mnt/vgate type mxfs` first. Rule for every harness: never
issue `XFS_IOC_GOINGDOWN`/any shutdown ioctl on a path without first proving
that path is the mxfs mount you meant — the ioctl number is shared across
filesystems, so an unmounted/misclassified target silently hits whatever
filesystem the mountpoint dir actually sits on. (The fix then exposed a REAL
mxfs finding, unrelated to this trap: the fresh 4-AG loop fs's first `mkdir`
after "Ending clean mount" fails `Allocated a known in-use inode 0x83!`,
instrumented as P-DIALLOC-VERIFY in 0.39.10.)

### sess433 — node journald is volatile; a post-reboot sweep of the victim proves nothing
[[trap-node-journald-volatile-rebooted-node-kernel-log-gone]]: on the test
nodes, `journalctl --list-boots` shows only boots from 2026-07-01 plus the
live boot — `/var/log/journal/*` files are stale from image build,
`Storage=` is effectively unset, and the live journal lives only in
`/run/log/journal/...` (tmpfs). So `journalctl -k -b -1` on a node AFTER a
`virsh destroy` returns 0 lines for the pre-crash window: the volatile
journal died with the VM, exactly like the dmesg ring in the sess400/429
traps above, just via a different subsystem. Rule for any harness that
power-cycles a node (`lone_crash_replay`, `node_death_replay`, `tck`):
capture `dmesg`/journalctl on the victim INTO `tests/evidence/` BEFORE the
destroy, or derive the victim-side facts from a survivor's journal instead.
A post-hoc `-b -1` sweep on the victim is not missing evidence by bad luck —
it is structurally incapable of holding it.

## Cross-cutting pattern

Every one of these traps is a case where a command or setup that is fine in
isolation (`find`, `sudo`, `make clean`, `pgrep -f`, `grep -v`, a rebuild, a
scratchpad path, an unaligned write, a dmesg sweep, a backgrounded harness, a
board condition flag, a host-load misread, a log-window assumption, a shared
ioctl number, a volatile journal) becomes destructive specifically because of
clyde/rig state: NFS-backed mounts, a shared `.ko` under NFS, a host that gets
rebooted mid-run, D-state accumulation with no kill path, a heartbeat thread
that cannot stall, a session relay that tears down child processes, a ring
buffer that persists across laps but wraps in minutes under load, unrelated
host workload that looks like a wedged node, a rig condition wired to
hardware that no longer exists on the fleet, an ioctl number reused across
filesystems, or a journal that does not survive the reboot it was meant to
diagnose. None of these were filesystem defects; all of them cost a rig
rebuild, a lost run, a falsified verdict, or a multi-hour diagnosis detour
before being converted into a standing rule (several are now load-bearing in
CLAUDE.md RULE 2c/2d/3). A repeating shape across the newest entries: when
post-mortem evidence for a victim node comes back EMPTY, suspect the capture
mechanism (dead ring, volatile journal, wrong mount, disabled node) before
concluding the event left no trace.
