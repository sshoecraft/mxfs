---
name: compiled-clyde-host-process-safety-and-vm-recovery
description: Clyde host safety: pgrep/ps mmap_lock wedges, self-kill-by-pattern traps, D-state domain recovery, and rig resource exhaustion — all without a host r…
metadata:
  type: project
tags: [compiled, clyde, host-safety, pgrep, wedge, rig, libvirt]
---

Clyde is the dev host: it runs libvirt, the SCST/iSCSI target, NFS, and Claude
Code itself. Per CLAUDE.md RULE 2, only the user resets it — every host
incident below either has a recovery path that avoids that, or (mmap_lock)
proves there isn't one and the only fix is not entering the state. Two
standing reference procedures anchor the recovery paths that follow:
node power control is `virsh -c qemu:///system destroy/start` (the default
`qemu:///session` URI shows an unrelated, always-"shut off" VM set) —
[[reference-node-power-control]] — and after any clyde reboot/power-loss,
three host-side things must be rebuilt before SSH/run works at all: the LIO
LUN (`lio_tcm_setup.sh setup`), the persistent SSH password copy
(`/home/steve/.mxfs/pass` → `/tmp/.mxfs_pass`, since `/tmp` does not survive
reboot), and the test1/test2 VMs — [[env-cluster-bringup-after-host-reboot]].

## The mmap_lock wedge (2026-08-07): the incident that set the rule

`pgrep -f PATTERN` / `ps -e` / `ps aux` read `/proc/<pid>/cmdline` for every
process, which takes that process's `mmap_lock`. One task wedged holding its
own mmap_lock (here: `ffmpeg` blocked in `__lock_buffer` via THP direct
compaction, itself downstream of a stuck `dm-delay` bio from the MXFS fence
harness) makes every later `pgrep -f`/`ps -e` on the host block forever in
D-state — unkillable by SIGKILL or `timeout`, +1 loadavg permanently, no
per-tick accumulation but one per watcher launch. Clyde reached loadavg 583
this way and needed a manual reset. The recovery attempt (`dmsetup suspend
--noflush --nolockfs` → `wipe_table --force` → `resume`) does NOT work: it is
circular (suspend needs the fs frozen, freezing needs the wedged superblock,
draining needs the very bio being cleared) and the failed attempt itself
grabs `md->suspend_lock`, consuming the escape hatch and guaranteeing the
reset it was meant to avoid. `pgrep -x`/bare `pgrep NAME` match on `comm`
only and are safe; only `-f` and full `ps` listings read cmdline. The fix
landed as `tools/mxfs_pgrep.sh`, which reads `/proc/<pid>/stat` first and
skips any D-state task before ever opening cmdline. Full detail, stack
traces and the patched call sites: [[never-pgrep-f-on-clyde-mmap-lock-wedge]].

Diagnosing an already-wedged host safely reduces to one rule, proven again in
the libvirt incident below: `/proc/*/comm`, `/proc/*/stat`, and
`/proc/<pid>/task/*/stack` are safe; `cmdline` and `maps` are not, whatever
banner they hide behind (`pgrep -f`, `ps -e`, `ps aux`).

## Recurring failure mode: a kill built from a command-line substring kills its own caller

Independent of the mmap_lock wedge, matching processes by command-line
pattern has bitten twice more, both times by matching the *invoking shell's
own command text* rather than the intended target:

- **sess25**: `prep_cluster` under unrelated host load (measured ssh latency
  669-1101ms with `Wow.exe`/`worldserver` at 100%+ CPU) misread a slow SSH
  as a wedged node and escalated to `virsh destroy+start`. The power-cycled
  node comes back without `/src` (deliberately not an fstab automount), which
  *creates* the `SRC_MISSING` condition that triggers the next escalation —
  a self-sustaining flap loop. Breaking it: check `uptime`/CPU hogs before
  assuming a wedge, kill stale prep trees by an *anchored* pattern (`^/bin/bash
  \./run\.sh`, never `"run.sh 32 caw"` — that substring appears in the
  wrapping `bash -c` and kills its own shell), and remount `/src` by hand.
  Full detail: [[rig-prep-spurious-powercycle-under-host-load]].
- **sess593**: `pids=$(tools/mxfs_pgrep.sh 'join_during_takeover.sh s593b');
  for p in $pids; do kill $p; done` matched the Bash tool's own `sh -c`
  chain (the command text carries the pattern), killing the invoking shell
  before its own cleanup ran and losing a harness verdict 2 minutes from
  completion. `tools/mxfs_pgrep.sh` does not protect against this — it only
  guards the mmap_lock hazard, not self-match. Fix: track PIDs explicitly
  (`setsid nohup bash -c '...' & echo $! > tests/evidence/<label>.pid`, then
  `kill $(cat …pid)`), or wait for the lap's own WANT= match instead of
  killing anything; a `kill` belongs last in a chain, or in its own call, so
  a self-kill can't skip cleanup. Full detail:
  [[trap-a-kill-list-from-mxfs-pgrep-includes-the-shell-that-ran-it-and-kills-the-harness-mid-lap]].

Net rule across both: never match a live target by command-line substring on
clyde. Use a pidfile you control, or an anchored pattern that cannot appear
in the shell that's building it.

## D-state wedges outside pgrep: libvirt domain recovery without a host reset (sess384, 2026-08-20)

A qemu leader can zombie with live sub-threads stuck in uninterruptible sleep
(here: writing the guest's serial log to the host's own ext4 — not an MXFS
defect) and deadlock libvirtd for *that one domain*: `virsh destroy` fails
with "Device or resource busy", `virsh domstate <d>` never returns, and
`virsh list --all` hangs because it touches every domain. Recovery is a
five-layer unlock that must be done in order, each layer only becoming
visible once the previous is cleared: libvirtd's runtime state files,
virtlogd's lock on the serial log (keyed by path — rename the persistent XML
to a new filename, don't just move it), virtlogd's lock on the qemu log,
virtlockd's lease on the disk image (unbreakable while the zombie holds the
fd — point the domain at a copy), and systemd-machined's stale registration
(`machinectl terminate`). Automated end-to-end in `tools/recover_wedged_domain.sh`
(~3 min, dominated by a sparse image copy), verified to bring the domain back
and let a 32-node cluster re-prep clean. It never touches the host (RULE 2).
This incident is also why every `virsh` call in `run.sh`'s
`power_cycle_node()` is now wrapped in `timeout 60` — unbounded, it hangs an
unattended prep forever against a deadlocked domain, the same shape as the
sess25 flap loop above. Detail: [[libvirt-domain-deadlock-recovery-without-host-reset]].

## Rig work must survive session/relay teardown, and liveness checks are snapshots only

A harness launched as a plain Bash child of the session (foreground or
`run_in_background`, directly or via an agent's Bash) dies when the session
tears down at a relay boundary — proven sess412/413: a 32-node board died at
the exact relay moment, 3 minutes into a 17-minute run, no summary row
written. Fix: launch with `setsid nohup sh -c '...' &`, detaching it from the
session's process group, and write per-stage `STAGE <name> rc=N` lines to an
evidence file under `tests/evidence/` (never scratchpad — a host reboot wipes
`/tmp`). At the start of any session, before rig work (especially rebuilds),
check for a live orphan with `tools/mxfs_pgrep.sh` and harvest its evidence
first — but its output is a point-in-time snapshot with no liveness
guarantee; always confirm `/proc/<pid>` still exists before treating a
listed pid as a live run. Detail:
[[trap-harness-survives-session-exit-check-mxfs-pgrep-before-rig-work]].

## Resource exhaustion produces the same symptom class: background work silently dies

Two later incidents show clyde's own memory pressure killing background rig
work the same way process-matching bugs do — no wedge, but a run that
vanishes mid-flight with the intermediate state left behind:

- **sess515**: 32 idle test VMs (leftovers from earlier boards, ~1.3GB RSS
  each) drove clyde to 0 free / 20 of 23GB swap; Claude Code's own host
  killed an 80-minute background rig chain with "system is running low on
  memory". The chain script itself survived as an orphan and died later at
  its own next failure. Fix: `virsh shutdown` (ACPI, often doesn't complete)
  then `virsh destroy` the idle VMs; check `free -g` before any long
  background job and shut VMs the job doesn't need; a killed wrapper does
  NOT kill the chain it launched — check `tools/mxfs_pgrep.sh` before
  assuming the rig is idle. Detail:
  [[trap-32-idle-vms-running-exhausts-clyde-ram-harness-kills-background-tasks-shut-idle-vms]].
- **sess594**: the same kill fired with 62GB genuinely available (`free -m`:
  650MB "free" but 63GB buff/cache) — the tool host's OOM threshold reads the
  cache-heavy `free` column, not the kernel's actual pressure. A deploy
  script had already brought both nodes down before dying, leaving neither
  node with a loaded module and nothing else announcing it. Fix: prefer the
  foreground for deploys and laps (the Bash tool's 600s cap covers
  `module_swap_deploy`'s 3-5 min and any 2-node lap ≤560s); after any killed
  background rig task, check both nodes' srcversion, mount count, and the
  script's log tail before trusting any marker — do not read "low on memory"
  as a clyde problem to fix. Detail:
  [[trap-the-tool-host-kills-a-long-background-rig-task-under-its-own-memory-threshold-mid-deploy]].

## Cross-cutting rules

1. Never match a live process by command-line substring on clyde — pidfile
   or anchored-pattern only, and check `comm`/`stat`, never `cmdline`/`maps`.
2. A D-state task cannot be killed or timed out; every "fix" that requires
   grabbing a lock the wedged task already holds (dmsetup resume, `virsh
   destroy` on a busy domain) will itself wedge and consume the escape
   hatch — stop and use the layered recovery path instead of retrying.
3. Any long-running host-local job (rig chain, deploy) can vanish without an
   MXFS-side cause: check host load and `free -g`/swap before it starts, and
   verify actual on-disk/module state after any unexplained failure rather
   than trusting the last log line.
