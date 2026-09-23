---
name: compiled-test-environment-infra-reference
description: MXFS rig topology, shared-LUN stack evolution (LIO→SCST/mpath), VM/NFS/ship-gate rules, and design-reference pointers (prior mxfs versions, GFS2/OCFS…
metadata:
  type: project
tags: [compiled, environment, infra, rig, reference, test-cluster]
---

## Topic

MXFS test-environment and infrastructure reference: what the rig physically
is, how its shared-storage stack evolved, the recurring VM-stability fixes,
the NFS `/src` rules, the ship-gate tooling, and the external reference
material (prior MXFS versions, other clustered filesystems) used for design
comparison. Not defect history — this is "what the rig is and where the
facts live," compiled because these notes were reference-only and aging
(38-165 days) without ever being cross-linked.

### Machines

[[Network topology]] + [[test-environment]]: clyde is the dev host, two
NICs — `192.168.1.166` (main LAN, physical nodes' iSCSI path) and
`192.168.120.1` (lab/VM bridge, `br0`, dnsmasq DNS+DHCP, test VMs' iSCSI
path). Same box, same underlying LUN reachable both ways. ~94G RAM — the
32-VM fleet (test1-test32, Ubuntu 24.04, 4 vCPU/4GB each, test2 historically
2 vCPU/2GB and needs fixing before scale tests) does NOT fit all-at-once;
batch heavy fleet ops ~8 at a time. Other hosts: pve1/pve2 (physical
Proxmox, Xeon W3520/W3550, kernel 6.17.2-1-pve, QNAP iSCSI LUN, **no SCSI
CAW support — TCP DLM only**), z440/serv (dev box, not .55),
solardirector (RPi aarch64, no kernel headers). A multi-OS/kernel fleet
beyond the Ubuntu-24.04 test1-32 set was later defined in `lab/vms.md`
(proxmox-ve-9.1/8.4, rhel/alma/oel/sles/debian/fedora variants) built via
osimager `mkosimage`; as of that note only Proxmox 9.1 and Ubuntu 24.04
(subiquity) auto-install cleanly — Fedora 43 and Debian 13.3 preseed both
broken. Credentials for all nodes: `~/.config/mxfslab/secrets` (mode 600,
never in the repo), resolved by `tools/mxfs_secrets.sh` /
`tools/mxfs_sshpass.sh`; node root password is kept in sync with osimager's
`images/linux` secret.

### Shared-LUN stack: superseded, do not follow the old recovery steps literally

[[test-environment]] and [[env-cluster-bringup-after-host-reboot]] both
document an EARLIER rig generation: a single shared LUN via **LIO
fileio + tcm_loop, no iSCSI** (`/home/steve/disk.img` → `/dev/mxfs-shared`
→ `/dev/sda` in guests), rebuilt post-reboot with
`scripts/lio_tcm_setup.sh setup` and a `/tmp/.mxfs_pass` restore from
`/home/steve/.mxfs/pass`. **This is stale.** The current fleet (see
`compiled-rig-operational-traps`, `rig-recovery-after-clyde-reboot-scst-mpath`)
is SCST + dm-multipath (`/dev/mapper/mpatha`, dual portal, for CAW) — the
`tcp` board condition alone still targets the old LIO/`/dev/sda` rig, which
is why `./run.sh 32 tcp prep_cluster` fails on the current fleet
(`/dev/sda` claimed by dm-1) and needs `MXFS_DEV=/dev/mapper/mpatha` to
exercise TCP DLM on today's hardware. Read `env-cluster-bringup-after-host-
reboot`'s three numbered steps as documentation of a past incident's fix,
not a current runbook — the current post-reboot sequence is
`scst_setup.sh setup` → `mpath_up.sh up 32` → preflight → `prep_cluster`.
What both eras agree on and remains true: a missing/mis-permissioned SSH
passfile masquerades as a hung/wedged node (looks like rc=124/143, is
really absent auth) — always check the passfile before diagnosing a node
as dead.

### VM stability fixes (still current)

[[env-test1-dhcp-reservation-fix-sess29]]: test1/test2 IPs come from a
system dnsmasq on `br0:67` (`/etc/dnsmasq.d/lab.conf`), not libvirt's
default network — originally a bare dynamic range with no reservations, so
a lease could silently move (test1 .186→.114) and strand any script that
hardcodes an IP. Fixed permanently with `dhcp-host=<MAC>,<IP>,<name>`
entries + `systemctl restart dnsmasq`. Gotcha: dnsmasq loads every file
under `/etc/dnsmasq.d/`, `.dpkg-*` excepted — a stray `.bak` there is
"illegal repeated keyword" and dnsmasq won't start; keep backups
elsewhere. Console recovery when a node is unreachable over SSH:
`scripts/vm_console_type.py <dom> --text ... --enter` types into the VGA
console via `virsh send-key`; serial console (`virsh console`) is silent
on these VMs, so use `virsh screenshot` + Read the PNG to see actual state.

### `/src` NFS rig rules (still current)

[[infra-src-is-qnap-nfs-do-not-touch-exports]]: `/src` on clyde AND every
test VM is an NFS mount **from the QNAP** (`192.168.1.4:/src`), not served
by clyde — clyde re-mounts it too. Never touch clyde's `/etc/exports` or
`exportfs` for this, never repoint `NFS_SERVER` away from `192.168.1.4`,
never "fix" it by exporting from clyde or `192.168.120.1`. If a node
reports `mxfs.ko` missing, the fix is simply `make modules` on clyde (which
writes into the QNAP-backed tree, visible to every node) — nothing else.
clyde's own QNAP mount is `soft`, so `modinfo` there can report a stale
cached srcversion after a clean; verify with `ls -la mxfs.ko` instead.

### Ship-gate and status tooling (still current)

[[criteria-ship-gate]]: `SUCCESS_CRITERIA.md` (copied from mxfs.1) is the
spec; verifiers live in `tests/criteria/`, each prints `RESULT: PASS|FAIL`
and persists to `.criteria_results.json`. Run the whole gate via
`tests/criteria/verify_ship.sh` (stops at first FAIL, or `--keep-going`),
one criterion via `tests/criteria/<name>.sh --nodes N`. Adapting .1's suite
to v5 required: `MXFS_REPO`/`DEFAULT_NODES` updated (cluster is no longer
partitioned — all of test1-32 available), mount syntax changed (v5 has no
`dlm_transport` mount option; transport is the `force_transport` module
param, plumbed through `MXFS_MOUNT_OPTS`), and a real bug in
`verify_ship.sh` where an unsplit `"script.sh --flag val"` string was
passed straight to `bash` as one filename (fixed with `read -ra`).
[[test-status-showstat]]: `./showstat.sh <N> <dlm>` (e.g. `./showstat.sh 2
tcp`) reads `criteria.json` (regenerated by `scripts/gen_criteria.py`,
written to by `tests/suite/run_one.sh`) and prints the PASS/FAIL/PENDING
matrix keyed by `<nodes>/<dlm>`. Coordinated multi-node tests were, as of
that note, skipped by `run_suite.sh` ("coordinated runner TBD") — only
`coord=none` tests auto-run there; `run.sh <N> <dlm>` is the coordinated
runner.

### End-user deployment requirements (still current)

[[doc-enduser-iscsi-caw-setup]]: `docs/iscsi_setup.md` is the end-user-facing
"what a real shared LUN must provide" doc, distinct from the clyde-specific
test-rig doc. Core requirements for CAW: SCSI COMPARE AND WRITE (0x89)
honored atomically (not faked), SCSI PR type 5 (WRITE-EXCL
REGISTRANTS-ONLY) per I-T nexus, write-through target cache, FUA reads
reaching media. Target matrix: SCST supports real CAW; LIO fileio/iblock
fakes it (TCP DLM only on that backend); vendor arrays need verification
via `sg_opcodes` + `tools/caw_verify` + `tools/fua_verify`. Required per-node
tuning: `echo 180 > /sys/block/sdX/device/timeout` (+ udev rule) to avoid
the 30s-timeout → ABORT_TASK → nexus-loss → permanent-LUN-wedge failure
class.

### Design-comparison reference sources (still current)

[[reference-clustered-fs-sources]]: local paths for comparing MXFS's
coherency model against established clustered filesystems —
`~/src/linux/fs/gfs2/` (glock demote: synchronous `go_sync`+`go_inval`
before DLM unlock; anti-starvation via min hold-time + DLM queue
fairness), `~/src/linux/fs/ocfs2/` (LVB-based: downconvert thread
checkpoints then sets an LVB carrying i_size/times/generation, so a
generation match skips a disk re-read; anti-starvation via a
BAST-set blocked flag), and `~/src/linux/fs/dlm/` (`lock.c`: a queued
convert or wait entry blocks new grants — the fairness reference MXFS's
own AG-DLM anti-starvation work has repeatedly drawn on).

### Prior MXFS iterations — why they matter, and what they showed

[[Prior mxfs version directories — load-bearing context for v5 work]]:
`~/src/mxfs.{1,2,3}` hold earlier full implementations with their own
populated awareness docs, bug journals and scaling benchmarks that v5
(this repo) started fresh without inheriting — noted because sess20-27
of v5 re-discovered issues (TCP DLM scale limits, BAST delivery semantics,
lease/disconnect interaction, peer reconnect cooldowns, membership
stabilization) already characterized there. Key pointers:
`mxfs.1/.claude/awareness/subsystems/{cluster,dlm,platform-vfs}.md`,
`mxfs.1/docs/{architecture,dlm-protocol,perf}.md`,
`mxfs.1/libmxfs/*.md` (per-module changelogs), `mxfs.1/bench.json`
(1.01x CAW vs 7.7x TCP write spread), `mxfs.2/NEWSYS.md`,
`mxfs.3/{journal,project}.md`. Decision at the time (sess28): research
this corpus first, bootstrap v5's own awareness system later with
carry-forward facts (that bootstrap has since happened — see this
project's `.claude/awareness/`).

[[reference_mxfs1_sess74_results]]: sess74 (2026-05-07) resurrected and
benchmarked mxfs.1 v0.14.0 on the SAME hardware v5 uses. Morning numbers
looked like a clean win for mxfs.1 (fio ~1.00-1.03x XFS single-node, 100%
on 5×256/15×256/15×512 cross-node dd stress vs v5's 80% / mixed / mixed)
but an rsync-of-element-web run the same day found mxfs.1 has a
**single-node** dir-format-transition corruption bug (`libmxfs/dir_cache.c`
flush path corrupts dir blocks on SF→block→leaf transition; rsync silently
dropped ~84% of the tree) that v5 does not share — v5's bug surface is
cross-node instead. Conclusion at the time: neither version was
production-ready, and the v5-vs-mxfs.1 architecture question stayed open;
don't compare v5's freshly-measured numbers against mxfs.1's stale figures
without re-measuring both on the same hardware in the same session, and
don't port v5's manual-bio CAW fix into mxfs.1 prophylactically — mxfs.1's
PAL passed 100% at 2-node without it, so the bio-aliasing hypothesis behind
that v5 fix doesn't appear to apply there. FUA-on-write storage facts
(Samsung 870 EVO `bdev_fua=0`, LIO `emulate_write_cache=0`) are environmental
and apply to both versions equally.

### Closed performance investigation: mxfs-vs-XFS single-node fio gap

[[mkfs-mxfs-vs-mkfs-xfs-agcount-geometry-difference]]: an apparent "mxfs is
2.5x faster than XFS" single-node fio result was a TEST METHODOLOGY bug,
not a real mxfs advantage or a benchmark artifact — every comparison used a
fresh file each time, so both sides were being measured at first-touch
(never-before-written extents), and first-touch vs steady-state throughput
differs by very different ratios per filesystem (XFS 15,645→44,582 iops,
2.85x; mxfs 36,674→53,238 iops, 1.45x). At steady state mxfs is ~93-99% of
XFS — near parity, as expected for a thin overlay on the same fork. Fixed
by making `tests/suite/fio_perf.sh` run each workload twice and report only
the second pass; `tests/tooling/fio_vs_xfs_baseline.sh` was deliberately
left first-touch-only (different, complementary, already
position-balanced). Ruled out as causes of the *asymmetry* itself: the
per-mount ILOCK hook (fires uniformly on every acquisition, not just
first-touch), mkfs_mxfs's AG geometry (mxfs targets ~1GB/AG vs stock XFS's
~12.5GB/AG on the same LUN — reformatting XFS to match changed nothing),
host page cache (device is `o_direct=1`, confirmed via SCST vdisk config),
sparse allocation. Left open and NOT investigated further (user's explicit
call): why mxfs's first-touch penalty is smaller than XFS's despite
byte-for-byte identical allocation code in the traced paths
(`xfs_direct_write_iomap_begin`, `xfs_iomap_write_direct`,
`xfs_iomap_write_unwritten`, `xfs_dio_write_end_io`) — the measurement
itself was single-shot and non-position-balanced, so before trusting the
magnitude (or that the asymmetry is even real), redo it position-balanced
with repeated rounds; escalate to blktrace only if the effect survives
that. If it does hold up, it's a legitimate architectural win to document,
not a bug to fix (durability-skipping and data-caching were already ruled
out as explanations).
