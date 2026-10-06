# MXFS — Multinode XFS

> **⚠️ THIS REPOSITORY IS THE DEVELOPMENT TREE, NOT A RELEASE. DO NOT INSTALL
> MXFS FROM IT.**
>
> **The code on this branch is work in progress. It has not been verified to
> release quality and cannot be considered production quality. To install
> MXFS, use a release package from the
> [Releases page](https://github.com/sshoecraft/mxfs/releases). Clone and build
> this repository only to run the latest development code, knowing it is not
> a release.**

> **A shared-LUN clustered filesystem written entirely by AI.**
>
> Every line of the clustering, coordination, distributed-lock, fencing, and
> on-disk-envelope code in this repository was written by an autonomous AI agent
> (Anthropic's Claude Code) — **not** by a human using an AI tool. MXFS starts
> from the upstream Linux kernel **XFS** code, written by the XFS developers,
> and the AI has since modified much of it heavily (see "How this was built").
> Everything that turns XFS into a filesystem many machines can mount at once
> is AI-authored.

> ## 0.90.51: multipath, verified by taking paths away
>
> **The `mpath` attachment is released at 2, 4, 8 and 16 nodes with both lock
> managers:** `{2,4,8,16}/net/mesh/mpath` and `{2,4,8,16}/disk/caw/mpath`.
> Every node reaches the shared LUN through a dm-multipath map over two iSCSI
> paths, each path on its own NIC and its own storage network.  Each of the
> eight configurations passed the 31-row suite the `direct` configurations
> pass, and then the path-fault rows of
> [`docs/mpath-verification.md`](docs/mpath-verification.md), all under load on
> every node: one path lost and returned and then the other, a whole storage
> network lost on every node at once, a flapping path, a mount and an unmount
> on one path, a node killed while the survivors are on one path, a fenced
> node whose dead path comes back, every path lost, a node that withdraws, and
> on `disk/caw` a lock command the target applied whose answer never arrived.
> A row passes only with no failed operation on any node, no node lost that
> the row did not kill, every stall under the bound, and every acknowledged
> file read back by checksum from another node.
>
> Making those rows pass took changes to the filesystem, not only to the rig:
> a node now registers its fencing key on each path itself and follows its
> paths as they come and go, the lone survivor's fence works with one
> registration per path, a `disk/caw` lock swap whose answer was lost is
> recognised as landed, and several faults that are not specific to multipath
> were found and fixed on the way (a lock wait that lost its registration, a
> refused lock upgrade that starved behind its own node's readers, a healthy
> node shutting down behind a stalled peer, a survivor opening a dead node's
> files as directories, a lookup failing when its name was removed under it).
> `CHANGELOG.md` has each with what was measured.
>
> **What this covers:** iSCSI; two paths on separate networks to ONE target;
> the multipath and initiator settings in `tools/mpath_settings.sh`, which are
> the ones to use; the test rig's platform, Ubuntu 24.04 with kernel
> 6.8.0-101-generic and multipath-tools 0.9.4.  **What it does not:** a second
> target or storage controller, Fibre Channel or SAS, more than two paths,
> other multipath settings, automatic failback to a preferred path group, and
> the other three platforms, whose package rounds attach on one path.
>
> The eight `direct` configurations and all four platforms were verified again
> on this build.

> ## 0.90.42: sixteen nodes
>
> **`16/net/mesh/direct` and `16/disk/caw/direct` are released.**  Sixteen
> nodes mounting one LUN, with either lock manager, passed the same 31-row
> suite the smaller clusters pass — data integrity, coherency, crash and fence
> recovery, pace against native XFS — on the build this release ships, and
> the 2-, 4- and 8-node configurations and all four platforms were verified
> again on it.
>
> Two defect records stood between 8 nodes and 16.  One was disproved by
> measurement.  The other was a real fault in the `disk/caw` lock manager's
> clean-up after an abandoned lock wait, found by reading the code and never
> seen on the rig: the clean-up could act on a lock slot that had since been
> reused for a different lock.  The check that stops it from releasing that
> other lock was already in the tree; this release adds a deterministic test
> for it and fixes what the test then showed — when the slot had been reused,
> the abandoned wait's own registration was left behind, which stalls every
> other node's readers of that lock.  See `CHANGELOG.md`.

> ## `2/net/mesh/drbd` is withdrawn: do not deploy MXFS on DRBD
>
> **MXFS on DRBD dual-primary (`2/net/mesh/drbd`) is no longer a released
> configuration, as of 2026-10-06.** On two physical Proxmox VE 9 hosts, eight
> concurrent VM installs on the shared filesystem shut both hosts' MXFS mounts
> down, and the guests whose disks were on it got I/O errors: installers failed
> and one guest's kernel panicked.  The validation it was released on, two
> Ubuntu 24.04 VMs on the test rig, never put that load on it, and most of
> what that load found is not specific to Proxmox.  The fixes are being made
> and verified on this development tree, on those two hosts;
> `tools/defects.py 2/net/mesh/drbd --release` lists what still blocks the
> configuration.  It is released again only when a release lists it under
> "Released" below.

> ## 0.90.41: MXFS on DRBD dual-primary — a clustered filesystem with no shared storage
>
> **Two nodes, a local disk each, no SAN, no iSCSI target, no third server.**
> DRBD replicates the two disks synchronously (protocol C) with both nodes
> Primary at once, and MXFS mounts `/dev/drbd0` read/write on both.  The
> configuration is **`2/net/mesh/drbd`**.  This is the smallest possible MXFS
> cluster: two Proxmox hosts with local NVMe can share one filesystem for VM
> images and live migration without buying storage.
>
> DRBD has no SCSI underneath, so it has neither persistent reservations (how
> MXFS fences a dead node) nor COMPARE AND WRITE (how it claims heartbeat and
> recovery records).  MXFS supplies both from the attachment itself:
>
> - **Fencing through an authority outside both nodes.**  DRBD's
>   `fencing resource-and-stonith` freezes I/O when a node loses its peer and
>   runs MXFS's handler, which has the site's fence authority (IPMI, a PDU, the
>   hypervisor) power the peer off and hold it off.  The authority grants one
>   winner per split.  The survivor proves the peer is off, disconnected and
>   Outdated (fence proof kind 25) before every irreversible recovery step.
> - **Admission by a witness.**  A mount is refused unless DRBD is on protocol
>   C with two primaries, MXFS's fence handler, every split-brain policy set to
>   `disconnect`, no suspended I/O, and this node a working, UpToDate Primary.
> - **A compare-and-swap on the replicated device**: a two-party bakery lock
>   in reserved sectors, with swaps group-committed under one acquisition.
> - **Recovery after both nodes lose power**: the first node back has the
>   authority hold its peer off, replays both journals, then lets the peer
>   rejoin.
>
> **Measured on the rig** (two nodes, DRBD 8.4.11, Ubuntu 24.04, the 0.90.41
> module built from the tree): the cluster suite's rows all passed, the
> fault rows and `crash_audit` included; a power cut of both nodes recovered
> with every file of both nodes intact, also when the recovery's completion
> was refused partway and finished by a resume; a recovery whose owner died
> was taken over and finished, by the owner's next boot and by the other
> node, every file intact; a node crash with a writer running was fenced,
> certified and recovered in 84 s with every fsynced file of both nodes
> intact; a link cut settled in 11 s and a split had exactly one winner in
> 11 s; unmount/remount cycles, a crash-cut retirement and a whole-cluster
> restart left nothing stalled; a device stacked on DRBD, and a loop device,
> were refused and left byte-identical.  Cold `chk_mxfs` clean after each.
>
> **Status: withdrawn on 2026-10-06** (see above).  It was released in 0.90.41,
> two nodes, on Ubuntu 24.04 with DRBD 8.4.11, the platform and DRBD version
> everything above was measured on.  The
> packages ship everything a DRBD node needs
> (`/usr/sbin/mxfs_drbd_witness.py`, `/usr/sbin/mxfs-drbd-fence-peer`).  Not
> yet run for this attachment, and therefore not claimed: the package-install
> round, and Proxmox VE 9, RHEL 9.8 and Debian 13.  Setup
> is in "DRBD dual-primary" under Quick start, the design in
> [`docs/attachment-methods.md`](docs/attachment-methods.md) ("DRBD
> dual-primary"), and the design rulings in
> [`docs/rulings/drbd-dual-primary-attachment.md`](docs/rulings/drbd-dual-primary-attachment.md).
>
> 0.90.41 is the first published DRBD release.  The attachment was built in
> 0.90.40, whose release validation found three ways a second fault during
> pair-outage recovery could leave a volume unmountable; 0.90.40 was held
> back, all three were fixed, and the tests that found them are part of what
> passed above.  A pair outage on `2/net/mesh/direct` is also no longer left
> REFUSED when the other host is still booting.
>
> Also since 0.90.39, for every configuration: a stacked device is never resolved
> to the disk underneath it for SCSI passthrough, a compare-and-swap never
> falls back to a plain write, a node joining after a whole-cluster bootstrap
> settles the adopted victim's lock records (reads of the inodes they covered
> used to hang), and a departing node hands its lock pages off in parallel.
> See `CHANGELOG.md`.

> ## 0.90.39: `mkfs.mxfs` is no longer slow
>
> **If you tried MXFS before and the format alone put you off, try it again.**
> `mkfs.mxfs` used to take tens of seconds on a small LUN and minutes on a
> large one, where `mkfs.xfs` takes a moment.  It now formats a 20 GB LUN in a
> quarter of a second.
>
> | LUN | before | 0.90.39 |
> |---|---|---|
> | 10 GB | 12.4 s | 0.13 s |
> | 20 GB | 17.9–30.9 s | 0.24 s |
>
> The cause was the lock authority ledger, which mkfs lays out on the LUN and
> sizes with it.  mkfs wrote every empty page of it as its own synchronous
> 4 KiB write, about 2.3 ms each: 10,571 of them for 20 GB, 67,650 for
> 128 GiB, so the wait grew with the LUN.  It now writes
> them in large batches, flushes once at the end instead of opening the device
> `O_SYNC`, and computes CRC32C in hardware.
>
> The formatted device is byte-for-byte identical: its sha256 matches the old
> binary's output at 10 GB and 20 GB.  Every board of this release formatted
> its LUN with it, and the 8-node boards' cold audit read clean on every node.
>
> Also in 0.90.39:
>
> - **Fixes for races that could crash or wedge a node**, all in the slots
>   that let a lock-release drain re-enter the inode lock.  A design review
>   found three; this version's own self-test found a fourth.  None was seen on
>   the rig before the fixes.  A release drain that cannot claim a slot is now
>   queued and retried instead of run without one.  0.90.37 has these races,
>   so upgrade from it.
> - **The RPM builds again.**  The 0.90.38 source tarball was missing a header
>   the new mkfs needs.
> - All six released configurations were verified on this version, and the
>   release boards now run side by side, each on its own fixed-size test LUN.

> ## Released: sixteen configurations, on the `direct` and `mpath` attachments
>
> A configuration is four fields, `<nodes>/<class>/<method>/<attach>`, for
> example `8/net/mesh/direct`. Each field is explained in the tables below and in
> [`docs/attachment-methods.md`](docs/attachment-methods.md).
>
> ### Released
>
> | configuration | first released in | platforms |
> |---|---|---|
> | `2/net/mesh/direct` | 0.89.77 | Ubuntu 24.04 from 0.89.77, Proxmox VE 9 from 0.89.78, RHEL 9.8 from 0.89.84, Debian 13 from 0.90.0 |
> | `2/disk/caw/direct` | 0.90.7 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `4/net/mesh/direct` | 0.90.24 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `4/disk/caw/direct` | 0.90.24 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `8/net/mesh/direct` | 0.90.36 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `8/disk/caw/direct` | 0.90.36 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `16/net/mesh/direct` | 0.90.42 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `16/disk/caw/direct` | 0.90.42 | Proxmox VE 9, RHEL 9.8, Ubuntu 24.04, Debian 13 |
> | `2/net/mesh/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `2/disk/caw/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `4/net/mesh/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `4/disk/caw/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `8/net/mesh/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `8/disk/caw/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `16/net/mesh/mpath` | 0.90.51 | Ubuntu 24.04 |
> | `16/disk/caw/mpath` | 0.90.51 | Ubuntu 24.04 |
>
> All sixteen were verified on the current release, 0.90.51: each
> configuration's suite on the test rig at its node count, and for the `direct`
> configurations the installed packages on two nodes of each of the four
> platforms. The `mpath` configurations were verified on the test rig only,
> which runs Ubuntu 24.04 (kernel 6.8.0-101-generic, multipath-tools 0.9.4),
> with the path-fault rows of `docs/mpath-verification.md` in each board:
> the package rounds on the other platforms attach on one path. A release
> claims exactly the configurations it lists.
>
> ### Implemented, not yet released
>
> The code runs these and the test rig can build them. No release has
> verified them yet, so they are not claimed.
>
> | method and attach | configurations |
> |---|---|
> | `net/mesh/direct` | `32/net/mesh/direct` |
> | `net/mesh/mpath` | `32/net/mesh/mpath` |
> | `net/mesh/pass` | `2/net/mesh/pass`, `4/net/mesh/pass`, `8/net/mesh/pass`, `16/net/mesh/pass`, `32/net/mesh/pass` |
> | `disk/caw/direct` | `32/disk/caw/direct` |
> | `disk/caw/mpath` | `32/disk/caw/mpath` |
> | `disk/caw/pass` | `2/disk/caw/pass`, `4/disk/caw/pass`, `8/disk/caw/pass`, `16/disk/caw/pass`, `32/disk/caw/pass` |
> | `net/mesh/drbd` | `2/net/mesh/drbd` (released in 0.90.41, withdrawn on 2026-10-06; see the top of this file) |
>
> Every other node count from 3 to 64 (3, 5 to 7, 9 to 15, and 17 and up) is in
> the same state on `net/mesh` and `disk/caw` with `direct`, `mpath` or `pass`.
> From 17 nodes up, open defects in the queue include ones that can lose data
> or hang a node.
>
> ### The four fields
>
> **`nodes`**: how many nodes mount the filesystem, 2 to 64. Released: 2, 4, 8 and 16.
>
> **`class`**: where the lock manager keeps lock state.
>
> | class | lock state lives |
> |---|---|
> | `net` | in node memory, exchanged over the network |
> | `disk` | on the shared LUN, claimed with a storage primitive |
>
> **`method`**: which lock manager of that class.
>
> | method | implemented | how it works |
> |---|---|---|
> | `net/mesh` | yes | Peer to peer over the network; lock mastership is spread across the members. The release packages default to it (`force_transport=1`). |
> | `net/server` | no | One lock server, or an active/standby pair, holds every lock. |
> | `disk/caw` | yes | SCSI COMPARE AND WRITE on a lock block on the LUN (`force_transport=0`). The storage target must implement COMPARE AND WRITE atomically (see "Choosing the transport" below). |
> | `disk/reserve` | no | SCSI-2 RESERVE/RELEASE around a plain write of the lock block. |
> | `disk/pr` | no | SCSI persistent reservations as the lock, or guarding its write. |
> | `disk/fused` | no | NVMe fused Compare+Write; the Linux block layer cannot issue it today. |
> | `disk/paxos` | no | Disk Paxos / Disk Lease: consensus on plain reads and writes. |
>
> **`attach`**: how the shared LUN reaches each node.
>
> | attach | implemented | released | the node's path to the LUN |
> |---|---|---|---|
> | `direct` | yes | yes | its own initiator, one path: bare metal, or an in-guest iSCSI login |
> | `mpath` | yes | yes | its own initiator over two or more paths, assembled by dm-multipath |
> | `pass` | yes | no | the hypervisor's initiator: the LUN is passed into the VM (QEMU SCSI passthrough, VMware RDM) |
> | `drbd` | yes | no: released in 0.90.41, withdrawn on 2026-10-06 | a DRBD dual-primary replica of two local disks: no shared storage at all |
>
> A configuration that names a method or an attach that is not implemented does
> not exist yet. `drbd` can never be more than two nodes, because DRBD allows
> exactly two primaries, and `docs/attachment-methods.md` limits it to `net`,
> because COMPARE AND WRITE cannot be atomic across two replicas. It fences
> through a fence authority outside both nodes (power off and hold off, proof
> kind 25) instead of SCSI reservations, which DRBD does not have; the
> authority is the site's own (IPMI, a PDU, a hypervisor), and what it must
> guarantee is in `docs/attachment-methods.md`.
>
> Both implemented methods fence a dead node with SCSI persistent reservations
> on the LUN, so both need storage that implements them
> ([`docs/fencing.md`](docs/fencing.md)).
>
> **Running 0.90.37 or earlier?  Upgrade.**  0.90.36 and earlier have defects
> that can lose data, and 0.90.37 has races that could crash or wedge a node
> (the claim-slot ones described under 0.90.39 above).  The data-loss defects
> were found after 0.90.36 shipped, measured on `8/net/mesh/direct`; the code
> involved is not specific to that configuration. All are fixed and verified
> since 0.90.37:
>
> - A name created in a directory that another node had just removed was lost
>   (`mkdir`, `link`, `symlink`, `rename`), and a `symlink` into such a
>   directory could shut nodes down.
> - An entry removed while other nodes were adding to its directory could
>   survive with its inode freed, and a shared directory's link count could
>   end up above its entries. A task whose lock-release claim had outlived its
>   release modified the directory with no lock grant.
> - A release claim whose owning process had exited was never retired, could
>   be inherited by an unrelated process, and could shut a node down.
>
> **No open defect that can lose data, or crash, hang or shut down a node,
> reaches any released configuration.**  That is the bar a configuration has
> to clear to be released, and `tools/defects.py <configuration> --release`
> shows it for each one.  The defect queue itself is public
> (`data/defects.json`, read with `tools/defects.py`), and every record carries
> its evidence.  It holds 94 open records.  51 of them reach only clusters
> larger than 16 nodes, which are not released.  The 43 that reach a released
> configuration (between 9 and 37 each, depending on the configuration) are
> each classified as
> not crossing that bar, most of them as slowness in a particular operation:
> `tools/defects.py --at 8/net/mesh/direct -d` lists them for one
> configuration.
>
> **Verified attachments: `direct` and `mpath`**, over iSCSI. In every
> verification, each node ran its own iSCSI initiator and reached the shared
> LUN either on one path with nothing between MXFS and the target (`direct`),
> or through a dm-multipath map over two paths to the same target (`mpath`,
> from 0.90.51, on Ubuntu 24.04 with multipath-tools 0.9.4 and the settings of
> `tools/mpath_settings.sh`). The `mpath` verification takes paths away under
> load; what it covers and what it leaves out is at the top of this file and
> in `docs/mpath-verification.md`. `pass` is not
> verified with either method: it carries the fencing reservations and, for
> `disk/caw`, the COMPARE AND WRITE lock commands through a layer no release
> has tested. Fibre Channel and SAS are not verified. A device without SCSI
> persistent reservations (virtio-blk, NVMe, md RAID) is refused at mount.
>
> **Without shared storage, `drbd`, is not released.** Two nodes, each with a
> local disk, replicated by DRBD dual-primary and fenced without SCSI
> reservations (`2/net/mesh/drbd`, `docs/attachment-methods.md`).  It was
> released in 0.90.41 on Ubuntu 24.04 with DRBD 8.4.11 and withdrawn on
> 2026-10-06, after it failed under real load on two physical Proxmox hosts
> (see the top of this file).
>
> What a build has to pass before it is called a release, and what that does
> not cover, is in "How a release is validated" below.
>
> **The exception, on `2/net/mesh/direct`:** once, in 39 attempts on RHEL 9.8,
> a file create on the surviving node stalled for about 60 s after its peer was
> declared dead, fenced and replayed, and then resumed
> (`D-SURVIVOR-CREATE-STALLS-60S-AFTER-PEER-DEATH-UNTIL-RESUMED-VICTIM-UNMOUNTS`).
> Its cause is not known, it has not recurred since, and it is shipped open by
> the owner's decision.
>
> **Directory sharding** (`mkfs.mxfs -D` with the module parameter
> `dirshard_mkdir_enable=1`) is experimental, off by default and part of no
> release. On `4/disk/caw/direct` a node's listing of a sharded directory that
> another node had just re-created failed with "Structure needs cleaning" in 3
> of 10 laps (`D-DIRSHARD-REUSE-PEER-READDIR-EUCLEAN-ON-CAW-AT-4-NODES`).
>
> **Performance:** every released configuration passes the suite's pace rows
> against native XFS on the same storage (`fio_perf`, `fio_perf_vs_xfs`), and
> every row of the suite runs under a time budget derived from native XFS.
> Performance work continues; the open records are in the queue.
>
> **Released for exactly these kernels**, each installed from the release
> packages on two x86-64 nodes of that platform sharing an iSCSI LUN and
> verified there with both lock managers (the 2-, 4-, 8- and 16-node suites
> run on the test rig, which is the Ubuntu 24.04 row):
>
> | platform | kernel verified |
> |---|---|
> | Proxmox VE 9 | 6.17.2-1-pve, 7.0.14-19-pve |
> | Ubuntu 24.04 LTS | 6.8.0-101-generic (the GA kernel) |
> | RHEL / AlmaLinux / Rocky 9.8 | 5.14.0-687.49.1.el9_8 |
> | Debian 13 | 6.12.107+deb13-amd64 (Debian 13.7) |
>
> **Any other kernel is untested, even on the same distribution.** MXFS builds
> against each kernel's own API, and a distribution's kernels differ: every
> RHEL 9 minor release reports 5.14 but carries different backports (9.2 has
> far fewer than 9.8), and Ubuntu 24.04 point releases install newer HWE
> kernels. The module may not build, or may build different code, on a kernel
> not listed here. On RHEL the RPM builds the module with DKMS (from EPEL) and
> installs an SELinux rule that labels MXFS files as XFS files are labeled.
> Other platforms are in development or planned — see `data/platforms.json`.
>
> **Storage:** the shared storage's write cache must survive a power loss
> (battery- or flash-backed, as enterprise SAN and NAS arrays provide), or
> losing the storage target's power must be outside what the cluster has to
> survive. Crash-durable operation on unprotected caches is in development.
>
> The release packages and `make install` configure both for you:
> `/etc/modprobe.d/mxfs.conf` sets `options mxfs force_transport=1`
> (`net/mesh`) and `options mxfs target_cache_protected=1` (the storage
> declaration above); without the second a clustered mount is refused. A new cluster forms on `net/mesh` by default; `disk/caw` has to be
> asked for with `force_transport=0` (see "Choosing the transport"). To see
> what still blocks each configuration:
>
> ```
> tools/defects.py 16/net/mesh/direct --release  # released; also 2/, 4/, 8/ and .../mpath
> tools/defects.py 16/disk/caw/mpath --release   # released; also 2/, 4/, 8/ and .../direct
> tools/defects.py 2/net/mesh/drbd --release     # withdrawn: not released
> tools/defects.py 32/disk/caw/mpath             # 32 nodes: not released yet
> ```

---

## What MXFS is

MXFS ("Multinode XFS") lets **multiple nodes mount the same block device at the
same time**, read/write, with coherent caching and crash consistency — a
shared-disk clustered filesystem in the family of GFS2 and OCFS2, but built as a
fork of XFS.

- **One shared LUN, many nodes.** Every node opens the same device — reachable
  over SCSI (iSCSI verified; see "Verified storage attachment" above) —
  read/write, concurrently. NVMe, NVMe-oF included, is not supported: the
  fencing and lock commands are SCSI's.
- **Or two nodes and no shared storage at all.** Two hosts with a local disk
  each, replicated by DRBD dual-primary, mount one MXFS filesystem read/write
  on both (`2/net/mesh/drbd`, "DRBD dual-primary" under Quick start).  Not
  released: withdrawn on 2026-10-06, see the top of this file.
- **Coherent and consistent.** A write on one node becomes visible to the
  others; metadata and data stay consistent across node failures.
- **One kernel module, no daemon.** All cluster coordination — locking, peer
  discovery, membership, heartbeat, fencing — runs in-kernel inside a single
  module, `mxfs.ko`. There is no userspace cluster daemon to run.
- **XFS on disk.** File data is stored in a standard XFS v5 filesystem, wrapped
  in an MXFS coordination envelope (see below).

## How it works

MXFS is a fork of upstream Linux **XFS**, taken from the Linux 6.19
development tree (no exact upstream commit was recorded), plus a coordination
overlay.

- **Forked and heavily modified XFS.** `xfs/` began as upstream XFS and has been
  changed throughout, not only extended: it is about 314k lines against about
  226k in upstream `fs/xfs`, and core files such as `xfs_inode.c` and
  `xfs_buf.c` are several times their upstream size. The MXFS overlay
  (`xfs/xfs_mxfs_dlm.c` plus per-allocation-group and per-inode hooks)
  intercepts the points where nodes would otherwise collide — allocation-group
  metadata, the inode cache, the buffer cache — and coordinates them across the
  cluster. It is not a patch series against upstream today.
- **Distributed lock manager (`dlm/`).** Two lock managers are implemented:
  - **`net/mesh`** (released at 2, 4, 8 and 16 nodes on `direct` and `mpath`,
    and at 2 nodes on `drbd`) — a network DLM spoken over TCP between nodes.
  - **`disk/caw`** (released at 2, 4, 8 and 16 nodes on `direct` and
    `mpath`) — lock state lives *in-band on the shared
    disk*, claimed with the SCSI **COMPARE AND WRITE** (opcode `0x89`) atomic
    primitive plus SCSI Persistent Reservations. No separate lock network is
    required, which is what lets it scale past the point where a network DLM
    stops keeping up (more than 16 nodes is still in development).

  The module parameter `force_transport` picks the lock manager a new cluster
  forms on: `1` (the default) is `net/mesh`, `0` is `disk/caw`. The release
  packages also set `1` explicitly. A node joining an existing cluster adopts
  the lock manager the cluster's members are already using.
- **Membership and fencing.** Peers are found by UDP-multicast discovery;
  liveness is tracked by an on-disk heartbeat with per-node slot claiming; a
  departed or partitioned node is fenced with SCSI Persistent Reservations
  before its resources are recovered. Each node owns a journal slice, so a
  survivor can replay a dead node's journal.
- **Platform abstraction (`pal/`).** All OS-specific code — VFS glue, block I/O,
  FUA reads, module init — routes through a `mxfs_pal_*` layer, which also keeps
  the DLM and tools buildable in user space.
- **On-disk envelope.** `mkfs.mxfs` lays the device out as:

  ```
  [ MXFS super  4 KB ] [ journal ~64 MB ] [ disklock ~32 MB ] [ XFS v5 data … ]
  ```

  The XFS superblock is shifted past the journal and disklock regions, and the
  4 KB MXFS super carries its own magic so the device is never mistaken for — or
  mounted as — plain XFS.

### ⚠️ Use the MXFS tools, never the stock XFS tools

`xfs_db`, `xfs_info`, `xfs_repair`, and `xfs_admin` are the **stock XFS tools
from `xfsprogs`** (installed system-wide under `/usr/sbin`) — they are *not* part
of MXFS. Because of the envelope above, they read the wrong sectors and return
empty or garbage output on an MXFS device. MXFS ships its own equivalents:

| Job | Stock XFS — do **not** use | MXFS tool |
|---|---|---|
| Format | `mkfs.xfs` | `mkfs.mxfs` |
| Check / repair (fsck) | `xfs_repair` | `chk_mxfs -a` / `-p` / `-y` |
| Geometry / info | `xfs_info` | `chk_mxfs -v` |
| Grow | `xfs_growfs` | `resize.mxfs` |
| Low-level debug | `xfs_db` | *(none yet)* |

There is no separate `mxfs_info` or `mxfs_repair` — `chk_mxfs` does both the
repair and the geometry/info jobs. There is currently no low-level debugger
equivalent to `xfs_db`. Tool names follow the standard Linux `mkfs.TYPE` /
`fsck.TYPE` convention (`chk_mxfs` also runs as `fsck.mxfs`).

## How this was built

MXFS was written **entirely by AI** — specifically Anthropic's **Claude Code**,
an autonomous AI coding agent — across many development sessions. No human wrote,
hand-edited, or line-by-line reviewed the clustering code. The human/AI boundary
is clean:

- **Human-written:** the upstream Linux kernel **XFS** source MXFS forked,
  written by the XFS developers (their copyright notices are kept in every
  forked file).
- **AI-written:** everything that makes it *multinode* — the DLM (`dlm/`), the
  coordination overlay (`xfs/xfs_mxfs_dlm.c` and the per-AG / per-inode hooks),
  the platform abstraction (`pal/`), the on-disk envelope, the userspace tools
  (`tools/`), and the test and benchmark harnesses — **and every change made
  to the forked XFS files since the fork**, which is a large share of `xfs/`.

## How a release is validated

A release claims configurations (`<nodes>/<class>/<method>/<attach>`,
[`docs/attachment-methods.md`](docs/attachment-methods.md)) and kernels, and it
claims each only after that exact build passed everything below on it. The set
of configurations a release must have green is its release matrix
(`data/configurations.json`). Nothing is
carried over from an earlier version: when a larger cluster size is
released, the smaller ones are run again on the same build. One script
drives the whole sequence and logs every step with its exit code
(`tests/release_verify_chain.sh`, which calls `tests/full_verify.sh`); their
headers are the reference for what follows.

### What a build must pass

1. **A build from a clean copy of the tree.** No compiler warnings, the
   userspace tools, the user-mode tests of the lock manager's authority
   ledger (`tests/tauth`), and two source audits (every cross-file
   declaration matches its definition; no two inode flags share a bit).
2. **The cluster suite, on every configuration of the release matrix.** About thirty rows (`tests/suite/manifest`), each run on a real
   cluster of that many nodes mounting one LUN:
   - what one node writes, every other node reads, and nothing is lost
     silently (`cache_coherency`, `strong_consistency`, `mmap_coherency`,
     `posix_multi`, `zero_silent_loss`, `rsync_paired`, the `dirent_*` rows,
     `dir_reuse_coherency`);
   - the lock manager under contention and membership change
     (`dlm_fairness`, `dlm_membership`, `dlm_scaling`, `scaling_curve`);
   - a node killed, or cut off from the others, in the middle of writing:
     the rest must fence it, replay its journal and go on serving
     (`crash_consistency`, `crash_audit`, `fence_during_write`,
     `fault_netpartition`);
   - no kernel fault, hang or filesystem shutdown on any node during any of
     it (`kernel_health`, `node_responsive`, `sustained_load`, `soak`);
   - the filesystem checker exits 0 on the LUN after all of it
     (`chk_clean`);
   - pace, against native XFS on the same storage (`fio_perf`,
     `fio_perf_vs_xfs`);
   - on an `mpath` configuration, the path-fault rows as well (`path_*`,
     defined in [`docs/mpath-verification.md`](docs/mpath-verification.md)):
     paths, a whole storage network and whole nodes taken away under load on
     every node. The run's log records that every node's mount sat on a
     multipath map with at least two active paths when the board started and
     when it ended, and a board that ends otherwise fails.

   The manifest lists every row with its budget.  Every row must read PASS on the board (`tools/criteria.py
   <configuration>`). The board keeps each row's last eleven runs, and a row
   with a genuine failure anywhere in that window does not read PASS: it
   has to pass lap after lap until the failure has left the window. A row
   that was skipped is not a pass either.

   Every row also has a time budget, derived from twice what the same work
   takes on native XFS plus the measured cost of forming the cluster
   (`tests/criteria/TIMEOUT_BUDGETS.md`). Running over it is a failure, even
   when every byte is right.
3. **The packages, installed as a user installs them, on every released
   platform.** On a set of nodes of that platform with a LUN of its own, as
   many nodes as the release claims: the package installs and DKMS builds
   the module against that platform's kernel; every node mounts with no
   options; each node writes 64 MiB and every other node reads it back by
   checksum; files created on one node are counted and removed on another;
   the checker exits 0; the nodes find each other by static `peer=`
   addresses with multicast dropped; every node is rebooted and the data is
   intact. Each configuration of the matrix; Proxmox on both of its kernels; RHEL with
   SELinux enforcing and its sVirt test (`tests/selinux_svirt_mxfs.sh`).
4. **A hung node, on every released platform, on each configuration of the matrix.** One
   node's CPUs are stopped in the middle of a write, so it answers nothing
   and closes nothing. The others have 120 s to declare it dead and 180 s
   to have fenced it, replayed its journal and written again
   (`tests/tcp_peer_freeze_death.sh`).
5. **The platform ledger.** `scripts/release.sh` runs each released
   platform's kernel build check and refuses to publish unless
   `data/platforms.json` holds a recorded verification of that exact version
   on every released platform (`tools/platforms.py check`).
6. **The text agrees with the data.** `tools/release_text_check.py` derives
   what is released from the release data (the release matrix, the
   configurations verified by a rig of their own, the platform ledger, the
   version, the defect queue) and reads this file, the manual pages, the
   installed module-options file, the storage guides and the module's own
   parameter descriptions against it: the Released table, the current
   version, the defect counts, the cluster sizes, and any wording that calls
   a released thing a trial, unverified, unsupported or in development.
   `scripts/release.sh` runs it before it builds a package and again before
   it publishes, and stops on a failure.
7. **The configurations with a rig of their own.** `2/net/mesh/drbd` is
   verified by `tests/drbd_release_verify.sh` (the suite on `/dev/drbd0`, then
   the remount, node-death, fence, split, device-resolution, pair-outage and
   takeover tests), not by a board column, so nothing would go red if its run
   were left out. `scripts/release.sh --publish` refuses a version without
   that script's PASS for it.

### The defect bar

The defect queue is public (`data/defects.json`, read with
`tools/defects.py`). Each record says what was observed, on what evidence,
and the smallest cluster and the configurations its evidence reaches (a
pattern such as `disk/caw/*`); a record nobody has classified counts against
every configuration.

- A configuration is released only when `tools/defects.py <configuration>
  --release` lists nothing: no open defect that reaches it and
  can corrupt or lose data, or crash, hang or shut down a node. An exception
  is the owner's decision and is named at the top of this file.
- A defect leaves the queue in two ways only. It is disproved by direct
  evidence, or it is fixed and verified: the cause shown by an instrument in
  the running kernel and not by reading the code, the change made at that
  cause, and a test that meets the cause passing under the criteria it had
  before. "Could not reproduce" closes nothing, and neither does a clean run
  that never met the cause.
- Where the defect is a crash or a race, the test is run on a control build
  as well. If the build without the change does not fail the way the defect
  did, the test proves nothing about the change. The 0.90.30 entry of
  `CHANGELOG.md` shows both arms for two such defects, with the numbers
  measured.

### What this does not cover

- **Every node is a virtual machine.** The development rig and the platform
  sets are KVM guests on one host, and the shared LUNs are iSCSI LUNs served
  from that host. This process has verified no release on separate physical
  machines or on a storage array.
- **Only the kernels and cluster sizes named at the top of this file.**
- **No run longer than the suite.** The `soak` row is 30 seconds unless it
  is asked for longer, and no multi-hour soak is part of the sequence.
- **Loss of power at the storage.** The write cache is required to survive
  it (see "Storage" above).
- **Anything the suite has no row for.** A passing suite says those rows
  passed. The first time two nodes were killed at once, under load, it
  found defects that every single-death row had passed over.

The raw logs of these runs (22 GB of kernel logs and traces) stay on the
rig host and are not in this repository. What is here is every harness, the
defect queue, and a changelog that carries the measurements each release
and each fix rests on. `lab/README.md` describes how the test platforms are
built.

## Build

MXFS builds as an out-of-tree kernel module against the running kernel's headers.

```
make             # build the kernel module -> mxfs.ko
make install     # as root: install everything a node needs (below)
make tools       # build the userspace tools in tools/ without installing them
make load        # insmod mxfs.ko
make unload      # rmmod mxfs
```

`make install` installs what the release packages install, from the same file
list (`packaging/common.sh`): the module (`modules_install` + `depmod`), the
tools (`mkfs.mxfs`, `chk_mxfs` with its `fsck.mxfs` link, `resize_mxfs`,
`mxfs_admin`) in `/usr/sbin`, the LU-reset and DRBD witness helpers, the DRBD
fence-peer handler `/usr/sbin/mxfs-drbd-fence-peer`, the man pages,
`/etc/modprobe.d/mxfs.conf` (an existing one is kept; `make install OVERWRITE=1`
replaces it and saves the old one as `mxfs.conf.backup`), `/etc/modules-load.d/mxfs.conf`
and the udev rule. It refuses to run on a host that already has an MXFS
package or DKMS module installed: remove that first, or two versions of the
module and the tools end up installed under the same names.

A matching kernel build tree must be present at `/lib/modules/$(uname -r)/build`.
The module is developed against a **6.8.x** host kernel; its XFS source was
forked from the Linux 6.19 development tree, bridged by the `pal/`
compatibility layer. The
current version is recorded in [`VERSION`](VERSION).

## Tools

Installed by `make install` and by the packages.

| Tool | Installed as | Purpose |
|---|---|---|
| `mkfs_mxfs` | `/usr/sbin/mkfs.mxfs` | Format a block device for MXFS. |
| `chk_mxfs` | `/usr/sbin/chk_mxfs` | Check / repair and report geometry — the MXFS `fsck`. |
| `resize_mxfs` | `/usr/sbin/resize_mxfs` | Grow an MXFS filesystem after the device has been expanded. |
| `fua_verify` | — | Verify SCSI READ/WRITE **FUA** semantics across nodes on a shared LUN. |
| `caw_verify` | — | Verify SCSI **COMPARE AND WRITE** (`0x89`) persistence across nodes (built separately). |

Synopses:

```
mkfs.mxfs   [-f] [-n count] [-v] [-V] DEVICE    # -n = per-node log slices (1-64, default 4)
chk_mxfs    [-v] [-a|-p|-y|-n] DEVICE           # -n check-only (default); -a/-p/-y repair
resize.mxfs [-v] [-n] [-V] DEVICE               # -n = dry run
```

## Quick start

The released configurations are 2, 4, 8 and 16 nodes with either lock manager
(`net/mesh` or `disk/caw`), each node reaching the LUN over iSCSI on one path
(`direct`) or through dm-multipath on two (`mpath`, with the settings of
`tools/mpath_settings.sh`), and two nodes with no shared storage on DRBD
dual-primary (`2/net/mesh/drbd`, its own section below). Install
the release package from the
[Releases page](https://github.com/sshoecraft/mxfs/releases) on every node; it
loads the module with `force_transport=1 target_cache_protected=1`, i.e.
`net/mesh`, and every node must run the same version. A source build of this
tree (`make && make install`) installs the development code, which is not a
release (see the notice at the top).
For `disk/caw`, see "Choosing the transport" below before the first mount.

```
apt install ./mxfs_<version>_amd64.deb                  # Ubuntu 24.04, Proxmox VE 9
dnf install epel-release kernel-devel-$(uname -r)       # RHEL / AlmaLinux / Rocky 9.8: DKMS is in EPEL
dnf install ./mxfs-<version>-1.el8.x86_64.rpm
```

With firewalld on, open the DLM, discovery, lock-hint and heartbeat ports on
every node:
`firewall-cmd --permanent --add-port=7600/tcp --add-port=7601/udp --add-port=7602/udp --add-port=7603/udp && firewall-cmd --reload`.
(7600/tcp carries the locks of `net/mesh`; 7602/udp carries the lock-release
requests and grant notices of `disk/caw` between the nodes.)

On the first node, format and mount the shared device:

```
mkfs.mxfs /dev/sdX
mount -t mxfs /dev/sdX /mnt/shared
```

On each other node, mount the **same** device — no reformat:

```
mount -t mxfs /dev/sdX /mnt/shared
```

The nodes discover each other and coordinate through the kernel module. Files
written on one node are visible on the others.

Discovery uses multicast (`239.66.83.1`). Where multicast does not pass, such
as Proxmox or ESXi nested inside VMware Workstation, or where one node sits on
another network, name the other node's address at mount time:

```
mount -t mxfs -o peer=10.0.0.12 /dev/sdX /mnt/shared      # on 10.0.0.11
mount -t mxfs -o peer=10.0.0.11 /dev/sdX /mnt/shared      # on 10.0.0.12
```

`peer=` adds unicast to multicast discovery and may be repeated;
`peers=A/B/...` replaces multicast with exactly that list and drops every
other sender. See `mxfs(5)` and [`docs/discovery.md`](docs/discovery.md).

### DRBD dual-primary (`2/net/mesh/drbd`)

**Not released: withdrawn on 2026-10-06** (see the top of this file).  Do not
put data you need on it until a release lists it again.

Two hosts, each with a local disk, and no shared storage, no third machine and
no fence hardware. The complete, tested setup is in
[`docs/drbd-setup.md`](docs/drbd-setup.md): `make install` on both, an LVM
volume per host, the DRBD resource (protocol C, two primaries, every
`after-sb-*` `disconnect`, `fencing resource-and-stonith` with
`/usr/sbin/mxfs-drbd-fence-peer`), `mkfs.mxfs` once, and
`systemctl enable --now mxfs-drbd@<resource>` to mount at boot.

Fencing is on by default with no configuration. On losing the peer, the host
with the lower DRBD address isolates the other from itself and carries on; the
other freezes and restarts, and rejoins once it is provably out. When that
lower-address host is the one that died, the other cannot tell it from a cut
link and waits for it, which no two-node system without a third vote or fence
hardware can avoid. A node fence (IPMI, a PDU, a hypervisor) replaces the
default through `/etc/mxfs/drbd-fence.conf`. Design:
[`docs/rulings/drbd-two-node-self-exclusion.md`](docs/rulings/drbd-two-node-self-exclusion.md).

Never restore a node of this pair from saved memory or a VM snapshot, and never
force-promote or mount `/dev/drbd0` by hand.

### Choosing the transport

Both lock managers are released for clusters of two, four, eight and sixteen
nodes, on `direct` and on `mpath`. Pick one per cluster, before its first mount:

| | `net/mesh` | `disk/caw` |
|---|---|---|
| Where the locks live | messages between the nodes | slots on the shared LUN, claimed with SCSI COMPARE AND WRITE |
| Storage it needs | any shared block device with SCSI Persistent Reservations | a target that implements COMPARE AND WRITE **atomically**, plus Persistent Reservations |
| Network it needs | a reliable low-latency link between the nodes | discovery and lock-release notices only (UDP) |
| How to select it | the package default (`force_transport=1`) | `force_transport=0` |

To run `disk/caw`, change the line in `/etc/modprobe.d/mxfs.conf` on **every**
node before the first mount, then reload the module (or reboot):

```
options mxfs force_transport=0
```

```
modprobe -r mxfs && modprobe mxfs
cat /sys/module/mxfs/parameters/force_transport     # 0
```

The setting survives a reboot on every released platform. On RHEL the RPM
keeps `mxfs` out of the initramfs (`/etc/dracut.conf.d/mxfs.conf`), so the
module is always loaded with the file on the root filesystem rather than a
copy baked into the boot image; an initramfs built by an earlier MXFS
package is rebuilt when the package is installed.

The setting only chooses the lock manager of a **new** cluster: a node that
mounts a volume other nodes already have mounted joins on that cluster's lock
manager, and a mount that asks for `net/mesh` on a volume that already has
`disk/caw` members is refused. On a device that does not implement COMPARE AND
WRITE a `disk/caw` mount is refused at admission (`P311-CAW-ADMISSION-REFUSED`),
so nothing is written. Each mount logs which lock manager it runs:

```
dmesg | grep P-DOMAIN-ADMITTED       # ... transport=CAW)
```

**Not every target that accepts COMPARE AND WRITE honours it.** The Linux LIO
target reports success without an atomic compare-and-swap; on LIO use
`net/mesh`. This release's `disk/caw` verification ran on an SCST
`vdisk_fileio` iSCSI target.
For any other target, prove it first with `caw_verify` from both nodes
([`docs/iscsi_setup.md`](docs/iscsi_setup.md) §4).

**Before trusting data, verify the storage.** The shared LUN must honor durable
(FUA) writes and SCSI Persistent Reservations, which MXFS uses to fence a failed
node. See [`docs/iscsi_setup.md`](docs/iscsi_setup.md) for the storage
requirements, and use `fua_verify` from both nodes to prove them before you
format.

## Repository layout

| Path | Contents |
|---|---|
| `xfs/` | XFS forked from the Linux 6.19 development tree and heavily modified, plus the MXFS coordination overlay — the bulk of the code. |
| `dlm/` | Distributed lock managers `net/mesh` and `disk/caw`, discovery, membership, lease, disklock heartbeat, SCSI-PR fencing, journal slicing. |
| `pal/` | Platform abstraction layer — kernel/userspace split, VFS + block-I/O glue, module init. |
| `mxfs_clayer/` | Cluster-layer helpers (pinned resources, adaptive yield quantum). |
| `tools/` | Userspace binaries: `mkfs` / `chk` / `resize` / `fua_verify` / `caw_verify`. |
| `include/`, `compat/` | Shared headers and compatibility shims. |
| `tests/` | Multi-node test harness + `tests/criteria/` ship-gate verifiers. |
| `bench/` | Performance benchmarks (paired against native XFS). |
| `scripts/` | Cluster orchestration and diagnostics. |
| `packaging/` | Debian packaging. |
| `docs/` | Architecture, operator, and man-page documentation. |

## License

MXFS is licensed under the **GNU General Public License, version 2** (`GPL-2.0-only`)
— see [`LICENSE`](LICENSE).

MXFS is a fork of the Linux kernel **XFS** filesystem, which is GPL-2.0. As a
derivative work, the combined kernel module (`mxfs.ko`) is necessarily licensed
under the same terms: you are free to use, study, modify, and redistribute it,
including commercially, provided derivative works are distributed under GPL-2.0
with complete corresponding source.

Copyright (C) 2026 Stephen P. Shoecraft.
