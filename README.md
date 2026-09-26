# MXFS — Multinode XFS

> **A shared-LUN clustered filesystem written entirely by AI.**
>
> Every line of the clustering, coordination, distributed-lock, fencing, and
> on-disk-envelope code in this repository was written by an autonomous AI agent
> (Anthropic's Claude Code) — **not** by a human using an AI tool. MXFS starts
> from the upstream Linux kernel **XFS** code, written by the XFS developers,
> and the AI has since modified much of it heavily (see "How this was built").
> Everything that turns XFS into a filesystem many machines can mount at once
> is AI-authored.

> ## ⚠️ Released configuration: 2 nodes, TCP or CAW transport — nothing else
>
> **The supported configurations are a 2-node cluster on either DLM
> transport:**
>
> - **TCP** — the lock manager talks over the network between the two nodes.
>   Works on any shared block device. The release packages default to it.
> - **CAW** — the lock state lives on the shared LUN itself and is claimed
>   with SCSI COMPARE AND WRITE. Needs a storage target that implements
>   COMPARE AND WRITE atomically (see "Choosing the transport" below).
>
> For both configurations no known defect has been shown to corrupt or lose
> data, or to crash, hang or shut down a node, with the one exception named
> below, and the full test suite passes on each. That is not the same as having
> no defects: the public queue (`data/defects.json`, read with
> `tools/defects.py`) holds **87 open defects**. **24 of them reach
> 2-node TCP** and **7 reach 2-node CAW**; apart from the exception below,
> each is classified as not crossing the data-loss or crash bar, most of them as
> slowness. Each record carries its own evidence. Read them before relying on
> MXFS: `tools/defects.py 2 tcp -d`, `tools/defects.py 2 caw -d`.
>
> **The exception, on TCP:** once, in 39 attempts on RHEL 9.8, a file create on
> the surviving node stalled for about 60 s after its peer was declared dead,
> fenced and replayed and then resumed
> (`D-SURVIVOR-CREATE-STALLS-60S-AFTER-PEER-DEATH-UNTIL-RESUMED-VICTIM-UNMOUNTS`).
> Its cause is not known, it has not recurred since, and it is shipped open by
> the owner's decision.
>
> **In development — do not use:**
> - **More than 2 nodes** (3 to 32), on either transport.
>
> That configuration still has open defects in the queue, including ones that
> can lose data or hang a node. Performance work is also still open on every
> configuration.
>
> **Released for exactly these kernels**, each installed from the release
> packages and verified on two x86-64 nodes sharing an iSCSI LUN, on both
> transports:
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
> Not yet recommended for production data.
>
> **Storage:** the shared storage's write cache must survive a power loss
> (battery- or flash-backed, as enterprise SAN and NAS arrays provide), or
> losing the storage target's power must be outside what the cluster has to
> survive. Crash-durable operation on unprotected caches is in development.
>
> The release packages configure both for you: `/etc/modprobe.d/mxfs.conf`
> sets `options mxfs force_transport=1` (TCP) and
> `options mxfs target_cache_protected=1` (the storage declaration above).
> Building from source, load the module with
> `modprobe mxfs target_cache_protected=1`: without it a clustered mount is
> refused. The module forms a new cluster on TCP by default; CAW has to be
> asked for with `force_transport=0` (see "Choosing the transport"). To see
> what still blocks each configuration:
>
> ```
> tools/defects.py 2 tcp --release   # released
> tools/defects.py 2 caw --release   # released
> tools/defects.py 32 caw            # 32 nodes, in development
> ```

---

## What MXFS is

MXFS ("Multinode XFS") lets **multiple nodes mount the same block device at the
same time**, read/write, with coherent caching and crash consistency — a
shared-disk clustered filesystem in the family of GFS2 and OCFS2, but built as a
fork of XFS.

- **One shared LUN, many nodes.** Every node opens the same device — reachable
  over iSCSI, Fibre Channel, or NVMe-oF — read/write, concurrently.
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
- **Distributed lock manager (`dlm/`).** Two transports can carry lock state:
  - **TCP (released, 2 nodes)** — a network DLM spoken over TCP between nodes.
  - **CAW (released, 2 nodes)** — lock state lives *in-band on the shared
    disk*, claimed with the SCSI **COMPARE AND WRITE** (opcode `0x89`) atomic
    primitive plus SCSI Persistent Reservations. No separate lock network is
    required, which is what lets it scale past the point where a network DLM
    stops keeping up (more than 2 nodes is still in development).

  The module parameter `force_transport` picks the transport a new cluster
  forms on: `1` (the default) is TCP, `0` is CAW. The release packages also
  set `1` explicitly. A node joining an existing cluster adopts the
  transport the cluster's members are already using.
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

## Build

MXFS builds as an out-of-tree kernel module against the running kernel's headers.

```
make modules     # build the kernel module -> mxfs.ko
make tools       # build the userspace tools
make install     # install the module (modules_install + depmod)
make load        # insmod mxfs.ko
make unload      # rmmod mxfs
```

A matching kernel build tree must be present at `/lib/modules/$(uname -r)/build`.
The module is developed against a **6.8.x** host kernel; its XFS source was
forked from the Linux 6.19 development tree, bridged by the `pal/`
compatibility layer. The
current version is recorded in [`VERSION`](VERSION).

## Tools

Built by `make tools`; the core three install into `/sbin` via
`make -C tools install`.

| Tool | Installed as | Purpose |
|---|---|---|
| `mkfs_mxfs` | `/sbin/mkfs.mxfs` | Format a block device for MXFS. |
| `chk_mxfs` | `/sbin/chk_mxfs` | Check / repair and report geometry — the MXFS `fsck`. |
| `resize_mxfs` | `/sbin/resize.mxfs` | Grow an MXFS filesystem after the device has been expanded. |
| `fua_verify` | — | Verify SCSI READ/WRITE **FUA** semantics across nodes on a shared LUN. |
| `caw_verify` | — | Verify SCSI **COMPARE AND WRITE** (`0x89`) persistence across nodes (built separately). |

Synopses:

```
mkfs.mxfs   [-f] [-n count] [-v] [-V] DEVICE    # -n = per-node log slices (1-64, default 4)
chk_mxfs    [-v] [-a|-p|-y|-n] DEVICE           # -n check-only (default); -a/-p/-y repair
resize.mxfs [-v] [-n] [-V] DEVICE               # -n = dry run
```

## Quick start

The released configurations are **two nodes on the TCP or the CAW
transport**. Install the release package on both nodes (it loads the module
with `force_transport=1 target_cache_protected=1`, i.e. TCP), or load a source
build with `modprobe mxfs force_transport=1 target_cache_protected=1` on both.
For CAW, see "Choosing the transport" below before the first mount.

```
apt install ./mxfs_<version>_amd64.deb                  # Ubuntu 24.04, Proxmox VE 9
dnf install epel-release kernel-devel-$(uname -r)       # RHEL / AlmaLinux / Rocky 9.8: DKMS is in EPEL
dnf install ./mxfs-<version>-1.el8.x86_64.rpm
```

With firewalld on, open the DLM, discovery, lock-hint and heartbeat ports on
both nodes:
`firewall-cmd --permanent --add-port=7600/tcp --add-port=7601/udp --add-port=7602/udp --add-port=7603/udp && firewall-cmd --reload`.
(7600/tcp carries the TCP transport's locks; 7602/udp carries the CAW
transport's lock-release requests and grant notices between the nodes.)

On the first node, format and mount the shared device:

```
mkfs.mxfs /dev/sdX
mount -t mxfs /dev/sdX /mnt/shared
```

On the second node, mount the **same** device — no reformat:

```
mount -t mxfs /dev/sdX /mnt/shared
```

The nodes discover each other and coordinate through the kernel module. Files
written on one node are visible on the other.

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

### Choosing the transport

Both transports are released for two nodes. Pick one per cluster, before its
first mount:

| | TCP | CAW |
|---|---|---|
| Where the locks live | messages between the two nodes | slots on the shared LUN, claimed with SCSI COMPARE AND WRITE |
| Storage it needs | any shared block device with SCSI Persistent Reservations | a target that implements COMPARE AND WRITE **atomically**, plus Persistent Reservations |
| Network it needs | a reliable low-latency link between the nodes | discovery and lock-release notices only (UDP) |
| How to select it | the package default (`force_transport=1`) | `force_transport=0` |

To run CAW, change the line in `/etc/modprobe.d/mxfs.conf` on **both** nodes
before the first mount, then reload the module (or reboot):

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

The setting only chooses the transport of a **new** cluster: a node that mounts
a volume the other node already has mounted joins on that cluster's
transport, and a mount that asks for TCP on a volume that already has CAW
members is refused. On a device that does not implement COMPARE AND WRITE a
CAW mount is refused at admission (`P311-CAW-ADMISSION-REFUSED`), so nothing is
written. Each mount logs which transport it runs:

```
dmesg | grep P-DOMAIN-ADMITTED       # ... transport=CAW)
```

**Not every target that accepts COMPARE AND WRITE honours it.** The Linux LIO
target reports success without an atomic compare-and-swap; on LIO use TCP.
This release's CAW verification ran on an SCST `vdisk_fileio` iSCSI target.
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
| `dlm/` | Distributed lock manager: CAW + TCP transports, discovery, membership, lease, disklock heartbeat, SCSI-PR fencing, journal slicing. |
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
