# MXFS — Multinode XFS

> **A shared-LUN clustered filesystem written entirely by AI.**
>
> Every line of the clustering, coordination, distributed-lock, fencing, and
> on-disk-envelope code in this repository was written by an autonomous AI agent
> (Anthropic's Claude Code) — **not** by a human using an AI tool. The only
> human-written code is the upstream Linux kernel **XFS** tree it forks — the
> single-host filesystem MXFS builds on. Everything that turns XFS into a
> filesystem many machines can mount at once is AI-authored.

> ## ⚠️ Released configuration: 2 nodes, TCP transport — nothing else
>
> **The only supported configuration is a 2-node cluster using the TCP DLM
> transport.** For that configuration no known defect corrupts or loses data,
> or crashes, hangs or shuts down a node, and the full test suite passes.
>
> **In development — do not use:**
> - **More than 2 nodes** (3 to 32), on any transport.
> - **The CAW transport** (disk-based locking over SCSI COMPARE AND WRITE),
>   at any cluster size, including 2 nodes.
>
> Those configurations still have open defects in the queue, including ones
> that can lose data or hang a node. Performance work is also still open on
> every configuration.
>
> **Validated on Ubuntu 24.04 LTS (kernel 6.8) only.** Proxmox VE and Red Hat
> testing is next. Not yet recommended for production data.
>
> The release packages select TCP for you (`/etc/modprobe.d/mxfs.conf` sets
> `options mxfs force_transport=1`). Building from source, load the module
> with `modprobe mxfs force_transport=1`: without it a new cluster forms on
> CAW. To see what still blocks each configuration:
>
> ```
> tools/defects.py 2 tcp --release   # the released configuration
> tools/defects.py 2 caw             # CAW, in development
> tools/defects.py 32 tcp            # 32 nodes, in development
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

MXFS is a fork of upstream Linux **XFS (6.19-rc0)** plus a coordination overlay.

- **Forked XFS + overlay.** The entire `xfs/` tree is upstream XFS. The MXFS
  overlay (`xfs/xfs_mxfs_dlm.c` plus per-allocation-group and per-inode hooks)
  intercepts the points where nodes would otherwise collide — allocation-group
  metadata, the inode cache, the buffer cache — and coordinates them across the
  cluster.
- **Distributed lock manager (`dlm/`).** Two transports can carry lock state:
  - **TCP (released, 2 nodes)** — a network DLM spoken over TCP between nodes.
  - **CAW (in development)** — lock state lives *in-band on the shared disk*,
    claimed with the SCSI **COMPARE AND WRITE** (opcode `0x89`) atomic
    primitive plus SCSI Persistent Reservations. No separate lock network is
    required, which is what lets it scale past the point where a network DLM
    stops keeping up.

  The module parameter `force_transport` picks the transport a new cluster
  forms on: `1` is TCP, `0` (the module's built-in default) is CAW. The
  release packages set `1`. A node joining an existing cluster adopts the
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

- **Human-written:** the upstream Linux kernel **XFS** source (the `xfs/` tree),
  which MXFS forks — the local, single-host filesystem MXFS is built on.
- **AI-written:** everything that makes it *multinode* — the DLM (`dlm/`), the
  coordination overlay (`xfs/xfs_mxfs_dlm.c` and the per-AG / per-inode hooks),
  the platform abstraction (`pal/`), the on-disk envelope, the userspace tools
  (`tools/`), and the test and benchmark harnesses.

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
The module is developed against a **6.8.x** host kernel; its XFS source is forked
from upstream **6.19-rc0**, bridged by the `pal/` compatibility layer. The
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

The released configuration is **two nodes on the TCP transport**. Install the
release package on both nodes (it loads the module with `force_transport=1`),
or load a source build with `modprobe mxfs force_transport=1` on both.

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

**Before trusting data, verify the storage.** The shared LUN must honor durable
(FUA) writes and SCSI Persistent Reservations, which MXFS uses to fence a failed
node. See [`docs/iscsi_setup.md`](docs/iscsi_setup.md) for the storage
requirements, and use `fua_verify` from both nodes to prove them before you
format.

## Repository layout

| Path | Contents |
|---|---|
| `xfs/` | Forked upstream XFS (6.19-rc0) + the MXFS coordination overlay — the bulk of the code. |
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
