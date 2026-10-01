# Attachment methods and configurations

What MXFS is tested and released as, and why it is named the way it is. A
**configuration** names everything about a cluster that changes which code runs
and what the storage has to do:

```
<nodes>/<class>/<method>/<attach>        e.g.  8/net/mesh/direct
                                                2/disk/caw/mpath
```

| field | question it answers |
|---|---|
| `nodes` | how many nodes mount the filesystem |
| `class` | where the DLM keeps lock state |
| `method` | which DLM implementation of that class |
| `attach` | how the shared LUN reaches each node |

The definitions are `data/configurations.json`. The only code that parses a
configuration is `tools/configuration.py`, and every harness, the board
(`tools/criteria.py`) and the defect queue (`tools/defects.py`) ask it.

The native-XFS single-node baseline that the performance ceiling is measured
against is not a configuration of MXFS (no module, no DLM, no cluster) and is
spelled `1/xfs`.

## Vocabulary

- **configuration**: one full key, as above.
- **board**: the results of every criterion for one configuration
  (`tools/criteria.py 8/net/mesh/direct`).
- **release matrix**: the set of configurations a release must have green, in
  `data/configurations.json`. A release names its configurations exactly. A
  claim for N nodes is re-earned at every smaller node count it also claims, on
  the same module.

## Why four fields

The rig used to name what it tested with four condition codes, `tcp`, `cawd`,
`cawp` and `caw`. Each code fused two independent choices, the lock manager and
the attachment, and picked four points out of a grid. That hid two things:

- every release was verified on direct single-path iSCSI only, while the release
  text said "TCP" or "CAW" with no attachment named;
- TCP had no multipath or passthrough cell at all, although a TCP cluster fences
  through the LUN exactly as a CAW cluster does.

Every tool also parsed the codes its own way, with exact string matches: a defect
tagged `caw` never appeared in a `cawd` view, and the board's own configuration
list had no `cawd` or `cawp` column. Splitting the fields removed both problems.
The old codes are refused by name, and the tools say what replaces each one:

| retired code | configuration |
|---|---|
| `tcp` | `net/mesh/direct` |
| `cawd` | `disk/caw/direct` |
| `caw` | `disk/caw/mpath` |
| `cawp` | `disk/caw/pass` |
| `tcpmp` | `net/mesh/mpath` |

## What every configuration needs from the device

Both DLM classes use the shared LUN for more than data. A device that cannot do
these things cannot carry MXFS, whichever lock manager is chosen:

1. **SCSI persistent reservations, including PREEMPT AND ABORT.** This is how a
   dead or partitioned node is fenced before its journal slice is replayed
   (`dlm/scsipr.c`). The kernel side registers through the block layer's
   generic reservation ops; the fence itself needs a SCSI device underneath.
2. **SCSI FUA reads for cache coherency.** The coherency path builds SCSI
   commands and sends them itself (`pal/linux/kern.c`), because the Linux block
   layer does not carry FUA on reads.
3. **COMPARE AND WRITE, for `disk/caw` only.** The lock state lives on the LUN
   and is claimed with an atomic compare-and-swap.
4. **A distinct initiator identity per node.** A reservation key fences an I_T
   nexus. Two nodes that share one nexus are fenced together.

MXFS checks these at mount and refuses a device that fails them, rather than
mounting unfenced:

- no reservations (virtio-blk, anything without SCSI PR): `P303-FENCECAP-UNREGISTERED`;
- reservations but no PREEMPT AND ABORT (NVMe through the block layer): `P303-FENCECAP-NOABORT`;
- `disk/caw` on a device without COMPARE AND WRITE: `P311-CAW-ADMISSION-REFUSED`.

## Class: where the lock state lives

- **`net`**: lock state is held in node memory and exchanged over the
  interconnect. The lock traffic needs no storage primitive, but fencing and
  coherency reads still go through the LUN (above).
- **`disk`**: lock state lives on the shared LUN and is claimed with a storage
  primitive. No lock traffic crosses the network. The storage has to provide an
  atomic primitive, or the method has to build one out of plain I/O.

## Method: which implementation

| method | implemented | mechanism |
|---|---|---|
| `net/mesh` | yes | Peer-to-peer. Lock mastership is spread across the members, and a departure re-maps it. What `force_transport=1` loads. |
| `net/server` | no | One lock server (or an active/standby pair) holds every lock, and clients ask it. Lustre's lock manager and the StorNext metadata controller work this way. |
| `disk/caw` | yes | SCSI COMPARE AND WRITE on a lock block. What `force_transport=0` loads. |
| `disk/reserve` | no | SCSI-2 RESERVE/RELEASE: take the LUN, update the lock block, release it. VMFS worked this way before ATS. |
| `disk/pr` | no | SCSI persistent reservations used as the lock, or as the mutual exclusion around a plain write. |
| `disk/fused` | no | NVMe fused Compare+Write, NVMe's compare-and-swap. The Linux block layer cannot issue a fused pair, and the kernel's NVMe target rejects fused commands. |
| `disk/paxos` | no | Disk Paxos / Disk Lease: consensus on plain reads and writes to per-node blocks, with no atomic command. It works on any shared block device and costs more I/O per lock. |

A method that is not implemented is named so the grammar has a place for it. A
configuration that uses one is refused until it exists.

## Attach: how the LUN reaches each node

| attach | implemented | the node's path to the LUN | rig bring-up |
|---|---|---|---|
| `direct` | yes | Its own initiator, one path: bare metal, or an in-guest iSCSI login. | `scripts/rig.sh N/<class>/<method>/direct` |
| `mpath` | yes | Its own initiator over two or more paths, assembled by dm-multipath. | `scripts/rig.sh N/<class>/<method>/mpath` |
| `pass` | yes | The hypervisor's initiator. The disk is passed into the VM as a SCSI LUN (QEMU SCSI passthrough, VMware RDM). | `scripts/rig.sh N/<class>/<method>/pass` |
| `drbd` | no | DRBD dual-primary: each node's local disk, replicated synchronously to the other. | none |

Each attachment has its own way of breaking the requirements above:

- **`mpath`**: a reservation key is registered on every path. PREEMPT AND ABORT
  and path failover interact, and each distribution's multipathd handles
  reservations (`mpathpersist`) its own way. This is the most common production
  shape: dual-path iSCSI or FC.
- **`pass`**: VMs on one host can share one initiator identity. Fencing one node
  by its reservation key then also cuts off a healthy node on the same host.
  Reservations and COMPARE AND WRITE also have to survive the hypervisor's SCSI
  forwarding; QEMU forwards reservations only through `qemu-pr-helper`.
- **`drbd`**: see below.

### DRBD dual-primary

Two nodes, each with a local disk, and DRBD keeping them identical: a shared
filesystem with no shared storage array and no third server. Mainline DRBD
(`drivers/block/drbd/`) gives MXFS two properties it needs and lacks one:

- it refuses `allow-two-primaries` unless the replication protocol is C
  (`drbd_nl.c`), so a write completes only once both disks hold it;
- it carries FUA and flush to the peer (`DP_FUA`, re-applied on receive), so the
  journal's durability ordering holds across the pair;
- it implements no reservation ops, so it cannot be fenced by the storage.

So `drbd` needs, before any configuration can use it:

1. **A fencing method other than SCSI reservations** (`docs/fencing.md`): DRBD's
   own resource fencing to keep the victim's writes off the survivor's replica,
   plus a node fence, plus a split-brain tiebreaker. With two nodes and one
   replication link, a lost link looks like a dead peer to both sides.
2. **A coherency read path that does not use SCSI commands.** Under protocol C, a
   plain read of the local replica after a completed write is coherent. That has
   to be proved on the device and allowed only on DRBD protocol C.
3. **`net` only.** COMPARE AND WRITE cannot be atomic across two replicas: two
   nodes comparing against their own copies can both win. DRBD allows exactly two
   primaries, so the configurations are `2/net/mesh/drbd` and nothing larger.

Until then, today's mount refusal of a DRBD device is correct.

## Fabric is a separate question

The attachment says how many paths there are and whose initiator it is. The
fabric says what carries the SCSI commands: iSCSI, Fibre Channel, FCoE, SAS (a
shared dual-ported enclosure), or NVMe over Fabrics. The rig on clyde builds
iSCSI only, so a release names its fabric ("verified on iSCSI") and lists the
others as unverified. FC and SAS need hardware clyde does not have. NVMe of any
kind fails requirement 1 (above) today, and NVMe/TCP could be built with the
kernel's NVMe target only once MXFS supports NVMe.

## Device layers

A layer stacked between MXFS and the LUN has to pass all four requirements
through, or it is refused at mount:

- **refused**: NVMe; virtio-blk; md RAID (no reservations, and plain md on shared
  disks is unsafe regardless: each node keeps its own array state);
  md-cluster (it coordinates through the Linux DLM, but the device still carries
  no reservations or COMPARE AND WRITE); LVM or device-mapper volumes spanning
  more than one device (dm passes reservations through only when a volume maps to
  exactly one device, which is why dm-multipath works); DRBD until it has a
  fencing method.
- **fine behind a single target**: RAID inside the storage array; md or DRBD
  active/passive as the backend of one SCSI target. MXFS then sees an ordinary
  LUN and the attachment is `direct` or `mpath`. What has to hold is that the
  reservation state survives the target failing over.

## Open questions

- **Is the fence method part of the configuration?** For every implemented
  attachment it is SCSI reservations. `drbd` implies a combination
  (`docs/fencing.md`). It becomes a field of its own only when one attachment can
  be fenced more than one way.
- **Which attachments a release matrix must hold, and whether the per-platform
  rounds run each of them.** Each distribution's multipathd is its own
  implementation of reservation handling, so an `mpath` release verified on one
  OS says little about another.
- **Cloud shared disks** (Azure Shared Disks, EBS Multi-Attach, GCP multi-writer)
  behave like `direct` or `pass` depending on the platform. They need an
  attachment of their own only if their reservation semantics turn out to differ.
