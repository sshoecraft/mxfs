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
| `drbd` | yes | DRBD dual-primary: each node's local disk, replicated synchronously to the other. Released as `2/net/mesh/drbd` in 0.90.41, withdrawn on 2026-10-06 (README). | `scripts/drbd_rig.sh` (a rig and a board of its own: see below) |

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

What replaces the storage's facilities (the design and its consult ruling are
in `docs/rulings/drbd-dual-primary-attachment.md`):

1. **Admission by a witness, not a reservation.** DRBD exports no in-kernel
   interface, so a node-local helper (`tools/mxfs_drbd_witness.py`) reads
   `/proc/drbd`, drbdadm's parse of the resource, the fence-peer handler's
   receipts and the fence authority's live answer, and reports them through
   `/proc/fs/mxfs/drbd_report` under a kernel nonce (`pal/linux/drbd.c`).
   `dlm/drbdfence.c` judges the report: protocol C, two primaries,
   `fencing resource-and-stonith` with this attachment's handler, every
   `after-sb` policy `disconnect`, no suspended I/O, this node Primary and
   UpToDate, and either both disks UpToDate with the fence authority reachable
   or the peer already fenced in the current episode. A DRBD mount holds no PR
   context.
2. **A compare-and-swap built on the device.** Every record the network lock
   manager updates with COMPARE AND WRITE (heartbeat, slot claim, recovery
   milestones, bootstrap owner, ledger tickets) is updated on DRBD by a
   read-compare-write held under a two-party Lamport bakery lock in reserved
   sectors 48-50 of the bootstrap region. Each register is written only by its
   owner, protocol C completes a write only once both disks hold it, and the
   registers bind the filesystem, the participant index and both endpoints so
   a pair that disagree about who is participant 0 refuses instead of sharing a
   register. The swap is atomic only against other swaps, so no plain write may
   touch a protected sector. Swaps are group-committed: every swap on one node
   queues, and whichever caller holds the node's lock serves all queued swaps
   (up to 32) inside one bakery acquisition, each read-compare-write in queue
   order, releasing once after every target write has completed. A swap costs
   a doorway (two replicated writes and a read) and a release (one write) on
   top of its own read-compare-write; served one at a time under a lock
   workload, swaps queued for 130 ms on average behind each other and pushed
   lock handoffs past the 1 s acquire wait.
3. **A fence proof profile of its own, kind 25 (`DRBD_STONITH_WITNESSED_V1`).**
   DRBD's `fencing resource-and-stonith` freezes a Primary's I/O when it loses
   its peer and runs the fence-peer handler (`tools/mxfs_drbd_fence_peer.sh`),
   which asks the fence authority to power the peer off and hold it off. The
   authority serialises requests, so in a split exactly one side is granted,
   and it names each grant with an episode. Before replay the survivor takes
   the witness again: the link disconnected, the peer's disk Outdated, a
   STONITHED receipt naming the peer, and the authority reporting the peer off
   and inhibited under that receipt's episode. That is the admission half. The
   retirement half comes from the same state: DRBD reaches a disconnected state
   only after it freed the replication socket and waited for every peer write
   already submitted to the local disk (`drbd_receiver.c`,
   `conn_disconnect`/`drbd_disconnected`), a completed operation of the
   survivor's own target. The certificate binds a victim key derived from the
   incarnation it excludes, because a DRBD mount registers none.
4. **Continuing exclusion.** The same witness is taken before every
   irreversible recovery step, and a peer that was started again or reconnected
   fails it. "Connected and Secondary" is not exclusion. A fenced node rejoins
   only after the survivor's recovery completes and the survivor releases its
   inhibit: then it boots, DRBD resyncs it, it is promoted once UpToDate, and it
   mounts through admission like any node.
5. **Retirement of a clean departure is the departure itself.** On SCSI a
   cleanly released heartbeat slot becomes reusable only once some node proves
   the departed incarnation's PR key absent, because a registered key is a
   device-enforced write capability. A DRBD Primary holds no such capability:
   nothing at the device level ever withdraws its writes outside a fence. What
   retirement protects against is the old incarnation writing again after its
   slot is reused, and on this attachment that can only be the incarnation
   itself, which unmounted, or an old incarnation brought back from saved
   memory. So: the release record is written only after the unmount record is
   durable; every record of a DRBD incarnation carries `MXFS_HB_FEAT_DRBD`; the
   departing node publishes its own slot EMPTY after its release, and a record
   a crash left between the two is published EMPTY by the next DRBD node that
   reads it, from its exact image. Only a DRBD mount applies the rule, only to
   a record carrying the marker; key 0 alone stays unknown. Bringing an old
   incarnation back is excluded by prohibition: a node of this attachment is
   never restored from saved memory or reverted to a snapshot. A design consult
   held that a stricter rule needs external revocation of the departed
   incarnation (in practice a power-off per unmount, or an externally enforced
   promotion permit); the rule above is the decision taken instead, with the
   prohibition carrying what revocation would.
6. **The fence authority is the site's.** The handler and the witness reach an
   authority outside both nodes, by `ssh` to a forced command or by `exec` of a
   local program (`/etc/mxfs/drbd-fence.conf`), that answers three verbs:
   `fence <target> <requester>` (power the target off, inhibit its restart under
   a fresh episode, and refuse a requester that is itself inhibited, so a split
   has one winner), `status <target>`, and `release <target> <episode>
   <requester>`. What it must guarantee: the inhibit survives the authority's
   own restart and holds against every way the target can be started; only the
   survivor's `release` clears it; it never restores a node from saved memory.
   The packages ship the witness and the handler (`/usr/sbin`); the authority is
   the site's own (IPMI, a PDU, its hypervisor). The rig's is
   `tools/rig_fence_virsh.sh`, with a libvirt hook (`tools/libvirt_qemu_hook.sh`)
   that refuses to start an inhibited VM by any path and to restore one from
   saved memory.
7. **A pair outage is recovered by startup fencing.** When both nodes die at
   once nobody survives to fence, and on restart the bootstrap finds two dead
   incarnations that registered nothing a reservation could preempt. The pair
   has exactly two endpoints, so the first node to mount fences its peer
   through the authority before it claims the bootstrap record: once the other
   endpoint is off and inhibited and this node runs a new incarnation, no
   recorded incarnation of either can write. Every victim is certified by kind
   25 against that fence (its key derived from the incarnation, as the
   certificate binds it), both slices are replayed, and completion re-checks
   that the peer is still held off, which on SCSI the registrant reconcile
   proves. The peer rejoins through the survivor's release. If both nodes
   bootstrap at once, the authority grants one and powers the other off. The
   cost is one power cycle of the peer after a pair outage, the same trade
   Pacemaker's startup fencing makes.

   **A bootstrap owner that fails mid-term is taken over by the same proof.**
   The owner and any earlier contender are the peer or an earlier boot of this
   host, so a contender that has watched the record and the takeover journal
   stand still for the abandon window asks for the startup fence before it
   writes anything, and then excludes each of them by kind 25 — through the
   same function that certifies a victim, never by a separate judgment — and
   reseals the term as its own with kind 25 as the previous owner's proof. Its
   own key is derived as a claimant's is. This boot's own identity is never
   excluded this way (the peer's fence says nothing about it): that is the
   resume's case. Because the owner's startup fence left the peer's disk
   Outdated, the term can be continued only where the data is current: by the
   owner host's next boot, or by the peer once it has been released and
   resynced from an owner whose mount failed while its host stayed up.
8. **`net` only.** COMPARE AND WRITE cannot be atomic across two replicas without
   the lock above, and the disk lock manager would ride the emulated swap for
   every lock. DRBD allows exactly two primaries, so the configuration is
   `2/net/mesh/drbd` and nothing larger.

Coherency reads need nothing special: a device with no SCSI device underneath
takes the plain bio read, and under protocol C a read of the local replica after
a completed peer write is coherent. What must hold instead is that MXFS never
reaches a DRBD device's backing disk directly: SCSI passthrough resolves a
stacked device by content only when it is device-mapper (multipath), and only
to a disk that is a direct slave of that device, because DRBD's LBA 0 equals
its backing disk's and a passthrough sent there would write one replica only.
The slave test is what keeps a device-mapper volume stacked on DRBD (or on any
other layer) from resolving to the disk underneath, and it is applied to the
resolver's cache too: a cache entry is keyed on a device number, and a number
freed by a removed device is handed to the next one created.

The rig builds and exercises the whole attachment with `scripts/drbd_rig.sh`:
each node of a rig group gets a pool LUN of its own as its local disk, DRBD
comes up dual-primary with the rig's fence authority (`tools/rig_fence_virsh.sh`,
the hypervisor fence for test VMs), and MXFS, the suite, fio and the death,
fence and split tests run on `/dev/drbd0`. Because it has no pool LUN to share
and no SCSI fence, it is verified by that rig and not by the suite's ordinary
board columns: its results go to a board of their own
(`tests/evidence/drbd_rig/`), and a release that claims `2/net/mesh/drbd` runs
`scripts/drbd_rig.sh` on the build being released. (In the tooling the
attachment carries a flag named `trial` and is parsed only for a caller that
sets `MXFS_TRIAL=1`; that flag selects the separate rig and board, and says
nothing about release status.)

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
  exactly one device, which is why dm-multipath works).  DRBD dual-primary is
  not refused: it is its own attachment, with its own fencing (above).
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
