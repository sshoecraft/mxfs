# Fencing methods

Before a survivor replays a dead node's journal slice, it has to know that node
can no longer write. That guarantee is fencing, and recovery depends on it: a
replay while the victim still writes interleaves two writers on metadata that
only one of them holds, which is corruption.

Today MXFS has one fencing method, hard-wired: SCSI persistent reservations.
Each node registers a key on the shared LUN at mount. To fence, a survivor
issues PREEMPT AND ABORT against the victim's key, so the target itself rejects
the victim's I/O (`dlm/scsipr.c`). The mount checks that the device can do this
and refuses it otherwise (`docs/attachment-methods.md`).

That shape ties MXFS to storage that implements SCSI reservations and forwards
them intact. An attachment like DRBD dual-primary, a platform whose storage
cannot fence, or NVMe needs a different method. This document is the design for
making fencing pluggable.

## What a method has to do

Every method answers the same three questions, and the recovery path asks them
in this order:

1. **Arm, at mount.** Prove this node can be fenced by this method, or refuse the
   mount. This is what the reservation admission check does today. A node that
   cannot be fenced must never join, because nobody could recover after it dies.
2. **Fence, at a death.** Cut the victim off.
3. **Evidence, before replay.** Prove the victim can no longer write. Recovery
   waits for the evidence, never for the fence call returning. A fence that was
   issued but not confirmed is not a fence.

The recovery and replay path already consumes evidence from the reservation
method: the retirement witness and the certificate the survivor publishes. A new
method plugs in underneath that path and must produce evidence of the same
strength. It must not relax what recovery waits for.

## Methods

| method | cuts off | evidence | where it applies |
|---|---|---|---|
| `scsipr` | the victim's path to the target | the target rejects the victim's I/O (PREEMPT AND ABORT completed) | iSCSI, FC, SAS; `direct`, `mpath`, `pass` |
| `drbd` | the victim's replica | the survivor holds the only up-to-date copy; the victim's disk is outdated and cannot rejoin as primary without resync | DRBD dual-primary |
| `power` | the whole node | the BMC or PDU confirms the node is off (IPMI, Redfish) | bare metal |
| `hypervisor` | the VM | the hypervisor confirms the domain is destroyed (libvirt, the Proxmox API, vSphere) | virtual machines, the rig included |
| `cloud` | the instance, or its disk attachment | the provider's API confirms the detach or stop | cloud shared disks |
| `nvmepr` | the victim's NVMe path | NVMe reservation preempt-and-abort completed | NVMe-oF, once MXFS supports NVMe |

`scsipr` is today's code, moved behind the interface unchanged.

### Methods combine

A configuration may need more than one method, and recovery waits for evidence
from each. DRBD dual-primary is the case that forces it:

- `drbd` alone keeps the victim's writes off the survivor's replica, but the
  victim keeps writing to its own local disk and may keep serving whatever runs
  on it;
- in a split of the replication link, each side sees the other stop and both
  believe they survived;
- so `drbd` is combined with a node fence (`power` or `hypervisor`) and a
  tiebreaker: redundant replication links with STONITH, or DRBD 9's quorum with a
  diskless third node. DRBD's own `fencing resource-and-stonith` freezes I/O when
  the link drops until a fence-peer handler confirms the peer is down, which is
  the hook the node fence plugs into.

## Where each method runs

- **In the kernel**: `scsipr` and `drbd`. Both act on a block device the module
  already holds.
- **In userspace**: `power`, `hypervisor` and `cloud`. A kernel module cannot
  sensibly speak IPMI, a hypervisor API or a cloud API. The kernel asks a
  userspace helper to fence and waits for its answer, the way GFS2's lock
  manager uses `dlm_controld`. The helper can reuse the ClusterLabs fence agents
  that already exist for most platforms (`fence_ipmilan`, `fence_virsh`,
  `fence_pve`, `fence_aws`, and others) rather than reimplementing them.

The kernel-side interface lives in a `fencing/` subsystem. Like `dlm/`, it has to
build user-mode, with no direct kernel API outside `pal/`: everything
OS-specific routes through `mxfs_pal_*`.

## Invariants

- A node that no configured method can fence does not mount.
- Recovery replays a slice only after every configured method has produced
  evidence for that victim.
- A method's evidence names the victim by the same identity the recovery path
  uses. A power-off confirmation for the wrong node is not evidence.
- Unfencing (a victim coming back) goes through the same method, and a fenced
  node rejoins only by remounting.

## Open questions

- **A design consult comes before implementation.** This changes recovery and
  fencing semantics, which are hard to reverse once shipped.
- **Evidence strength across methods.** `scsipr` proves the storage rejects the
  victim, while `power` proves only that the node is off. Is "off" as strong as
  "rejected at the target" for every recovery path, including a node that was
  already partitioned with I/O in flight inside the target?
- **Which methods come first.** `hypervisor` can be exercised on the rig with
  libvirt. `drbd` needs it, plus the coherency read path that does not use SCSI
  commands (`docs/attachment-methods.md`).
- **How a configuration names its methods.** The fence methods are implied by the
  attachment today. They become part of the configuration only once one
  attachment can be fenced more than one way.
