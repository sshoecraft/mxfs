# MXFS Peer Discovery

## Overview

MXFS nodes discover each other automatically using UDP announcements. Each node
periodically broadcasts its presence (node UUID, volume UUID, TCP port) and
listens for announcements from other nodes. When a peer is detected with a
matching volume UUID, a TCP DLM connection is established.

Discovery runs in two threads per mount:
- **Sender** — sends announcements at startup (burst) and periodically thereafter
- **Receiver** — receives announcements, fires peer callback on new peers

A startup burst sends 10 rapid announcements at 500ms intervals, then settles
to one announcement every 2000ms. The burst ensures fast initial discovery even
if some UDP packets are lost.

---

## Discovery Modes

### Multicast (default)

Sends announcements to multicast group `239.66.83.1`, UDP port 7601. All nodes
on the network that have joined the group receive the packet. Only nodes
mounting the same XFS volume (matching volume UUID) respond.

This is the correct mode for production. It is network-aware: with IGMP
snooping on managed switches, traffic is delivered only to interested ports.
It does not spam the entire subnet.

```
mount -t mxfs /dev/sdb /mnt/shared
```

### Additional peers (`-o peer=`)

Adds addresses to multicast discovery rather than replacing it.  Multicast
runs as usual, and every datagram that goes to the group — discovery
announcements, lease heartbeats, and on the CAW transport the BAST/grant
nudges — is also sent by unicast to each listed address.  Nothing is dropped:
senders are admitted exactly as under multicast.

```
mount -t mxfs -o peer=10.0.2.7 /dev/sdb /mnt/shared
mount -t mxfs -o peer=10.0.2.7,peer=10.0.3.9 /dev/sdb /mnt/shared
```

- One address per option; repeat the option for more.  Multicast, broadcast
  and `0.0.0.0` are refused; duplicates collapse.
- This is for a node the multicast group cannot reach, such as one on another
  network.  Neither side hears the other's multicast, so the off-network node
  must list every member, and every member must list it.  Members on the same
  network keep finding each other by multicast.
- With two nodes, each simply lists the other.

### Static peer list (`-o peers=`)

Lists the cluster's addresses explicitly.  Every datagram that would have
gone to the multicast group — discovery announcements, lease heartbeats, and
on the CAW transport the BAST/grant nudges — is sent by unicast to each listed
address instead; no socket joins the group, and no broadcast is sent.  A
datagram, or an inbound DLM TCP connection, from an address that is not on the
list is dropped.  The packets themselves are unchanged, so peer registration,
the lease state machine and the TCP mesh behave exactly as under multicast.

```
mount -t mxfs -o peers=192.168.1.10/192.168.1.11/192.168.1.12 /dev/sdb /mnt/shared
```

- Addresses are IPv4, separated by `/` (a mount option string is itself split
  on `,`, so a comma cannot separate them).  Multicast, broadcast and
  `0.0.0.0` are refused; duplicates collapse; at most 64 addresses.
- The list may include the node's own address, so every node can carry the
  identical option.
- Every node of a cluster must use the same list, or none.  A node with a
  list neither sends to nor listens on the group, so a node without one cannot
  be heard by it — the same as a network partition, and handled as one.  The
  node without a list logs `P-PEERS-MISMATCH` once when it hears a listed node
  (the announcement carries a flag saying so).
- Read at mount; a remount does not change it.
- A repeated `peers=` adds to the list, and `peer=` addresses given with it
  join the same list, which stays exclusive.

This is the mode for deployments that want fully predictable network traffic:
no multicast, no broadcast, only unicast between a defined set of addresses.

### Broadcast, custom groups and ports — not mount options

The discovery code can send to the broadcast address or another group, and
the TCP and UDP ports are compile-time defaults (`include/mxfs/mxfs_ports.h`),
but none of `broadcast`, `multicast=`, `discovery_port=` or `port=` is a mount
option: the only parser that knew them belongs to the retired `dlm/mount.c`,
which is not built into `mxfs.ko`.  The live mount always uses multicast
`239.66.83.1` or, with `peers=`, unicast.  An environment that cannot pass
multicast (the nested-virtualisation cases below) should use `peers=`.

---

## Mount Options

| Option | Default | Description |
|---|---|---|
| `peer=A` (repeatable) | none | Also unicast to this IPv4 address, alongside multicast; nobody is dropped |
| `peers=A/B/...` | none (multicast) | Unicast to exactly these IPv4 addresses; drop everyone else |
| `cluster=NAME` | none | Must match the cluster name recorded on the filesystem (`mkfs.mxfs -c`, `mxfs_admin -c`); a mismatch in either direction refuses the mount before any cluster traffic |

---

## Environment Guide

The multicast/unicast decision depends entirely on the network path between nodes.

| Environment | Mode | Notes |
|---|---|---|
| Physical servers, managed switch (UniFi, Cisco, etc.) | Multicast | IGMP snooping handles group membership correctly |
| Physical servers, unmanaged switch | Multicast | Switch floods multicast; works fine |
| VirtualBox on Linux host | Multicast | VMs connect directly to Linux bridge; bridge floods multicast |
| libvirt/QEMU with Linux bridge | Multicast | Same as VirtualBox |
| Proxmox on physical hardware | Multicast | Proxmox Linux bridge + managed switch = correct |
| VMware Workstation VMs (direct) | Multicast (unverified) | Needs testing |
| **Nested ESXi on VMware Workstation** | **`peers=`** | See below |
| Proxmox nested on VMware Workstation | `peers=` | Same issue as nested ESXi |
| Any network where policy forbids multicast | `peers=` | Unicast only, to the listed addresses |

### Nested ESXi Requirement

When ESXi runs as a virtual machine inside VMware Workstation, multicast
**does not work**; mount every node with the same `-o peers=` list.

The failure is caused by VMware Workstation's internal vmnet switch, which does
not forward multicast frames between guest VMs. The packet path is:

```
test VM → ESXi vSwitch → ESXi VM's vmnet NIC → VMware vmnet switch → ESXi VM's vmnet NIC → ESXi vSwitch → test VM
```

VMware's vmnet switch silently drops multicast at the second step.  Unicast
frames are forwarded normally — the DLM's TCP traffic already crosses it — so
a static peer list carries discovery and the lease heartbeats over the same
path.

This behavior is specific to nested virtualization — VMware's vmnet switch is
the offending layer. Standard vSphere on physical hardware does not have this
problem. VirtualBox, libvirt, and Proxmox do not have this problem because they
use Linux bridging, which floods unknown multicast.

Switching from VMware standard vSwitch (vSS) to Distributed Virtual Switch
(vDS) on the inner ESXi does not fix this, because the vmnet layer is below the
ESXi layer and remains in the path regardless.

### Why multicast is the default and broadcast is not offered

Multicast needs no configuration and, with IGMP snooping, reaches only the
ports that joined the group.  Broadcast (`255.255.255.255`) would reach every
host on the subnet, not just MXFS nodes; in corporate environments that
generates unexpected traffic, triggers network monitoring alerts, and can get
the application permanently blocked by the network team.  Where multicast is
unavailable or unwanted, the static peer list gives the same result with
unicast only.

---

## Unicast Traffic Volume

With `peers=`, each datagram MXFS would multicast once is sent once per listed
address instead: a node sends one ~100-byte discovery announcement per address
every 2000 ms (after a 10-packet, 500 ms-interval burst at mount), plus one
lease heartbeat per address per renew interval.  For a 32-node cluster that is
32 announcements every 2 s from each node — still small, and addressed only to
cluster members.

---

## Cluster Name

A filesystem may record the cluster it belongs to (`mkfs.mxfs -c NAME`, or
later `mxfs_admin -c NAME`; `mxfs_admin -c ""` clears it).  A mount of a named
filesystem must pass `-o cluster=NAME` with the same name, and a mount that
passes `cluster=` must find that name recorded; either mismatch refuses the
mount before any heartbeat, network traffic or write.

The point is the node configured for a different cluster: it would hear none
of this cluster's peers, conclude it is alone, and write the shared disk.  The
name is an agreement check, not a secret — the same role as OCFS2's on-disk
cluster name and GFS2's lock table name.  It is an incompatible envelope flag,
so a kernel that does not check it refuses the volume outright.  Renaming is
offline: `mxfs_admin -c` refuses while any node can write the device.
