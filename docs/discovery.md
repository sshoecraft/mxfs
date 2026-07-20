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

### Broadcast (`-o broadcast`)

Sends announcements to `255.255.255.255`, UDP port 7601. Every host on the
local subnet receives the packet regardless of group membership. Required in
environments where the network infrastructure does not forward multicast between
nodes.

```
mount -t mxfs -o broadcast /dev/sdb /mnt/shared
```

**Use broadcast only when multicast does not work in your environment.** See
the environment guide below.

---

## Mount Options

| Option | Default | Description |
|---|---|---|
| `broadcast` | off | Use broadcast instead of multicast for discovery |
| `multicast=ADDR` | `239.66.83.1` | Override the multicast group address |
| `discovery_port=N` | `7601` | UDP port for discovery packets |
| `port=N` | `7600` | TCP port for DLM connections |

### Examples

Default (multicast, standard ports):
```
mount -t mxfs /dev/sdb /mnt/shared
```

Broadcast mode (nested ESXi, see below):
```
mount -t mxfs -o broadcast /dev/sdb /mnt/shared
```

Custom multicast group and ports:
```
mount -t mxfs -o multicast=239.100.1.1,discovery_port=9001,port=9000 /dev/sdb /mnt/shared
```

All nodes in a cluster must use the same discovery mode and ports.

---

## Environment Guide

The multicast/broadcast decision depends entirely on the network path between nodes.

| Environment | Mode | Notes |
|---|---|---|
| Physical servers, managed switch (UniFi, Cisco, etc.) | Multicast | IGMP snooping handles group membership correctly |
| Physical servers, unmanaged switch | Multicast | Switch floods multicast; works fine |
| VirtualBox on Linux host | Multicast | VMs connect directly to Linux bridge; bridge floods multicast |
| libvirt/QEMU with Linux bridge | Multicast | Same as VirtualBox |
| Proxmox on physical hardware | Multicast | Proxmox Linux bridge + managed switch = correct |
| VMware Workstation VMs (direct) | Multicast (unverified) | Needs testing |
| **Nested ESXi on VMware Workstation** | **Broadcast** | See below |
| Proxmox nested on VMware Workstation | Broadcast | Same issue as nested ESXi |

### Nested ESXi Requirement

When ESXi runs as a virtual machine inside VMware Workstation, multicast
**does not work** and `-o broadcast` is required on every node.

The failure is caused by VMware Workstation's internal vmnet switch, which does
not forward multicast frames between guest VMs. The packet path is:

```
test VM → ESXi vSwitch → ESXi VM's vmnet NIC → VMware vmnet switch → ESXi VM's vmnet NIC → ESXi vSwitch → test VM
```

VMware's vmnet switch silently drops multicast at the second step. Broadcast
frames (destination MAC `ff:ff:ff:ff:ff:ff`) are unconditionally flooded and
pass through correctly.

This behavior is specific to nested virtualization — VMware's vmnet switch is
the offending layer. Standard vSphere on physical hardware does not have this
problem. VirtualBox, libvirt, and Proxmox do not have this problem because they
use Linux bridging, which floods unknown multicast.

Switching from VMware standard vSwitch (vSS) to Distributed Virtual Switch
(vDS) on the inner ESXi does not fix this, because the vmnet layer is below the
ESXi layer and remains in the path regardless.

### Why Broadcast Is Not the Default

Sending UDP broadcast (`255.255.255.255`) continuously reaches every host on
the subnet, not just MXFS nodes. In corporate environments this generates
unexpected traffic, triggers network monitoring alerts, and can result in the
application being permanently blocked by the network team — even after the
behavior is corrected.

Multicast with IGMP snooping is the correct solution for production networks.
Broadcast is provided as an explicit opt-in for lab and development environments
where multicast infrastructure is absent.

---

## Broadcast Traffic Volume

In broadcast mode, each mounted node sends one 100-byte UDP announcement every
2000ms. For a 32-node cluster that is 32 × 50 bytes/sec = 1600 bytes/sec of
broadcast traffic on the subnet — negligible at any reasonable scale. The
startup burst (10 packets per node at 500ms intervals) generates a brief spike
of ~5000 bytes per node over 5 seconds at mount time, then drops to steady
state.

---

## Static Peer List (Planned)

A future `peers=` mount option will allow explicit peer addresses, eliminating
all discovery traffic:

```
mount -t mxfs -o peers=192.168.1.10,192.168.1.11,192.168.1.12 /dev/sdb /mnt/shared
```

This is the preferred mode for corporate deployments where administrators want
fully auditable, predictable network traffic. No UDP, no multicast, no
broadcast — pure unicast TCP between a defined set of addresses. Not yet
implemented.
