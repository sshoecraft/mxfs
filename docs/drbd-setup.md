# MXFS on two hosts with DRBD dual-primary

Two hosts, each with a local disk, and no shared storage: DRBD keeps the two
disks identical and MXFS runs on top of both at once. This is the `2/net/mesh/drbd`
configuration. It works with exactly two hosts and nothing else: no SAN, no
third machine, no IPMI.

Every command below is run as root. "Both nodes" means run it on each host;
"node A" means only one of them. The examples use two Proxmox VE hosts named
`pve1` (192.168.1.80) and `pve2` (192.168.1.81).

## 1. Install

On both nodes, from the same version of the source:

```
apt install drbd-utils
git clone https://github.com/sshoecraft/mxfs && cd mxfs
make && make install
```

`make install` installs the module, `mkfs.mxfs` and the other tools, the DRBD
fence handler and its built-in fence authority, and two systemd units. If it
refuses because an older MXFS package or DKMS module is installed, remove that
first with the command it prints. If it warns that the loaded module is not the
one just installed, unmount any MXFS filesystem and run
`rmmod mxfs && modprobe mxfs`.

Both nodes must run the same MXFS version. Check with
`cat /sys/module/mxfs/srcversion` on each.

## 2. A backing device on each node

DRBD needs a block device of the same size on each node: a partition, a disk or
an LVM logical volume. On Proxmox the `pve` volume group's thin pool works:

```
lvcreate -V 40G -T pve/data -n mxfs        # both nodes
```

Do not use a loop device on a file. It is not recreated at boot, so the
resource cannot come back after a restart.

## 3. The DRBD resource

`/etc/drbd.d/mxfs.res`, identical on both nodes. The `on` names must be the
hosts' names exactly as `hostname` prints them.

```
resource mxfs {
    net {
        protocol C;
        allow-two-primaries yes;
        after-sb-0pri disconnect;
        after-sb-1pri disconnect;
        after-sb-2pri disconnect;
    }
    disk {
        fencing resource-and-stonith;
        c-fill-target 4M;       # DRBD 8.4's default keeps ~50 KB in flight
        c-max-rate    110M;     # and resyncs at ~9 MB/s on gigabit; this
        c-min-rate    20M;      # runs near link speed (set to your link)
    }
    handlers {
        fence-peer "/usr/sbin/mxfs-drbd-fence-peer";
    }
    on pve1 {
        device    /dev/drbd0 minor 0;
        disk      /dev/pve/mxfs;
        address   192.168.1.80:7788;
        meta-disk internal;
    }
    on pve2 {
        device    /dev/drbd0 minor 0;
        disk      /dev/pve/mxfs;
        address   192.168.1.81:7788;
        meta-disk internal;
    }
}
```

MXFS refuses to mount unless `protocol`, `allow-two-primaries`, every
`after-sb-*`, `fencing` and `fence-peer` are exactly as above. Do not add
`become-primary-on`: the `mxfs-drbd@` unit promotes the node only once it is
safe.

## 4. First synchronisation

```
drbdadm create-md mxfs && drbdadm up mxfs        # both nodes
drbdadm primary --force mxfs                     # node A only, this one time
```

Wait until `cat /proc/drbd` shows `ds:UpToDate/UpToDate` on both nodes, then:

```
drbdadm primary mxfs                             # node B
```

## 5. Format, once

```
mkfs.mxfs /dev/drbd0                             # node A only
```

A device that already holds a filesystem is refused; add `-f` to overwrite it.

## 6. Mount at boot

On both nodes:

```
echo MOUNTPOINT=/mnt/shared > /etc/mxfs/drbd-mxfs.conf
systemctl enable --now mxfs-drbd@mxfs
```

`mxfs-drbd@mxfs` brings the resource up, waits until DRBD is Connected with both
disks UpToDate, promotes the node, and mounts. At shutdown it unmounts and
steps down, so the other node carries on. Check it with
`systemctl status mxfs-drbd@mxfs`, and see why MXFS admitted or refused the
mount with `dmesg | grep P-DRBD-ARM`.

On Proxmox, add the mount as shared directory storage once (it is cluster-wide):

```
pvesm add dir shared --path /mnt/shared --shared 1 --is_mountpoint yes \
      --content images,iso,vztmpl,backup,snippets
```

## 7. What happens when a node is lost

Fencing is on by default and needs no configuration. The node with the lower
DRBD address (here `pve1`) is participant 0; the other is participant 1.

- **pve2 dies, or loses its network.** pve1 isolates pve2 from itself (the
  DRBD port and MXFS's ports, nothing else), takes DRBD StandAlone, and carries
  on within seconds. MXFS replays pve2's journal. When pve2 is back and
  reports MXFS unmounted, pve1 releases it, DRBD resyncs pve2 from pve1, and
  `mxfs-drbd@mxfs` mounts it again.
- **The replication link breaks with both nodes alive.** The same: pve1
  carries on, and pve2 freezes, logs why, and restarts itself, then rejoins as
  above.
- **pve1 is shut down or restarted on purpose.** Its unit unmounts and steps
  down first; pve2 sees that over ssh and carries on.
- **pve1 dies.** pve2 cannot tell a dead pve1 from a cut cable, so it does not
  take over. It freezes, logs exactly this, restarts, and waits. Bring pve1
  back. No two-node system without a third vote or fence hardware can do
  better: Proxmox HA and corosync's tie-breaker behave the same way.
- **Both nodes crash at once.** If they come back connected, MXFS needs proof
  the old mounts are gone and the built-in fencing cannot give it, so the
  mount is refused with that reason. Configure a node fence (below) for this
  case to recover automatically.

The release check uses ssh between the nodes as root. A Proxmox cluster
already has that trust; on other systems set up root keys both ways, with the
peer's host key known under its DRBD host name.

To use a real node fence instead (IPMI, a PDU, a hypervisor), write
`/etc/mxfs/drbd-fence.conf` with an `agent=exec` or `agent=ssh` authority; the
contract it must keep is in `docs/attachment-methods.md` ("The fence authority
is the site's").

## Never

- Never run `drbdadm primary --force`, `drbdadm resume-io`, or `drbdadm outdate`
  outside step 4, and never mount `/dev/drbd0` by hand. Each of these can put
  two writers on two copies of the data.
- Never restore either node from a VM snapshot or saved memory.
- Never edit the resource on one node only.
