# MXFS on two hosts with DRBD dual-primary

`2/net/mesh/drbd` is released from 0.90.107 (see the top of the README):
verified on two physical Proxmox VE 9 hosts with DRBD 8.4.11, installed exactly
as below.

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
apt install drbd-utils git build-essential proxmox-headers-$(uname -r)
git clone --branch v0.90.107 https://github.com/sshoecraft/mxfs && cd mxfs
make && make install
```

`--branch` names the release; the repository's default branch is the
development tree and is not a release.  To move to a later release, `git fetch
--tags && git checkout v<version>` in the clone, then `make && make install`
again on both nodes.

A Proxmox VE host ships with none of `git`, a compiler or the kernel headers.
On Debian or Ubuntu the headers package is `linux-headers-$(uname -r)`
instead. The module is built for the kernel that is running, so after a
kernel update and reboot, run `make && make install` again (with that kernel's
headers installed).

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
        ping-int 3;             # notice a dead peer within ~7 s, not 21 s
    }
    disk {
        fencing resource-and-stonith;
        c-fill-target 4M;       # DRBD 8.4's default keeps ~50 KB in flight
        c-max-rate    110M;     # and resyncs at ~9 MB/s on gigabit; this
        c-min-rate    20M;      # lets it run at the link's speed or the
                                # slower disk's (set c-max-rate to your link)
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

`ping-int` decides how long the surviving node's writes stop when its peer
dies. DRBD notices a dead peer by a keep-alive that goes unanswered, and while
writes are in flight that takes up to twice `ping-int` plus `ping-timeout`
(0.5 s); every write on the survivor waits for it. With DRBD's default of 10 s
the survivor's VMs stopped for 21 s in our tests; with 3 s, for 7 s. A
keep-alive is sent only when the link is otherwise idle, so the shorter
interval adds no traffic under load. A change to `ping-int` on a running pair
takes effect when the connection is next made.

## 4. First synchronisation

```
drbdadm create-md mxfs && drbdadm up mxfs        # both nodes
drbdadm primary --force mxfs                     # node A only, this one time
```

Wait until `cat /proc/drbd` shows `ds:UpToDate/UpToDate` on both nodes. The
first sync copies the whole device, so it takes as long as the slower of the
link and the receiving disk needs: on `pve1`/`pve2` (gigabit, older SATA SSDs
under a thin volume) 40 GiB took 22 minutes, at 31 MB/s. Then:

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
disks UpToDate, promotes the node, and mounts; pve1, if it was running alone,
gives pve2 30 s and then mounts without it (section 7). At shutdown it unmounts and
steps down, so the other node carries on. Check it with
`systemctl status mxfs-drbd@mxfs`, and see why MXFS admitted or refused the
mount with `dmesg | grep P-DRBD-ARM`.

Proxmox starts the guests marked "start at boot" and its HA services only once
the unit reports the filesystem mounted, so a VM whose disk is on
`/mnt/shared` does not fail to start because the mount came late. If the
mount cannot happen within `GUEST_WAIT` seconds of the unit starting (default
300; the peer is down or still booting), guests on local storage start
without waiting, and the unit starts the remaining "start at boot" guests
itself once it has mounted. Set another bound with a `GUEST_WAIT=<seconds>`
line in `/etc/mxfs/drbd-mxfs.conf`.

On Proxmox, add the mount as shared directory storage once (it is cluster-wide):

```
pvesm add dir shared --path /mnt/shared --shared 1 --is_mountpoint yes \
      --content images,iso,vztmpl,backup,snippets
```

With `--shared 1`, a live migration (`qm migrate <vmid> <node> --online`)
moves only the guest's memory: both hosts open the same disk image, the
source until the switchover, the target from then on. Give a guest that
must migrate a CPU type both hosts can run. `host` migrates only between
identical CPUs, and Proxmox's default `x86-64-v2-AES` needs AES-NI on both.
With an older CPU on one host (e.g. a Nehalem Xeon W3520, which has no
AES-NI), use `x86-64-v2`:

```
qm set <vmid> --cpu x86-64-v2
```

`tests/pve_live_migrate.sh` checks a pair end to end: a guest writing and
fsyncing throughout is migrated back and forth, and after every move each
file it wrote is read back from disk on the new host and checked.

## 7. What happens when a node is lost

Fencing is on by default and needs no configuration. The node with the lower
DRBD address (here `pve1`) is participant 0; the other is participant 1.

- **pve2 dies, or loses its network.** pve1's writes stop until DRBD notices
  (up to ~7 s with the `ping-int` above). Then pve1 isolates pve2 from itself
  (the DRBD port and MXFS's ports, nothing else), takes DRBD StandAlone, and
  carries on, and MXFS replays pve2's journal; a VM on pve1 that needs a file
  pve2 was writing waits for that replay too, ~17 s after pve2's death in our
  tests. When pve2 is back and reports MXFS unmounted, pve1 releases it, DRBD
  resyncs pve2 from pve1, and `mxfs-drbd@mxfs` mounts it again.
  pve1's fence handler resumes pve1's frozen I/O itself (`drbdadm
  resume-io`) once pve2 is isolated, before it answers DRBD. Left to resume
  it on the answer, the in-kernel DRBD 8.4 driver writes its metadata while
  holding an RCU read lock, which the kernel reports as a WARNING ("Voluntary
  context switch within RCU read-side critical section", from
  `drbd_uuid_new_current`); `resume-io` does the same work without that lock.
  The driver bug itself is fixed by the patch in `upstream/linux/` in this
  repository.
- **The replication link breaks with both nodes alive.** The same: pve1
  carries on, and pve2 freezes, logs why, and restarts itself, then rejoins as
  above.
- **pve1 is shut down or restarted on purpose.** Its unit unmounts, steps
  down and takes DRBD down before the network stops, so DRBD disconnects
  gracefully and pve2 carries on.
- **pve1 dies.** pve2 cannot tell a dead pve1 from a cut cable, so it does not
  take over. It freezes, logs exactly this, restarts, and waits. Bring pve1
  back. No two-node system without a third vote or fence hardware can do
  better: Proxmox HA and corosync's tie-breaker behave the same way.
- **pve1 restarts while pve2 is still down.** DRBD records that pve1's copy is
  the newer one and will not promote pve2 until it has resynced from it. So
  pve1 gives pve2 30 s to connect, then isolates it as above and mounts alone,
  about two and a half minutes after the boot in our tests. pve2 rejoins when
  it is back.
- **pve2 restarts while pve1 is down** (for example, pve2 was running alone
  after pve1 was shut down on purpose). pve2 waits for pve1 and does not mount
  alone. DRBD's record of which copy is newer can be left stale on disk by a
  crash, and only pve1 may ever take the pair alone, so pve2 cannot trust that
  record. Bring pve1 back.
- **A node's mount shuts down while the node stays up.** MXFS withdraws a
  node that lost its standing: no heartbeat of its own landed within its
  60 s authority lease, because its writes to the shared device stalled for
  that long. From then on every access to `/mnt/shared` on that node fails
  with an I/O error. A heartbeat that is merely slow costs nothing: every
  write waits for both disks, so one host's overloaded disk slows the other's
  writes too, and a beat may take up to about 29 s. `mxfs-drbd-guard`
  sees this within seconds (`/sys/fs/mxfs/drbd0/shutdown` reads 1) and
  rejoins the node without restarting it. It kills every process holding the
  mount at once, the VMs whose disks are on it among them: they can no longer
  read or write them, and a `qm stop` would pull their power too, only one VM
  at a time. Proxmox cleans each one up as after a guest crash. Then it
  unmounts the mount and restarts `mxfs-drbd@mxfs`, which mounts it again as
  after a restart of that node, and starts the on-boot guests. The node stays
  Secondary until the other node has replayed its old mount's journal (it asks
  over ssh; at most 3 min). Being Secondary on a connected link is how the
  other node knows the old mount is gone, so a node that promoted first would
  hold up that replay, and with it its own mount. Other VMs it killed stay
  stopped, and
  the journal names each one. It rejoins at most three times an hour. A mount
  that keeps shutting down stays down until you restart `mxfs-drbd@mxfs`, and
  the kernel log says why each time. A mount that cannot be released, because
  something the guard cannot stop holds it, restarts the host as in the cases
  above.
- **A host never promotes itself while the other is unreachable** unless it
  holds an exclusion of the other. A `drbdadm primary` run then is refused.
- **Both nodes crash or lose power at once.** When they come back, DRBD
  reconnects and resyncs. Then pve2 waits, Secondary, while pve1 mounts: pve2
  being Secondary on a connected link is DRBD's own proof that no old mount is
  left on it, and pve1 replays both nodes' journals. pve2 mounts once pve1 has
  (it asks pve1 over ssh), about two and a half minutes after the boot in our
  tests. If one of them does not come back, the other waits for it, unmounted:
  at boot neither can tell a dead peer from a cut cable.

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
