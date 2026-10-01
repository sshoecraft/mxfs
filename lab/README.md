# MXFS Test Lab

The **lab** = the libvirt/QEMU VM fleet on clyde + the shared-LUN rigs the
clustered filesystem runs on. This directory is the **entry point / map**: the
fleet *definition* (`vms.md`) plus this overview. The operational scripts stay in
`scripts/` (they cross-reference each other and are called by `run.sh` /
`ladder_rung.sh` / the net2 gates — moving them would break the web) and the
deep infra docs stay in `docs/`; this README points at both.

## Why `lab/` and not `tests/`
`tests/` holds test **cases** — repros, probes, `criteria/`, `suite/`. The lab is
the **substrate** those run on. Keeping them separate stops the fleet definition
from drowning in the ~150-script repro pile.

## The platforms to test on
**`vms.md`** lists, for every platform in `data/platforms.json`, the osimager
spec that builds its nodes and what to do to them after the build. Everything
below is the part that is the same for every platform.

### Building a platform's verification set
A release for N nodes is verified on N nodes of every platform it claims, and
on nothing smaller: two nodes for the 2-node release, four for the 4-node
release, eight for the 8-node one (`NODES=8 tests/full_verify.sh` refuses a
set with fewer). The steps are per node; a set is as many of them as the
release claims. A node of the development rig is never also in a platform
set: a node logged in to two targets orders its disks by session, and the
rig's prep has formed a cluster short of that node because of it.
1. **Install osimager** — `pip install osimager` (it drives HashiCorp Packer,
   which must be installed too). Run `mkosimage` with no arguments once: it
   says what to set up. Its documentation covers locations, credentials and
   specs: <https://sshoecraft.github.io/osimager>. A *location* is your
   network — bridge, addressing, DNS — and is yours to define.
2. **Build each node** from the row's spec:
   ```
   mkosimage -D libvirt_uri=qemu:///system qemu/<location>/<spec> <name> <ip>
   ```
   osimager's QEMU build registers the finished VM with libvirt. Name the URI:
   without it, a build run as an ordinary user lands in `qemu:///session`,
   where nothing in this tree looks. Then run
   `scripts/vm_reclaim_disk.sh <name>`: osimager defines the disk without
   discard, and a qcow2 without discard never gives back what the guest
   frees. The rig's busiest nodes grew to their full 26 GB virtual disks while
   each guest held about 5 GB. The script adds `discard='unmap'`, cold-starts
   the VM and trims it. If a build left the guest running inside Packer's
   QEMU instead of libvirt, `scripts/libvirt_adopt_qemu_guest.sh` moves it
   under libvirt on the same disk, MAC and PCI layout. Once one node of a
   platform is built and finished, `scripts/lab_clone_node.sh` clones it into
   the set's further nodes (disk, hostname, address, iSCSI initiator name);
   an SELinux-enforcing clone is relabeled afterwards, because a file the host
   rewrote is a new unlabeled inode.
3. **Do the row's "after the build" steps**, and boot the kernel
   `data/platforms.json` claims for the platform. Then on every node:
   - headers for the running kernel (DKMS compiles the module against them)
   - an iSCSI initiator and `sg3_utils`
   - root SSH with the password in your secrets store (below)
4. **Give the set a shared LUN of its own.** An iSCSI LUN that supports SCSI
   persistent reservations (and COMPARE AND WRITE, for the CAW transport),
   reachable from every node of the set. MXFS fences a dead node through the
   reservation, so a target without one cannot verify a release. The harness
   logs each node in to it. One LUN per platform lets the platforms verify in
   parallel without one set's format touching another's;
   `scripts/scst_platform_targets.sh setup` builds one SCST target per
   platform on the dev host and writes each platform's own lab file.
5. **Name the set in your lab file** (next section).
6. **Verify:** `tests/packaged_round.sh <platform>` installs the release's
   package on every node of the set and runs the checks the platform's
   `verify_tests` lists; `tests/tcp_peer_freeze_death.sh PREP=<platform>`
   freezes the set's second node and measures the first;
   `tools/platforms.py verify` records the result.

### Your lab file → `~/.config/mxfslab/lab`
Which nodes verify each platform, their addresses and the shared LUN are this
site's alone, so they are never in the tree. The harness reads them from
`~/.config/mxfslab/lab` (override with `$MXFS_LAB`) through
`tools/mxfs_lab.sh`, whose header is the format reference:
```
storage portal=<ip> target=<iqn> lun=/dev/disk/by-id/<id> also=<nodes>
nodes ubuntu2404=<n1>,<n2>,<n3>,<n4> rhel9=<n1>,<n2>,<n3>,<n4>
pair ubuntu2404=<nodeA>,<nodeB> rhel9=<nodeA>,<nodeB>
addr <node>=<ipv4>
qemu monitor_dir=<dir>
paths image=<file> delay_image=<file> vmdir=<dir> qemu_root=<dir>
```
`nodes` is a platform's verification set in the order the harnesses use it
(the first node formats and checks); `pair` is the two-node form of the same
line, for a lab that verifies only two-node releases, and `nodes` wins when
both are present. With one lab file per platform (`~/.config/mxfslab/lab.<platform>`,
selected with `$MXFS_LAB`), each file holds that platform's `nodes` line and
its own `storage` line.
`also=` lists nodes outside the sets that attach to the same LUN; they are
unmounted before the harness formats it. `addr` is only for a node no
resolver knows. `qemu monitor_dir` is only for a guest started outside
libvirt, which `tests/tcp_peer_freeze_death.sh` freezes through its QMP
socket. `paths` names the build host's own files: the fileio image behind an
SCST or LIO LUN, the dm-delay rig's image, the VM directory and the qemu
guests' root; the rig-setup scripts and the host preflight read them from here
unless an `MXFS_*` variable overrides them for one run. A platform with no
`nodes` (or `pair`) line, or with fewer nodes than the release claims, cannot
be verified here, and the harness says so and stops.

## `run.sh` is virsh-coupled on the VM path (gated), with an external escape hatch
- **VMs (default):** `prep_cluster()` **directly** `virsh list`s the `test[0-9]+`
  fleet (run.sh:374) and `virsh destroy`/`start`s it (:394/:396); `power_cycle_node`
  (:304/:306) recovers a wedged node via `virsh destroy+start`. So run.sh **does**
  assume QEMU/libvirt here.
- **External/physical:** the entire virsh fleet block is gated behind
  `[ -z "$MXFS_NODE_LIST" ]`. With `MXFS_NODE_LIST=ip1,ip2 … run.sh <N> <cond>`,
  run.sh **skips virsh entirely** and `power_cycle_node` refuses (no libvirt
  domain). That's the only way to drive non-libvirt nodes (pve1/pve2, serv).

So the libvirt coupling is real and lives in **both** run.sh's VM path *and* the
rig-setup scripts — `MXFS_NODE_LIST` is the escape hatch, not a full abstraction.

## Attachments → which rig provides each
A configuration is `<nodes>/<class>/<method>/<attach>`
(`docs/attachment-methods.md`). Either DLM (`net/mesh`, `disk/caw`) runs on any
attachment; the rig provides the attachment:

| attach | shape | rig | doc |
|---|---|---|---|
| `direct` | each VM its own iSCSI login, one path | SCST shared target, portal .1 | `docs/test_infra_scst_caw.md` |
| `mpath`  | **dm-multipath over two portals — the common enterprise shape** | SCST dual-portal + multipathd | `docs/multipath-attach.md`, `docs/multipath_support.md` |
| `pass`   | hypervisor passthrough (per-nexus PR) | SCST per-node targets wired into VM XML | `docs/test_infra_scst_caw.md` |

SCST's `vdisk_fileio` does SCSI **COMPARE AND WRITE (0x89) + Persistent
Reservations** natively — the two real FC-array primitives — which is why it's
the faithful CAW/FC emulation. The LIO/`tcm_loop` stack fakes COMPARE AND WRITE
and is no configuration's attachment (`docs/test_infra_lio_tcm.md` is its history).

## Lab-management scripts (in `scripts/`, referenced — not moved)
- `rig.sh <configuration>` — **front door**; owns ALL attachment
  transitions (node cleanout, VM XML wiring, portal/wwids hygiene, VM restarts).
- `define_vms.sh` — define the libvirt domains.
- `wire_vms.sh` — wire the LIO LUN into VMs; `rig.sh` uses only its `detach`.
- `scst_setup.sh` / `scst_wire_passthrough.sh` / `mpath_up.sh` — SCST CAW rigs.
- `lio_tcm_setup.sh` — the LIO/`tcm_loop` stack (no configuration uses it).
- `verify_infra.sh <configuration>` — infra-only bring-up +
  verify (no `mkfs`/mount/module — pure substrate check; runs `tools/caw_verify`).
- `cluster_reset_n.sh` — reset N VMs.
- `lab_clone_node.sh <source> <clone> <ip> ...` — grow a platform's set by
  cloning a verified node of it.
- `scst_platform_targets.sh setup [<platform> ...]` — one SCST target and one
  lab file per platform; naming platforms sets up only those.
- `lab_power.sh up|down|state <set> ...` — power whole sets (`<platform>`,
  `rig:<N>`, or a domain). The host cannot hold the 8-node rig and four
  8-node sets at once, so a verification powers up only what each step needs
  (`POWER=1` in `tests/full_verify.sh`).

## Test harness (in `scripts/` + root)
- `run.sh <configuration>` — one test run, e.g. `run.sh 8/net/mesh/direct`
  (`1/xfs` is the native-XFS baseline).
- `scripts/ladder_rung.sh <configuration>` — full rung; `RULE0_CALIBRATE=0` enforces
  each test's time budget, so a run over budget fails.
- `tests/packaged_round.sh <platform>` — a release installed on every node of
  a platform's verification set as a user installs it, and verified there.
- `NODES=<N> tests/full_verify.sh <version>` — everything a version must pass
  before it is published: the clean build and audits, the rig suite of every
  configuration of the release matrix at N nodes (`data/configurations.json`),
  the packages, and every platform's packaged round and hung-node test on each
  of those configurations.
- `tools/criteria.py <configuration>` — recorded results; `data/criteria.json` = the board.

## Credentials / test secrets → `~/.config/mxfslab/secrets`
Testing secrets are **not** in the repo. The single source of truth is
`~/.config/mxfslab/secrets` (mode 600), format `<key> field=value ...`:
```
node username=root password=<the lab node root password>
```
`tools/mxfs_secrets.sh` resolves it and materializes the sshpass passfile
(`/tmp/.mxfs_pass`); `tools/mxfs_sshpass.sh` — the SSH wrapper every test script
uses — re-resolves from the store if the passfile is missing, so nothing hardcodes
a password. The node root password is kept in sync with osimager's
`images/linux` secret, so osimager-built fleet nodes match what the harness uses.
To rotate: change it in `~/.config/mxfslab/secrets` (and osimager's `images/linux`),
then `chpasswd` the fleet.

## Physical / external hosts
Real hardware, reached only through the `MXFS_NODE_LIST` escape hatch (no
libvirt, so run.sh skips virsh recovery for these). A platform whose
verification set is real hardware (`vms.md` says so) is named in the lab file
like any other.

## Where the rest lives
Open defects: `tools/defects.py`. Platforms and what each release claims:
`tools/platforms.py`. Awareness map:
`.claude/awareness/structural-map.md` + `subsystems/*.md`. Deep infra history:
`docs/test_infra_*.md`, `docs/notes/SCST_PROBLEM.md`.
