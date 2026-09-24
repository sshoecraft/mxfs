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

### Building a platform's pair
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
   where nothing in this tree looks.
3. **Do the row's "after the build" steps**, and boot the kernel
   `data/platforms.json` claims for the platform. Then on every node:
   - headers for the running kernel (DKMS compiles the module against them)
   - an iSCSI initiator and `sg3_utils`
   - root SSH with the password in your secrets store (below)
4. **Give the pair a shared LUN.** An iSCSI LUN that supports SCSI persistent
   reservations, reachable from both nodes. MXFS fences a dead node through
   the reservation, so a target without one cannot verify a release. The
   harness logs each node in to it.
5. **Name the pair in your lab file** (next section).
6. **Verify:** `tests/packaged_round.sh <platform>` installs the release's
   package on the pair and runs the checks the platform's `verify_tests`
   lists; `tools/platforms.py verify` records the result.

### Your lab file → `~/.config/mxfslab/lab`
Which nodes verify each platform, their addresses and the shared LUN are this
site's alone, so they are never in the tree. The harness reads them from
`~/.config/mxfslab/lab` (override with `$MXFS_LAB`) through
`tools/mxfs_lab.sh`, whose header is the format reference:
```
storage portal=<ip> target=<iqn> lun=/dev/disk/by-id/<id> also=<nodes>
pair ubuntu2404=<nodeA>,<nodeB> rhel9=<nodeA>,<nodeB>
addr <node>=<ipv4>
qemu monitor_dir=<dir>
```
`also=` lists nodes outside the pairs that attach to the same LUN; they are
unmounted before the harness formats it. `addr` is only for a node no
resolver knows. `qemu monitor_dir` is only for a guest started outside
libvirt, which `tests/tcp_peer_freeze_death.sh` freezes through its QMP
socket. A platform with no `pair` line cannot be verified here, and the
harness says so and stops.

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

## Deployment conditions (`conditions.md`) → which rig provides each
| cond | shape | rig | doc |
|---|---|---|---|
| `tcp`  | commodity block, no CAW | LIO `tcm_loop` | `docs/test_infra_lio_tcm.md` |
| `cawp` | CAW FC-fabric passthrough (per-nexus PR) | SCST per-node targets | `docs/test_infra_scst_caw.md` |
| `cawd` | CAW direct iSCSI, no fabric | SCST shared target | `docs/test_infra_scst_caw.md` |
| `caw`  | **CAW over dm-multipath — #1 enterprise target** | SCST dual-portal + multipathd | `docs/condition4_multipath_scope.md`, `docs/multipath_support.md` |

SCST's `vdisk_fileio` does SCSI **COMPARE AND WRITE (0x89) + Persistent
Reservations** natively — the two real FC-array primitives — which is why it's
the faithful CAW/FC emulation (the LIO stack is CAW-off, used only for `tcp`).

## Lab-management scripts (in `scripts/`, referenced — not moved)
- `rig.sh {tcp|pass|direct|mpath} <N>` — **front door**; owns ALL condition
  transitions (node cleanout, VM XML wiring, portal/wwids hygiene, VM restarts).
- `define_vms.sh` — define the libvirt domains.
- `wire_vms.sh` — wire the shared LUN into VMs (LIO/`tcp` path).
- `scst_setup.sh` / `scst_wire_passthrough.sh` / `mpath_up.sh` — SCST CAW rigs.
- `lio_tcm_setup.sh` — LIO `tcp` rig.
- `verify_infra.sh {tcp|direct|passthrough|multipath} [N]` — infra-only bring-up +
  verify (no `mkfs`/mount/module — pure substrate check; runs `tools/caw_verify`).
- `cluster_reset_n.sh` — reset N VMs.

## Test harness (in `scripts/` + root)
- `run.sh <N> <cond>` — one test run (`xfs` baseline also accepted).
- `scripts/ladder_rung.sh <N> <cond>` — full rung; `RULE0_CALIBRATE=0` enforces
  each test's time budget, so a run over budget fails.
- `tests/packaged_round.sh <platform>` — a release installed on a platform's
  pair as a user installs it, and verified there.
- `scripts/matrix_check.py --cond <c|all>` — 4-condition × node-count board.
- `showstat.sh <N> <cond>` — recorded results; `criteria.json` = the board.

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
libvirt, so run.sh skips virsh recovery for these). A platform whose pair is
real hardware (`vms.md` says so) is named in the lab file like any other.

## Where the rest lives
Open defects: `tools/defects.py`. Platforms and what each release claims:
`tools/platforms.py`. Awareness map:
`.claude/awareness/structural-map.md` + `subsystems/*.md`. Deep infra history:
`docs/test_infra_*.md`, `docs/notes/SCST_PROBLEM.md`.
