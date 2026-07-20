# MXFS Test Infrastructure — SCST / CAW bring-up (conditions 2 & 3)

**Status:** current as of 2026-07-05. Companion to `docs/test_infra_lio_tcm.md`
(the LIO/tcm_loop stack for condition 1, TCP DLM). This doc covers the two
**CAW** deploy conditions on the SCST shared LUN.

MXFS must validate three deployment shapes (see memory
`caw-test-3-conditions-and-script-inventory`):

| # | Real deployment | Transport | Rig |
|---|---|---|---|
| 1 | commodity / no-CAW storage | TCP DLM (`force_transport=1`) | LIO/tcm_loop — `lio_tcm_setup.sh` |
| 2 | **FC fabric → physical hosts** | **CAW** | SCST + per-VM host passthrough (N sdX on clyde) |
| 3 | **direct iSCSI mount, no fabric** | **CAW** | SCST + each VM its own iSCSI initiator (0 sdX on clyde) |

Key fact: a SCST `vdisk_fileio` device does **not** create a local `/dev/sdX` on
clyde — the LUN only materialises inside an initiator that logs in. So one
shared target serves both CAW conditions; the difference is *who logs in*.

## The chain

```
/home/steve/disk.img
  → SCST vdisk_fileio device "mxfs"  (o_direct=1 — sess26 perf; CAW 0x89 + PR native)
  → iSCSI target iqn.2026-05.local.mxfs:shared, LUN 0   (br0 192.168.120.1:3260)
        │
   cond 3 (direct):        cond 2 (passthrough):
   each VM iscsiadm login   clyde logs into per-node targets iqn...:nodeK
   → guest /dev/sda         → N host /dev/disk/by-path devices
   (0 sdX on clyde)         → QEMU device='lun' one per VM → guest /dev/sda
                            (N sdX on clyde; distinct target per node = real
                             per-nexus PR fencing, sess26)
```

## Scripts (all in `scripts/`, RULE 3)

### `scst_setup.sh {setup|status|teardown}` — HOST target (foundation for 2 & 3)
Loads SCST (`scst`, `scst_vdisk`, `iscsi_scst`) + starts `iscsi-scstd`, creates
the shared `vdisk_fileio` device `mxfs` over `disk.img` with `o_direct=1`, and
publishes the `:shared` iSCSI target on `:3260`. **Auto-releases LIO** on the
same backing file first (CAW-on-SCST and TCP-on-LIO are mutually exclusive on
one LUN). `o_direct` is create-time only (sess26: buffered pwrite serialises all
nodes on the file inode i_rwsem → ~930 MB/s; o_direct → ~2.8 GB/s).

### `scst_wire_passthrough.sh {attach|detach|status} [N|list]` — condition 2 only
clyde's side of the FC-fabric sim. For each node K: creates a distinct target
`iqn.2026-05.local.mxfs:nodeK` (all LUN 0 → the same `mxfs` device), logs clyde
in over loopback → a stable `/dev/disk/by-path/...` device, and `virsh
attach-device`s it into `testK` as a shareable `device='lun'` at guest `sda`.
Distinct targets (not N ifaces to one target) are required: PR fencing is
per-nexus, and N sessions to one target+portal collide on a single by-path
symlink. Running VMs need a restart to see the LUN.

### `verify_infra.sh {tcp|direct|passthrough} [N]` — INFRA-ONLY bring-up + verify
Brings the infra up (host setup + per-mode wiring), restarts the VMs, presents
the shared LUN on each node, and **verifies the infra is configured correctly —
nothing more.** It does NOT touch the filesystem: no `mkfs`, no `mount -t mxfs`,
no mxfs module load, no workload. Testing the filesystem / CAW coordination is
the test harness's job (`tests/run_tests.sh`) and is deliberately out of scope.

Per node it checks: the shared LUN is present with the expected vendor + 50 GiB
size, is readable as a raw block device, and is the **same** LUN everywhere
(matching SCSI unit serial). For the CAW modes it also runs the raw cross-node
`tools/caw_verify` (a *storage* capability check — does the target honour CAW
0x89 cross-initiator — not a filesystem test). It also asserts the clyde
footprint for the mode (direct 0 sessions/0 sd\*; passthrough N/N; tcp 0/1).

`N` defaults to 2. Presents the LUN but leaves it unmounted; tear down with the
create scripts' teardown verbs. (Replaced the old `caw_cluster_up.sh`, which
wrongly formed an mxfs cluster and load-tested the FS — out of scope.)

## Bring-up + verify sequence

```bash
# verify the infra for each condition (infra-only, no filesystem ops)
scripts/verify_infra.sh direct 32
scripts/verify_infra.sh passthrough 32
scripts/verify_infra.sh tcp 32

# teardown to bare
#   guests: source tests/criteria/lib.sh; teardown_all "test1 test2 ..."
#   host:   scripts/scst_wire_passthrough.sh detach 32; scripts/scst_setup.sh teardown
#           scripts/lio_tcm_setup.sh teardown
```

## Guest buildup config (required — should be baked into the VM image)

These are applied to every test VM as part of node buildup. They are guest-side
config, not something the harness should have to redo each run:

- **`/etc/multipath/conf.d/mxfs.conf`: `find_multipaths strict`** (+ clear
  `/etc/multipath/wwids`). multipathd stays running (correct for prod), but with
  a single iSCSI path it must NOT wrap the LUN into `/dev/mapper/mpathX` — a lone
  mpath device holds `/dev/sda` and makes any `mount`/open fail *"already mounted
  or mount point busy"*. `strict` = only multipath devices explicitly in `wwids`,
  so a single path is left as raw `/dev/sda`. (The spurious *multi*-path fan-out
  that first triggered this was a lab artifact — see `allowed_portal` below.)
- **No `/src` NFS auto-mount in `/etc/fstab`.** A hard NFS mount at boot can hang
  the VM if the server is unreachable. `/src` is mounted only by the node-prep /
  buildup step, never at boot.

## Network / portal pinning (`allowed_portal`)

clyde has many IPs (br0 `192.168.120.1`, libvirt `192.168.122.1`, docker bridges
`172.17–20.0.1`, LAN). SCST advertises an iSCSI target on **all** of them by
default, so a guest's `iscsiadm --login` opens **one session per portal** (≈9) →
≈9 `sd` devices → multipathd coalesces them into `mpatha`, breaking direct-mode
mounts. `scst_setup.sh` pins the `:shared` target to the storage network only
(`add_target_attribute … allowed_portal 192.168.120.1`), so each guest gets
exactly one session on the correct path. A real SAN advertises only on its
storage network(s) for the same reason.

## Multipath (dm-multipath) — CHARACTERISED, works at the storage layer

Condition 4 (`verify_infra.sh multipath`, see `docs/condition4_multipath_scope.md`)
settled the earlier open question. On a real 2-path `/dev/mapper/mpathX`:
- **CAW works through dm-multipath** — cross-node PASS, both with and without
  `--retry-ua`. The earlier single UNIT ATTENTION (`0x29`) was a transient
  first-command UA, not a failure. (`caw_verify` gained `--retry-ua` regardless,
  since a correct SG_IO issuer should retry UA.)
- **PR / fencing works through dm-multipath** — a node reserving WE-RO (registered
  with `--param-alltgpt`) is seen by another node through *its* mpath device, and
  a non-registrant's write is correctly blocked (reservation conflict). Verified
  at N=2; presentation scales to 32/32 (every node gets a 2-path mpath device).
So the enterprise-SAN case (CAW+PR over multipath) is sound at the storage/
transport layer. Whether mxfs's *own* CAW/PR code paths run on `/dev/mapper/mpathX`
is still FS work — but the substrate is proven to support it.

## Known caveats

- **SCST wedge under heavy concurrent CAW** (`SCST_PROBLEM.md`): strictly-
  serialized CAW/WRITE-SAME drains can exceed the initiator timeout →
  ABORT_TASK → nexus loss → leaked D-state `iscsi_conn_cleanup` → permanent LUN
  wedge. Mitigation = the 180s guest SCSI timeout (in `prep_tcm_node_scst.sh`).
  This is an SCST software artifact, not how a real FC array behaves. Recover a
  live wedge with `scripts/scst_unwedge/` (no host reboot — RULE 2).
- Condition 2's clyde loopback initiator is the same iSCSI-loopback path the
  project moved *away* from onto LIO; it is inherent to simulating FC passthrough
  and only used for the CAW conditions.
- `disk.img` (50G) is shared with the LIO stack; `scst_setup.sh` tears LIO down
  first. Switching back to TCP means `scst_setup.sh teardown` + `lio_tcm_setup.sh
  setup`.
- End-user deployment guidance (not the test rig): `docs/iscsi_setup.md`.

## 4-condition FS validation (ccloop 72513a13, 2026-07-18)

The FS-level criteria matrix now carries one column per deployment condition
(`criteria.json` cell key `<N>/<cond>`; `conditions.md` is the user framing):

| cond | conditions.md | rig bring-up | guest device (run.sh default) |
|---|---|---|---|
| `tcp`  | 1: TCP DLM / commodity block | `scripts/rig.sh tcp 32` (LIO tcm_loop + `wire_vms.sh` + VM power-cycle) | `/dev/sda` (LIO-ORG) |
| `cawp` | 2: CAW FC-fabric passthrough | `scripts/rig.sh pass 32` (SCST per-node targets + `scst_wire_passthrough.sh` + VM power-cycle) | `/dev/sda` (SCST_FIO) |
| `cawd` | 3: CAW direct iSCSI | `scripts/rig.sh direct 32` (SCST `:shared`, portal .1 only, in-guest logins) | `/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0` |
| `caw`  | 4: CAW over dm-multipath | `scripts/rig.sh mpath 32` (delegates to `mpath_up.sh`) | `/dev/mapper/mpatha` |

- `run.sh <N> <cond>` accepts all four (plus `xfs` baseline); `cawd`/`cawp`
  map to the CAW transport for module/prep purposes (BASE_TRANSPORT).
- One full rung: `scripts/ladder_rung.sh <N> <cond>`.
- Board check: `scripts/matrix_check.py --cond all [--since ISO]`.
- `scripts/rig.sh` owns ALL transitions (node cleanout, VM XML unwiring,
  portal reconfig, wwids hygiene, VM restarts). Never leave a rig half-switched:
  a leftover dual-portal login on a single-path rig gets wrapped by multipathd
  and steals the raw sdX.
