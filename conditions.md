# Deployment Conditions

MXFS is validated against four deployment conditions — the "3+1" framing from
`compiled-caw-multipath-deploy-conditions` (2026-07-05): TCP DLM as the
no-CAW fallback, plus three distinct CAW deployment shapes (two no-mpath
variants and the primary enterprise dm-multipath target). Each has a short
code used throughout the test harness (`rig.sh`, `ladder_rung.sh`,
`matrix_check.py`, `showstat.sh`):

| Code | Condition | Rig shape |
|---|---|---|
| `tcp` | TCP DLM / commodity block (no CAW) — `force_transport=1`. | `rig.sh tcp`; LIO/tcm_loop. |
| `cawp` | CAW via FC-fabric passthrough. Simulates a physical host on FC fabric: clyde is the initiator with a distinct target per VM, giving each VM its own real PR fencing. | `rig.sh pass`; SCST + per-VM QEMU `device='lun'` passthrough. |
| `cawd` | CAW via direct iSCSI, no fabric — "Joe sysadmin mounts an iSCSI LUN." Each VM does its own `iscsiadm` login straight to clyde's SCST target (own nexus/PR, 0 sdX on clyde). | `rig.sh direct`; SCST shared target. |
| `caw` | CAW over dm-multipath — SAN (FC or iSCSI) with ≥2 paths + multipathd, mounting `/dev/mapper/mpathX`. The #1 real enterprise deployment target; added last, and the default condition when only one is meant. | `rig.sh mpath`; SCST dual-portal + multipathd. |

Use the code with the test harness, e.g.:

```
scripts/rig.sh mpath 32               # switch the 32-node rig to the caw condition
scripts/ladder_rung.sh 32 caw         # run the full rung for caw @ 32 nodes
python3 scripts/matrix_check.py --cond caw   # check matrix status for one condition
./showstat.sh 32 caw                  # view recorded results for caw @ 32 nodes
```
