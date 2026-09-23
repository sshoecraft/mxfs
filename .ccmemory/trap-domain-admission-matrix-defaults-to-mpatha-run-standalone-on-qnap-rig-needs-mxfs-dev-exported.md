---
name: trap-domain-admission-matrix-defaults-to-mpatha-run-standalone-on-qnap-rig-needs-mxfs-dev-exported
description: TRAP (sess517): tests/domain_admission_matrix.sh run outside sess507_chain_0750.sh defaults MXFS_DEV to /dev/mapper/mpatha; on the QNAP 2/tcp rig eve…
metadata:
  type: feedback
---

# TRAP: matrix without MXFS_DEV on the QNAP rig (sess517, 2026-09-05)

`tests/domain_admission_matrix.sh s517c_R8_1 test2` right after a QNAP death lap produced 9 FAILs: every row `MOUNT_RC=32 WALL=0 NOT_MOUNTED` and `REJOIN_RC=32`. Cause: the harness defaults `DEV=${MXFS_DEV:-/dev/mapper/mpatha}`; the chain (`tests/sess507_chain_0750.sh`) exports the QNAP by-path, a standalone invocation does not, so test2 tried to mount mpatha (no cluster there) while test1 was up on the QNAP LUN.

Signature to recognise it: ALL rows including the refusal rows fail (a real admission bug would fail one or two rows), walls of 0 s, no kernel refusal lines. Not a product fault; two matrix laps were wasted (~8 min).

Fix applied: the matrix header now prints `dev=`. Rule of thumb on this rig: any tests/*.sh run by hand against the QNAP cluster needs
`export MXFS_DEV=/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772-lun-0 MXFS_NODE_LIST=test1,test2` (same trap as the bare run.sh prep, sess513).
