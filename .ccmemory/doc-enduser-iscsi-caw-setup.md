---
name: doc-enduser-iscsi-caw-setup
description: End-user iSCSI/SAN setup + CAW storage requirements doc: docs/iscsi_setup.md. What a real shared LUN must provide for MXFS CAW/TCP-DLM.
metadata:
  type: reference
tags: [docs, iscsi, caw, scst, deployment, enduser]
---

## docs/iscsi_setup.md (created 2026-07-05)

End-user-facing deployment doc — the "what real shared storage must provide for
MXFS, and how to prove it before formatting" guide. Created because no
README/INSTALL/deployment doc existed; `docs/` was all internals/architecture.
Distinct from `docs/test_infra_lio_tcm.md` (that is the clyde LIO **test** rig).

### What it covers
- Transport choice: **CAW** (default, in-band on the LUN) vs **TCP DLM**
  (`force_transport=1`, out-of-band, for storage that can't do CAW).
- CAW hard requirements: SCSI COMPARE AND WRITE 0x89 honoured **atomically**
  (not faked), SCSI PR type 5 (WRITE-EXCL REGISTRANTS-ONLY) per I-T nexus,
  write-through (no volatile target cache), FUA reads reaching media.
- Target matrix: **SCST = CAW works**; **LIO fileio/iblock = CAW FAKED → TCP DLM
  only**; vendor arrays = verify.
- Pre-format verification: `sg_opcodes` (advertises), `tools/caw_verify`
  (cross-node CAW proof — the load-bearing one), `tools/fua_verify` (no stale
  read cache).
- Per-node REQUIRED tuning: `echo 180 > /sys/block/sdX/device/timeout` (+ udev
  rule) to prevent the 30s-timeout→ABORT_TASK→nexus-loss→permanent-LUN-wedge
  class; unique slot/identity per node.
- Reference SCST `/etc/scst.conf` (vdisk_fileio write_through, one iSCSI target
  per initiator), format/mount, and the "use chk_mxfs not xfs_db" envelope note.

Grounded in: [[test-cluster-scst-stack]], [[infra-lio-for-tcp-scst-for-caw-rationale]],
SCST_PROBLEM.md, tools/prep_tcm_node_scst.sh, tools/caw_verify.c, tools/fua_verify.c.

### Still missing (not this doc's job)
No host-side SCST bring-up **script** in the tree (old rig was manual
`/etc/scst.conf` + scstadmin/iscsiadm/virsh; disk-1.img is gone). If we stand up
CAW testing on clyde, build `scripts/scst_iscsi_setup.sh` (RULE 3) — see the
CAW-rebuild discussion, sess head after 8/tcp = 100%.
