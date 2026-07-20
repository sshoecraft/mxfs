---
name: sess72-tcp-dlm-scaling-harness-fixed-invalid-sweep
description: sess72: QNAP iSCSI target CRASHED under storm (3260 down). User chose TCP DLM on SCST LUN; scst_scale.sh ready. SCST kernel wedge-fix built (caw-abor…
metadata:
  type: project
---

## sess72 (ccloop 14d31183) — TCP DLM scaling sweep: QNAP died, pivoted to SCST; SCST kernel fix awaiting install

User's directive this session = **1/2/4/8/16-node TCP DLM scaling sweep** (`force_transport=1`),
NOT the CAW ship criteria. Added `tcp_dlm_scaling` criterion to SUCCESS_CRITERIA.md +
verify_ship.sh GATING + `tests/criteria/tcp_dlm_scaling.sh` (wraps qnap_scale.sh).

### ENV (host RESET since sess68 — healthy)
- clyde SCST host NOT wedged (3260 LISTENING, 0 iscsi_conn_cleanup). 16 VMs up.
- ONE shared NFS `/src` from QNAP `192.168.1.4:/src` (clyde + all VMs). DO NOT touch
  clyde /etc/exports — see [[infra-src-is-qnap-nfs-do-not-touch-exports]].
- Tree was `make clean`'d. REBUILT this session: `make modules` (mxfs.ko **55379AA2** =
  sess70 source) + `make tools` (mkfs_mxfs/chk_mxfs/resize_mxfs). Both on shared /src.
- Node LUNs: **sda = SCST_FIO** (clyde SCST, the chosen TCP-DLM substrate now);
  sdb = QNAP (now unusable, see below).

### QNAP iSCSI target CRASHED under the storm (key finding)
QNAP `192.168.1.4:3260` is **persistently CLOSED** (tested from clyde + nodes). Its
NFS(2049)/SSH(22)/web(8080/443) are UP — box alive, only the iSCSI target service died
under the 16-node mkdir storm. No QNAP admin creds (tried <REDACTED-ROTATED>/<REDACTED-ROTATED> on admin@ —
denied). Cannot restart it; TCP-DLM-on-QNAP is blocked until the user restarts the QNAP
iSCSI target. The QNAP appliance target itself does not survive this load.

### Two INVALID QNAP sweeps + harness fixes (do not trust those numbers)
qnap_scale.sh defects found+fixed: (1) mounted STALE un-formatted FS because mkfs_mxfs
binary was missing and only MOUNT_OK was checked → added MKFS_OK abort guard
(FORM-FAIL-MKFS). (2) Tried per-step iSCSI logout/login hardening → removed /dev/sdb and
raced the form → REVERTED to simple `--login`. Net: qnap_scale.sh now has the mkfs guard
and simple login (hardening must be done once cluster-wide, not per-step).

### USER DECISION (AskUserQuestion): run TCP DLM on the **SCST LUN** /dev/sda
Wrote **`scripts/scst_scale.sh`** (syntax-OK, +x): SCST counterpart of qnap_scale.sh.
Sources tests/criteria/lib.sh, uses `fresh_cluster_mount` (NFS-ensure + fresh
insmod-with-INSMOD_OPTS=`force_transport=1 fua_disable=0` + stale-PR clear + mkfs
w/ MKFS_OK check + mount + join + verify-all-mounted), then storm+verify per N.
MXFS_DEV defaults /dev/sda. NOT YET RUN.

### NEW: SCST kernel-side wedge FIX available (from parallel scst session) — INSTALL IT FIRST
Fix for the iscsi_conn_cleanup D-state / permanent EXEC_CHECK_BLOCKING wedge (the
nexus-loss-under-CAW-storm orphan) is BUILT but **NOT installed/loaded**:
- Source: `/src/scst/scst/src/scst_targ.c` (helper `__scst_check_unblock_aborted_scsi_atomic_cmd`
  + dev_exec_cmd_list reclaim walk in `__scst_unblock_aborted_cmds`). Branch caw-abort-reclaim,
  commit 488704520 on fork github.com/sshoecraft/scst. Backup patch `/tmp/scst-caw-abort-reclaim.patch`.
- Target version marker: `3.11.0-pre+caw-abort-reclaim.1`. CURRENTLY INSTALLED
  `/lib/modules/$(uname -r)/extra/scst.ko` = **3.11.0-pre (OLD, unfixed)**.
- Install (host healthy now, no wedge to clear first): `cd /src/scst/scst && make && sudo make install`
  then reload scst (umount mxfs on all nodes + virsh reset, or scst service reload), confirm
  `modinfo -F version .../scst.ko` shows `+caw-abort-reclaim.1`.

### NEXT SESSION
1. Install + reload the fixed scst.ko (above); confirm version marker.
2. Run `bash scripts/scst_scale.sh 100 1 2 4 8 16` → per-N silent/shutdown wall on TCP DLM.
3. With the SCST wedge fixed, ALSO worth re-running CAW `zero_silent_loss.sh` (the host-wedge
   that blocked sessions 14-68 may now be gone) — the scst session expects this as confirmation.
4. If TCP DLM shows silent loss with no conn errors → real mxfs TCP-DLM cross-node dir
   visibility bug (verify = drop_caches+FUA reread on NODE0).

Links: [[infra-src-is-qnap-nfs-do-not-touch-exports]] [[test-cluster-scst-stack]] [[sess70-overcount-fix-and-purge-cascade-fix]] [[sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge]]
</body>
