---
name: caw-scripts-all-3-conditions-proven
description: Infra scripts for 3 deploy conditions DONE + verified at 32 nodes (infra-only, no FS testing). verify_infra.sh replaces caw_cluster_up.sh. Left bare…
metadata:
  type: project
tags: [caw, scst, iscsi, test-infra, scripts, verified, infra-only]
---

## Infra create/destroy/verify scripts — DONE, verified at 32 nodes (2026-07-05)

SCOPE (corrected mid-task, user directive): these scripts ONLY create/destroy
the infra and verify the shared LUN is PRESENTED correctly. They do NOT test the
filesystem — no mkfs, no mount -t mxfs, no workload, no coherency. That is the
test harness's job (tests/run_tests.sh) and is FUTURE work. CAW itself is still
under development (only 8-node fio/tcp is validated = showstat 8 tcp = 100%).

### Scripts (all in scripts/, RULE 3)
- **scst_setup.sh {setup|status|teardown}** — host SCST target. vdisk_fileio
  device `mxfs` (async=1; o_direct=1), iSCSI target :shared, allowed_portal
  192.168.120.1 (br0 ONLY — critical: clyde has ~9 IPs incl docker bridges
  172.17-20.0.1 + libvirt 192.168.122.1; without the pin, guests open 9 sessions
  → multipath chaos). Releases LIO first (guard).
- **scst_wire_passthrough.sh {attach|detach|status} [N]** — cond2 host side:
  per-node target :nodeK, clyde loopback login → by-path dev → virsh device='lun'
  into testK. Distinct targets required (per-nexus PR + by-path uniqueness).
- **lio_tcm_setup.sh** — cond1 (TCP). Added release_scst guard (symmetric to
  scst_setup's release_lio); guard path = /sys/kernel/scst_tgt/devices/mxfs.
- **verify_infra.sh {tcp|direct|passthrough} [N]** — INFRA-ONLY verifier
  (replaced caw_cluster_up.sh, which was deleted — it wrongly formed a cluster).
  Per node: device present + vendor + 50GiB size + raw readable + same SCSI
  serial. CAW modes: raw cross-node caw_verify (storage capability, not FS).
  Checks clyde footprint (direct 0/0; passthrough N/N; tcp 0/1).

### VERIFIED 2026-07-05 — all 3 conditions, 32 nodes, EXIT 0
- direct 32: 32/32 nodes, same LUN (serial 2e476d07), CAW PASS, footprint 0/0.
- passthrough 32: 32/32, same LUN, CAW PASS, footprint 32 sessions/32 sd*.
- tcp 32: 32/32, same LUN (LIO-ORG), footprint 0 sessions/1 sd*.
Then torn down to BARE (SCST+LIO gone, 0 sessions, 0 sd*, 0/32 VM configs ref LUN,
disk.img intact).

### Verifier bugs found+fixed during testing (RULE 4)
1. direct login raced iscsid at boot → session with NO attached disk; plain
   re-login no-ops ("already present"). Fix: full clean cycle per retry
   (logout+delete → discover → login → session --rescan).
2. sg_inq serial parse flaky → false same_lun=no. Fix: retry + gate "same LUN"
   on the cross-node CAW proof for CAW modes.
3. footprint iscsiadm -m session needs sudo (non-root returned 0 sessions).

### GUEST BUILDUP config applied to all 32 (should be baked into VM image)
- /etc/multipath/conf.d/mxfs.conf: `find_multipaths strict` (+ cleared wwids) so
  a single iSCSI path is NOT wrapped into mpatha (which would hold /dev/sda). NOTE
  multipath stays RUNNING — this is prod-correct, just don't wrap a lone path.
- /etc/fstab: removed /src NFS auto-mount ([[feedback-src-nfs-not-fstab-automount]]).

### CORRECTION — do NOT overstate these as proven mxfs bugs (they were out of scope)
Earlier notes called two things "mxfs bugs". Both are UNPROVEN observations from
testing that was OUT OF SCOPE (infra task ≠ FS testing). Restated honestly:
- **CAW-through-dm-multipath: UNKNOWN, not a proven bug.** One caw_verify against
  /dev/mapper/mpatha returned UNIT ATTENTION (sense 0x29, power-on/reset) on the
  FIRST command; caw_verify does not retry UA. A UA is transient/retryable, so
  this is NOT evidence CAW fails through multipath. Needs a retry-aware test.
- **32-node CAW concurrent-workload corruption: one observation.** A concurrent
  mkdir workload on a fresh-mkfs 32-node CAW cluster gave EUCLEAN + FS shutdown on
  ~20/32, amid heavy churn. mkfs/chk_mxfs were clean. 32-node CAW is far past the
  validated 8-node ceiling; treat as an observation for the FS work, not a filed
  bug. Should not have been run under this (infra-only) task.

Docs: docs/test_infra_scst_caw.md (scripts, buildup config, allowed_portal, +
an "open question" note for the FS work). docs/iscsi_setup.md (end-user).
See [[caw-test-3-conditions-and-script-inventory]].
