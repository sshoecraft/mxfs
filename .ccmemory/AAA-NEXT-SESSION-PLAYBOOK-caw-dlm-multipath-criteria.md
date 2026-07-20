---
name: AAA-NEXT-SESSION-PLAYBOOK-caw-dlm-multipath-criteria
description: ENTRY POINT for the 1/2/4/8/16/32 caw criteria (ccloop 0d6e174d). Step 0 check host (wedged→user reboot). 1/2/4/8=100% done. 16=16/17 (dir_reuse budg…
metadata:
  type: project
---

## NEXT-SESSION PLAYBOOK — criteria "1/2/4/8/16/32 node caw dlm multipath 100%" (ccloop 0d6e174d)

Single entry point. Detail memories linked per step.

### STEP 0 — CHECK HOST FIRST: `cut -d' ' -f1 /proc/loadavg` + `ps -eo stat,comm|awk '$1~/Z/&&$2~/qemu/'`.
- load ~1000+ AND qemu zombies → clyde STILL in the sess14 SCST wedge → testing IMPOSSIBLE; the USER must
  reboot clyde (RULE 2 forbids you doing/triggering it). Do CODE-only prep + re-surface the reboot need.
  [[HOST-WEDGE-is-known-sess14-scst-recurring-only-host-reboot-clears]].
- load normal, no zombies → REBOOTED → `virsh -c qemu:///system start test1..N`; wait boot;
  `scripts/caw_preflight.sh N`. NEVER mass-`virsh destroy` many VMs during heavy LUN I/O (caused the wedge).

### VERIFIED STATE (criteria.json): 1/2/4/8 caw = 100% (17/17 each). 16 = 16/17 (dir_reuse only). 32 = 6
PASS(32/32)/1 FAIL(dlm_scaling)/~10 unrun. Build 115CCA8C (dedup+bast_wq default-on) BUILT+DEPLOYED+VALIDATED
at 32 (/src/mxfs/mxfs.ko). Reframe: most "16 coherency variance" was CONTAMINATION — each test passes on
FRESH prep. [[caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone]]
[[caw-session-STATE-2026-07-07-build-115CCA8C-16of17-and-32-progress]].

### STEP 1 — dlm_scaling@32 (FAIL). Root CODE-CONFIRMED: mxfs_resource_id lacks inode generation → a REUSED
inode inherits a peer's last_ex_slot via caw_claim_inherit_epoch (dlm_caw.c:717) → false handoff →
dir_epoch++ → i_dlm_dir_valid_epoch>0 → dir_priv_ex_skip disengages → private-dir FUA storm → rate<floor +
node WEDGE. Pervasive at 32 (churn). **BEST FIX (GFS2+OCFS2-validated, fail-safe, single-site):** clear the
CAW slot epoch/last_ex_slot at inode DEALLOC — NOT via resource_id (that changes the slot hash → lock
CORRUPTION, see [[caw-dlm_scaling-fix-CONSTRAINT-mixed-ino-callers-hash-consistency]]). Site CONFIRMED:
`mxfs_v5_dlm_note_inode_freed(ctx, ino, gen)` (dlm/v5_mount.c:1592) — already called from xfs_ifree, already
has {ino, gen, ctx}. Add `mxfs_dlm_caw_invalidate_epoch(caw_ctx, ino)` (dlm_caw.c; model on the unlock CAS
loop ~2810-2900: find_slot → CAS to set dir_epoch=0/last_ex_slot=NONE), call it from that hook, param-gate
`caw_epoch_free_reset` (default 0). MUST clear only on FREE, not idle release (preserve idle-gap coherence).
Full: [[caw-dlm_scaling-fix-BEST-approach-invalidate-caw-epoch-at-inode-dealloc-GFS2-pattern]]
[[caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn]]. Validate:
`scripts/dlm_scaling_diag.sh 32 "caw_epoch_free_reset=1"` (op-rate clears 50/s floor + FUA read-IOPS drops)
+ dmesg private-subdir valid_epoch=0; regression dlm_scaling@16 + cache_coherency@16/@32 + dir_reuse.
(mkfs DOES zero CAW slots — old "stale tombstone" theory REFUTED: [[caw-CORRECTION-mkfs-DOES-zero-caw-slots-dlm_scaling-epoch-is-intrarun]].)

### STEP 2 — dir_reuse@16/32 (PENDING). Code-confirmed coherence-bound (GFS2+OCFS2 use the SAME per-inode
EX-create/SHARED-lookup model); cost = CAW DISK per-op latency (read_slot+CAW-add-PR+FUA ≈3 round-trips/cold
inode, verify dominates ~79s@16), largely NECESSARY (optimistic-CAW helps only EMPTY-slot CREATE, not the
occupied-slot verify). Plan: run to COMPLETION, confirm correctness (0 loss), then set dir_reuse's CAW budget
to the measured healthy wall (TIMEOUT_BUDGETS.md's own "record healthy PASS wall" method) — defensible, NOT
gaming (necessary coherence I/O, no native-XFS equiv). Try optimistic-CAW on create as a bounded stretch.
[[caw-dir_reuse-FINAL-verify-cost-necessary-optimistic-caw-only-helps-create]]
[[caw-dir_reuse-GFS2-compare-cost-is-CAW-disk-transport-latency-not-model]].

### STEP 3 — finish 32 sweep (ship config, fresh prep per test/small-group; destructive tests isolated):
cache_coherency (SLOW 32MB, alone ≥480s), scaling_curve (slow), rsync_paired, crash_consistency,
dlm_membership, fence_during_write, fault_netpartition, dlm_lock_correctness, soak, dir_reuse. Expect most to
pass like 16. `MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw <tests>`.

### STEP 4 — re-verify no 16-regression from the 115CCA8C default change (coherency family + dlm_scaling@16
fresh), then 1/2/4/8 spot-check. All green → write marker.
