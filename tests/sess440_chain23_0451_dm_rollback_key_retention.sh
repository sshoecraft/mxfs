#!/bin/bash
# sess440 chain 23: build 0.45.1 (dm_pr_register rollback defeat of the
# retained same-boot fence key — scsipr probes swap(K,K) BEFORE the plain
# REGISTER; v5_same_boot_dirty_scan refuses a same-boot dirty remount with
# the key RETAINED (mxfs_scsipr_retain_key); v5_pr_fence_prove never P&As
# our own key, P238-FENCE-OWN-KEY -> snx mints kind 17), deploy, verify:
#   prep              must mount 32/32 (regression gate)
#   remount_refused   lone_mount_create: same-boot dirty remount REFUSED via
#                     P305-PR-SAME-BOOT-DIRTY-PREDECESSOR AND the key still on
#                     the LU after the refusal (keyheld>=1, new assertion)
#   remount_snx       single_node_exclusive=1: reuse + P238-FENCE-OWN-KEY +
#                     fence kind 17 + mrc2=0 file=1
#   fln_churn         fence_live_node churn (live-node fence path unchanged)
# Budgets: build ~3 min (bound 500), tools 120, prep 66-95 s (bound 300),
# remount arms bound 100 each (sess433 measured), fln_churn 88 s measured
# (bound 420), test20 restart 45 s.
cd /src/mxfs || exit 1
LABEL=${1:-s440a}
LOG=tests/evidence/sess440_chain23_0451_dm_rollback_key_retention_$LABEL.log
EV=tests/evidence/sess440_chain23_0451_dm_rollback_key_retention_$LABEL
VIRSH="sudo virsh -c qemu:///system"
SSH="tools/mxfs_sshpass.sh"
mkdir -p "$EV"
{
  echo "=== sess440 chain23 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  grep -a 'warning:' "$EV/build.txt" | grep -v 'compiler differs\|xfs_platform.h\|xfs_fs_report_error' | cut -c1-200 | head -20
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on 0.45.1"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx test1 32 remount_snx; echo "STAGE remount_snx rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  T0=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 420 tests/fence_live_node.sh $LABEL churn test20 test1 32 --no-prep; echo "STAGE fln_churn rc=$?"
  timeout 30 $SSH test1 "journalctl -k --since '$T0' | grep -a 'P236-FENCE-INTENT\|P236-FENCEKIND\|P-PRKEY-FENCED\|P238-FENCE-OWN-KEY\|P-PRKEY-VICTIM-UNKNOWN\|NO_VICTIM_KEY' | cut -c1-230 | head -12" > "$EV/fence_test1.txt" 2>&1
  echo "--- test1 fence lines: $(grep -ac 'P236\|P-PRKEY\|P238' "$EV/fence_test1.txt")"; grep -a 'P236\|P-PRKEY\|P238' "$EV/fence_test1.txt" | head -8
  $VIRSH start test20 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep4 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
