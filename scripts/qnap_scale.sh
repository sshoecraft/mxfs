#!/bin/bash
# qnap_scale.sh — scaling sweep on the QNAP direct-iSCSI LUN with TCP DLM.
# Find the wall: run the workload-A mkdir storm at 1, 2, 4, 8, 16 nodes and
# report per-step exactly what breaks (silent loss, mount/join failures,
# iSCSI conn drops). No CAW, no clyde SCST — each VM is its own initiator
# direct to the QNAP (iqn.2004-04.com.qnap:ts-453pro:...:f35772).
#
# Usage: qnap_scale.sh [dpn] [steps...]   default dpn=100 steps="1 2 4 8 16"
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MODULE=/src/mxfs/mxfs.ko
DEV=/dev/sdb
MNT=/mnt/shared
OPTS="force_transport=1 fua_disable=0 inode_mht_ms=50"   # TCP DLM + FUA reads (separate-initiator iSCSI) + LOW inode hold-time: the scaling storm needs fast DLM handoff (mht=300 default blows the per-step window -> acquire-timeout cascade -> conn-drop wedge). sess20(ccloop): tcp_dlm_scaling reloads its OWN module here, decoupled from the suite's high-mht main mount used by dir_reuse_coherency.
TGT=iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772
DPN="${1:-100}"; shift 2>/dev/null || true
STEPS=("$@"); [ ${#STEPS[@]} -gt 0 ] || STEPS=(1 2 4 8 16)
ALL=(test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16)

run() { timeout "${3:-120}" "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

# Always tear down ALL 16 so a non-participating node never holds the shared LUN.
teardown_all() {
  for n in "${ALL[@]}"; do run "$n" "umount -f $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; true" 40 >/dev/null & done; wait
  # confirm clean on every node (wedged node => abort, it would corrupt the next mkfs)
  for n in "${ALL[@]}"; do
    ok=0
    for t in 1 2 3 4 5; do
      run "$n" "! grep -q ' $MNT ' /proc/mounts && ! grep -q '^mxfs ' /proc/modules && echo CLEAN" 20 | grep -q CLEAN && { ok=1; break; }
      run "$n" "umount -f $MNT 2>/dev/null; rmmod mxfs 2>/dev/null; true" 40 >/dev/null; sleep 3
    done
    [ "$ok" = 1 ] || { echo "  TEARDOWN-FAIL $n (wedged)"; return 1; }
  done
  return 0
}

echo "=== QNAP scaling sweep: dpn=$DPN steps='${STEPS[*]}' opts='$OPTS' ==="
for N in "${STEPS[@]}"; do
  NODES=("${ALL[@]:0:$N}"); NODE0="${NODES[0]}"
  echo "--- N=$N nodes=${NODES[*]} ---"
  # clear conn-error baseline per step + ensure the QNAP target is logged in
  # (idempotent; iSCSI hardening is applied cluster-wide ONCE before the sweep
  # via a clean node reboot, NOT here — logging out/in per step removed the
  # LUN and raced the form mkfs).
  for n in "${NODES[@]}"; do run "$n" "dmesg -C 2>/dev/null; iscsiadm -m node -T $TGT --login >/dev/null 2>&1; true" 30 >/dev/null & done; wait
  if ! teardown_all; then echo "  N=$N RESULT: INFRA teardown-wedge"; continue; fi

  # NODE0 forms: mkfs + mount
  out=$(run "$NODE0" "
    modprobe libcrc32c; insmod $MODULE $OPTS 2>/dev/null;
    echo y | /src/mxfs/tools/mkfs_mxfs $DEV >/tmp/mk.log 2>&1 && echo MKFS_OK || { echo MKFS_FAIL; tail -2 /tmp/mk.log; }
    mount -t mxfs $DEV $MNT && echo MOUNT_OK || echo MOUNT_FAIL" 120)
  # CRITICAL: abort if mkfs did not succeed.  Without this, a missing mkfs_mxfs
  # binary (make clean w/o make tools) or a dropped iSCSI LUN echoes MKFS_FAIL
  # but mount still succeeds on the STALE prior filesystem — every subsequent
  # silent/found number is then measured against un-formatted leftover state
  # and is meaningless (the sess18 stale-FS-reuse trap).
  echo "$out" | grep -q MKFS_OK  || { echo "  N=$N RESULT: FORM-FAIL-MKFS ($(echo "$out"|tr '\n' ';'))"; continue; }
  echo "$out" | grep -q MOUNT_OK || { echo "  N=$N RESULT: FORM-FAIL ($(echo "$out"|tr '\n' ';'))"; continue; }

  # joiners
  for n in "${NODES[@]:1}"; do
    ( run "$n" "modprobe libcrc32c; insmod $MODULE $OPTS 2>/dev/null; mount -t mxfs $DEV $MNT && echo OK" 120 | grep -q OK || echo "  join $n FAIL" ) &
  done; wait

  # count actually-mounted
  MOUNTED=(); for n in "${NODES[@]}"; do run "$n" "mount|grep -q $MNT && echo M" 15 | grep -q M && MOUNTED+=("$n"); done
  M=${#MOUNTED[@]}
  TD="$MNT/scale_$N"; run "$NODE0" "mkdir -p $TD; sync" 30 >/dev/null

  # storm: each mounted node makes DPN dirs
  for idx in "${!MOUNTED[@]}"; do n="${MOUNTED[$idx]}"; id=$((idx+1))
    ( run "$n" "for j in \$(seq 1 $DPN); do mkdir $TD/n${id}_d\$j 2>/dev/null; done; sync" 200 >/dev/null ) &
  done; wait

  # verify (FUA reads -> drop caches first to force on-disk read)
  run "$NODE0" "sync; echo 3 > /proc/sys/vm/drop_caches" 30 >/dev/null
  found=$(run "$NODE0" "echo C=\$(find $TD -mindepth 1 -maxdepth 1 -type d 2>/dev/null|wc -l)" 90 | sed -n 's/.*C=\([0-9]*\).*/\1/p' | head -1)
  found=${found:-0}; expected=$((M*DPN)); silent=$((expected-found)); [ "$silent" -lt 0 ] && silent=0
  # iSCSI conn-error count this step
  ce=0; for n in "${MOUNTED[@]}"; do c=$(run "$n" "dmesg 2>/dev/null|grep -c 'conn error (1020)'" 15|tr -cd '0-9'); ce=$((ce+${c:-0})); done
  # any FS shutdown / reservation conflict
  sd=0; for n in "${MOUNTED[@]}"; do run "$n" "dmesg 2>/dev/null|grep -qiE 'shut down|reservation conflict' && echo X" 15|grep -q X && sd=$((sd+1)); done
  verdict=PASS; [ "$M" -lt "$N" ] && verdict=MOUNT-WALL; [ "$silent" -gt 0 ] && verdict=SILENT-LOSS; [ "$sd" -gt 0 ] && verdict=SHUTDOWN
  echo "  N=$N RESULT: $verdict mounted=$M/$N expected=$expected found=$found silent=$silent conn_errs=$ce shutdown_nodes=$sd"
done
teardown_all >/dev/null 2>&1
echo "=== sweep done ==="
