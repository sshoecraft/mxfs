#!/bin/bash
# tests/unmount_flush_clean.sh — verification arm for
# D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER.
#
# A clean unmount of a PR-protected LUN must issue ZERO failed I/Os.  The
# defect: xfs_shutdown_devices() ends with an unconditional
# blkdev_issue_flush() on the data device, and it used to run AFTER the late
# SCSI-PR unregister, so the target rejected that flush:
#   "reservation conflict error, dev dm-1, sector 0 op 0x1:(WRITE) ...
#    Synchronize Cache(10) ... FAILED"
# Fixed in 0.11.354 by unregistering after xfs_shutdown_devices.
#
# DISCRIMINATOR (do not loosen): the bare SCSI notice
# "sd N:0:0:0: reservation conflict" is the NORMAL PR-probe artifact emitted
# at every mount on every healthy node.  Only the block-layer failed-I/O line
# "reservation conflict error, dev ..." indicates a rejected command.
#
# Bar: >= CYCLES clean umount/mount cycles per node across N nodes with zero
# failed-I/O lines.  Default 3 cycles x 8 nodes = 24 unmounts.
#
# Budget (RULE 0): a umount+prep_node cycle is ~10-15s/node; 3 cycles across
# 8 nodes run in parallel ~= 2.5 min.
#
# usage: unmount_flush_clean.sh [N=8] [cycles=3]
set -u
N="${1:-8}"
CYCLES="${2:-3}"
SSH=tools/mxfs_sshpass.sh
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
RID="ufc_$(date +%s)"
say() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

for n in "${NODES[@]}"; do $SSH "$n" "echo $RID > /dev/kmsg" >/dev/null 2>&1; done

say "running $CYCLES umount/mount cycles on $N nodes (build $(cat VERSION))"
for c in $(seq 1 "$CYCLES"); do
  for n in "${NODES[@]}"; do
    ( $SSH "$n" "umount /mnt/shared >/dev/null 2>&1; \
                 MXFS_DEV='$DEV' MXFS_KO_MD5='$KOMD5' \
                 bash /src/mxfs/tests/setup/prep_node.sh caw >/dev/null 2>&1" ) &
  done
  wait
  say "cycle $c/$CYCLES done"
done

FAILIO=0; NOTICES=0; UNMOUNTED=0
for n in "${NODES[@]}"; do
  out=$($SSH "$n" "F=\$(dmesg | sed -n \"/$RID/,\\\$p\" | grep -c 'reservation conflict error, dev'); \
                   P=\$(dmesg | sed -n \"/$RID/,\\\$p\" | grep -c 'reservation conflict'); \
                   M=\$(mount -t mxfs | grep -c shared); echo \$F \$P \$M" 2>/dev/null | tr -d '\r')
  read -r f p m <<<"$out"
  FAILIO=$(( FAILIO + ${f:-0} ))
  NOTICES=$(( NOTICES + ${p:-0} ))
  [ "${m:-0}" = 1 ] || UNMOUNTED=$((UNMOUNTED+1))
  [ "${f:-0}" -gt 0 ] && say "  $n: $f FAILED-I/O line(s)"
done

say "totals: failed_io=$FAILIO probe_notices=$NOTICES (expected, benign) nodes_not_mounted=$UNMOUNTED"
if [ "$FAILIO" -eq 0 ] && [ "$UNMOUNTED" -eq 0 ]; then
  echo "RESULT: PASS | case=unmount_flush_clean | $(( N * CYCLES )) clean unmounts, ZERO failed I/O (probe notices=$NOTICES are the normal PR-probe artifact)"
  exit 0
fi
echo "RESULT: FAIL | case=unmount_flush_clean | failed_io=$FAILIO over $(( N * CYCLES )) unmounts; nodes_not_mounted=$UNMOUNTED"
exit 1
