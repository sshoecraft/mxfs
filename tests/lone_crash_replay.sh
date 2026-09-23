#!/bin/bash
# tests/lone_crash_replay.sh — sess432 directed measurement for
# D-SINGLENODE-ERA-EPOCH0-IMAGES-UNREPLAYABLE-AFTER-LONE-CRASH-0354.
#
# Shape (design-consult ruling sess432, Q4): node A mounts the shared LUN ALONE
# (dlm_caw single_node=true — its journal images carry authority epoch 0),
# does mkdir + create + fsync (acknowledged, durable in ITS log slice, not
# necessarily home), and is POWER-CYCLED (virsh destroy) before any peer
# joins.  Node B then mounts, must recover A's slice as a foreign slice under
# the requested enforcement knobs, and the fsync'd file must exist.
#
#   arm enforce0 : B mounts with foreign_replay_token_enforce=0 (blanket policy)
#   arm enforce1 : B mounts with target_cache_protected=1
#                  foreign_replay_token_enforce=1 (the sess404 production default)
#
# PASS = B's mount succeeds, the slice is replayed (no POLICY-REFUSED, no
#        quarantine, no FR-FAIL), the file is present with its content.
# FAIL = anything else.  The verdict lines are printed either way.
#
# derived time budget: fleet umount sweep 20 s, A mount 15 s, workload 2 s, destroy
# 5 s, dead-confirm ~62 s (heartbeat window) + fence + replay ~5 s, B mount
# barrier <= 30 s  => caller bound 200 s.  A is restarted at the end.
#
# usage: tests/lone_crash_replay.sh <label> [A=test1] [B=test2] [nodes=32] [arm=enforce1]
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}; NN=${4:-32}; ARM=${5:-enforce1}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$A"; LUN=$MXFS_DEV_RESOLVED
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lone_crash_replay_${LABEL}_$ARM
mkdir -p "$OUT"
MARK="LCR-$LABEL-$$"
echo "=== lone_crash_replay label=$LABEL A=$A B=$B arm=$ARM out=$OUT $(date -u +%FT%TZ) ==="

case "$ARM" in
  enforce0) KN="echo 0 > $P/foreign_replay_token_enforce";;
  enforce1) KN="echo 1 > $P/target_cache_protected && echo 1 > $P/foreign_replay_token_enforce";;
  *) echo "RESULT: FAIL | lone_crash_replay | unknown arm '$ARM'"; exit 1;;
esac

# 1. nobody mounted
for i in $(seq 1 "$NN"); do
  ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$OUT/umount_test$i.txt" 2>&1; echo "rc=$?" >> "$OUT/umount_test$i.txt" ) &
done
wait
STILL=$(grep -l '^1' "$OUT"/umount_test*.txt 2>/dev/null | wc -l)
[ "$STILL" = "0" ] || { echo "RESULT: FAIL | lone_crash_replay | precondition: $STILL node(s) still mounted"; exit 1; }
sleep 3

# 2. A alone: mount, workload, fsync, then power-cycle
RA=$(timeout 40 $SSH "$A" "echo $MARK > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrc=\$?; dmesg | sed -n '/$MARK/,\$p' | grep -ac 'single_node = true'; mkdir /mnt/shared/lcr_$LABEL 2>&1; echo mkdir_rc=\$?; python3 -c \"
import os
fd=os.open('/mnt/shared/lcr_$LABEL/f1', os.O_CREAT|os.O_WRONLY, 0o644); os.write(fd, b'lone-era-$LABEL\n'); os.fsync(fd); os.close(fd)
d=os.open('/mnt/shared/lcr_$LABEL', os.O_RDONLY); os.fsync(d); os.close(d)
print('fsync-ok')\" 2>&1; cat $P/foreign_replay_token_enforce" 2>/dev/null | tr '\n' ' ')
echo "A workload: $RA"
case "$RA" in *"mrc=0 "*"mkdir_rc=0 fsync-ok"*) ;; *) echo "RESULT: FAIL | lone_crash_replay | A workload failed: '$RA'"; timeout 20 $SSH "$A" "umount /mnt/shared" >/dev/null 2>&1; exit 1;; esac
# sess434: A's journal is VOLATILE (destroyed below) — capture its mount/log
# evidence first: adopted-slice notice, P308 incarnation boundary, P309 log
# tail geometry, single-node/grant lines.
timeout 25 $SSH "$A" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'adopted log slice\|P308\|P309\|single_node\|P243\|P130\|P131\|claimed heartbeat slot\|Ending \|log mount' | cut -c1-300" > "$OUT/A_pre_destroy.txt" 2>/dev/null
echo "A pre-destroy: $(grep -a 'P308\|P309\|adopted\|claimed heartbeat' "$OUT/A_pre_destroy.txt" | cut -c1-200 | tr '\n' ' ')"
KILL_T=$(date -u +%FT%T.%3NZ)
timeout 60 sudo virsh -c qemu:///system destroy "$A" > "$OUT/kill.txt" 2>&1; echo "destroy $A rc=$? at $KILL_T" | tee -a "$OUT/kill.txt"

# 3. B mounts with the arm's knobs; the mount barrier / settle must recover A's slice
RB=$(timeout 120 $SSH "$B" "$KN 2>&1 && echo knobs_ok; cat $P/target_cache_protected $P/foreign_replay_token_enforce | tr '\n' ','; echo $MARK-B > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrc=\$?; grep -a 'lone-era-$LABEL' /mnt/shared/lcr_$LABEL/f1 >/dev/null 2>&1 && echo file=1 || echo file=0" 2>/dev/null | tr '\n' ' ')
echo "B mount: $RB"
# 4. B may have mounted before A's death was confirmed (~62 s window): wait for a terminal replay verdict
W=0; V=""
while [ $W -lt 90 ]; do
  V=$(timeout 15 $SSH "$B" "dmesg | sed -n '/$MARK-B/,\$p' | grep -a 'P273-SHADOW-EVAL\|POLICY-REFUSED\|quarantin\|FR-FAIL\|P163-RECOVERY-COMPLETE\|foreign slice.*replay\|replayed=\|recovery complete' | cut -c1-240" 2>/dev/null)
  # sess435: 'quarantin' also matches the barrier line's 'quarantined=0x0' (false FAIL on a real pass)
  echo "$V" | grep -a 'P163-RECOVERY-COMPLETE\|POLICY-REFUSED\|quarantin\|FR-FAIL' | grep -aqv 'quarantined=0x0' && break
  sleep 5; W=$((W+5))
done
FILE2=$(timeout 15 $SSH "$B" "grep -a 'lone-era-$LABEL' /mnt/shared/lcr_$LABEL/f1 >/dev/null 2>&1 && echo file=1 || echo file=0; ls /mnt/shared/lcr_$LABEL 2>&1 | head -3" 2>/dev/null | tr '\n' ' ')
echo "verdict wait ${W}s; file after recovery: $FILE2"
echo "$V" > "$OUT/verdict_$B.txt"; cat "$OUT/verdict_$B.txt"
timeout 25 $SSH "$B" "dmesg | sed -n '/$MARK-B/,\$p' | cut -c1-300" > "$OUT/dmesg_$B.txt" 2>/dev/null
REF=$(grep -ac 'POLICY-REFUSED' "$OUT/dmesg_$B.txt"); QUAR=$(grep -a 'quarantin' "$OUT/dmesg_$B.txt" | grep -avc 'quarantined=0x0'); FRF=$(grep -ac 'FR-FAIL' "$OUT/dmesg_$B.txt"); RC=$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/dmesg_$B.txt")

# 5. teardown: B umount, knobs restored, A restarted for the next prep
timeout 20 $SSH "$B" "umount /mnt/shared 2>&1; echo urc=\$?; echo 0 > $P/foreign_replay_token_enforce 2>/dev/null; echo 0 > $P/target_cache_protected 2>/dev/null" 2>/dev/null | tr '\n' ' '; echo
timeout 60 sudo virsh -c qemu:///system start "$A" >> "$OUT/kill.txt" 2>&1; echo "restart $A rc=$?"
OK=1
case "$RB" in *"knobs_ok"*"mrc=0 "*) [ "$REF" = 0 ] && [ "$QUAR" = 0 ] && [ "$FRF" = 0 ] && [ "$RC" -ge 1 ] && case "$FILE2" in *file=1*) OK=0;; esac;; esac
if [ $OK = 0 ]; then echo "RESULT: PASS | lone_crash_replay arm=$ARM | refused=$REF quarantine=$QUAR frfail=$FRF complete=$RC $FILE2"; else echo "RESULT: FAIL | lone_crash_replay arm=$ARM | refused=$REF quarantine=$QUAR frfail=$FRF complete=$RC B='$RB' $FILE2"; fi
echo "=== lone_crash_replay $LABEL $ARM done out=$OUT $(date -u +%FT%TZ) ==="
exit $OK
