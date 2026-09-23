#!/bin/bash
# tests/d379b_dirty_depart_peer_fence.sh — sess433 verification for
# D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379 arm (B) and the
# LUN arm of D-LONE-NODE-CANNOT-REMOUNT-AFTER-OWN-DIRTY-SHUTDOWN-0355
# (record item 4: "force a node to depart with a dirty slice on an otherwise
# healthy cluster and assert (i) a survivor mints a fence certificate and
# replays the slice, (ii) a fresh mount is admitted — both WITHOUT re-mkfs").
#
# Shape (two nodes A, B on the shared LUN, everyone else unmounted):
#   1. fleet umount sweep (bounded, per-node rc);  mount A then B.
#   2. A: mkdir + fsync'd file, XFS_IOC_GOINGDOWN NOLOGFLUSH (only after
#      /proc/mounts proves the path is the mxfs mount), umount.
#      0.40.0 expectation on A: P277-SLOT-RETAINED-UNMOUNT-DIRTY and
#      P302-PR-KEY-RETAINED-FENCE-TARGET (key kept, NO P301 retire).
#   3. B: A's heartbeat goes stale (dead_timeout, 62 s default) -> B fences
#      A's RETAINED key: P236-FENCEKIND ... kind=PREEMPT_ABORT_DONE(16)
#      proves_excl=1, then replays A's slice (P163-RECOVERY-COMPLETE /
#      'foreign replay of slot N complete').  Pre-0.40.0 this was
#      KEY_ABSENT_UNPROVEN(6) forever (the sess379/sess432 brick).
#   4. A: plain mount again (NO single_node_exclusive): the plain REGISTER
#      must succeed because B's PREEMPT AND ABORT removed the predecessor
#      key (no P305), mrc=0, the fsync'd file is present.
#   5. teardown: umount both.
#
# PASS = p302>=1 on A, kind16>=1 and replay-complete>=1 on B, A remount mrc=0
#        file=1, zero P305 on the remount, zero 'in-use inode'/Corruption.
#
# derived time budget (measured components): sweep <=20 s, 2 mounts <=30 s,
# workload <5 s, death detection 62 s + fence + replay (node_death_replay
# measured replay terminal at kill+96 s) -> poll bound 120 s, remount <=20 s,
# teardown <=20 s  => caller bound 240 s.
#
# usage: tests/d379b_dirty_depart_peer_fence.sh <label> [A=test1] [B=test2] [nodes=32]
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}; NN=${4:-32}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$A"; LUN=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d379b_$LABEL
mkdir -p "$OUT"
MARK="D379B-$LABEL-$$"
T0=$(date +%s)
echo "=== d379b_dirty_depart_peer_fence label=$LABEL A=$A B=$B out=$OUT $(date -u +%FT%TZ) ==="

# 1. nobody mounted
for i in $(seq 1 "$NN"); do
  ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$OUT/umount_test$i.txt" 2>&1; echo "rc=$?" >> "$OUT/umount_test$i.txt" ) &
done
wait
STILL=$(grep -l '^1' "$OUT"/umount_test*.txt 2>/dev/null | wc -l)
echo "sweep: nodes still mounted after umount=$STILL"
[ "$STILL" = "0" ] || { echo "RESULT: FAIL | d379b | precondition: $STILL node(s) still mounted"; exit 1; }
sleep 3

# sess433: ARM the production enforcement knobs on both nodes (the sess407
# harness trap: with foreign_replay_token_enforce=0 the survivor runs the
# shadow-only evaluator and refuses by blanket policy even when every image
# WOULD_APPLY — measured on 0.40.1: manifest entries=8, WOULD_APPLY=9,
# still -117).
KN="echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce"
MA=$(timeout 25 $SSH "$A" "echo $MARK > /dev/kmsg; echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; $KN; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrcA=\$?" 2>/dev/null | tr '\n' ' ')
MB=$(timeout 25 $SSH "$B" "echo $MARK > /dev/kmsg; $KN; cat /sys/module/mxfs/parameters/foreign_replay_token_enforce | sed 's/^/enforce=/'; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrcB=\$?" 2>/dev/null | tr '\n' ' ')
echo "mounts: $MA $MB"
case "$MA$MB" in *"mrcA=0 "*"mrcB=0 "*) ;; *) echo "RESULT: FAIL | d379b | mounts: $MA $MB"; exit 1;; esac
sleep 4   # let B's membership settle (A must not be alone when it departs)

# 2. A departs DIRTY
R=$(timeout 60 $SSH "$A" "mkdir /mnt/shared/d379b_$LABEL 2>&1; echo mkdir_rc=\$?; python3 - <<'EOF'
import os, fcntl, struct, sys
ok=any(len(l.split())>2 and l.split()[1]=='/mnt/shared' and l.split()[2]=='mxfs' for l in open('/proc/mounts'))
if not ok:
    print('NOT-MXFS-MOUNT'); sys.exit(0)
fd=os.open('/mnt/shared/d379b_$LABEL/f1', os.O_CREAT|os.O_WRONLY, 0o644)
os.write(fd, b'x\n'); os.fsync(fd); os.close(fd); print('fsync-ok')
for k in range(2,6):
    fd=os.open('/mnt/shared/d379b_$LABEL/f%d'%k, os.O_CREAT|os.O_WRONLY, 0o644); os.write(fd, b'y\n'); os.close(fd)
dfd=os.open('/mnt/shared', os.O_RDONLY)
fcntl.ioctl(dfd, 0x8004587d, struct.pack('I', 2))   # GOINGDOWN NOLOGFLUSH
os.close(dfd); print('shutdown-ok')
EOF
umount /mnt/shared 2>&1; echo urcA=\$?; dmesg | sed -n '/$MARK/,\$p' | grep -a 'P277-\|P302-\|P301-\|P278-\|P163-WITHDRAW' | cut -c1-220" 2>/dev/null)
echo "A depart:"; echo "$R" | sed 's/^/  | /'
echo "$R" > "$OUT/A_depart.txt"
P302=$(grep -c 'P302-PR-KEY-RETAINED' "$OUT/A_depart.txt"); P301=$(grep -c 'P301-' "$OUT/A_depart.txt")
TDEP=$(date +%s)

# 3. B fences and replays.  Poll every 5 s, bound 120 s from the departure.
K16=0; RC=0; K6=0
for t in $(seq 1 24); do
  sleep 5
  BL=$(timeout 15 $SSH "$B" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P236-FENCEKIND\|P163-RECOVERY-COMPLETE\|foreign replay of slot\|P238-FENCE-UNPROVEN\|replayed=' | cut -c1-240" 2>/dev/null)
  echo "$BL" > "$OUT/B_fence_t$t.txt"
  K16=$(grep -c 'kind=PREEMPT_ABORT_DONE(16)' "$OUT/B_fence_t$t.txt"); K6=$(grep -c 'KEY_ABSENT_UNPROVEN' "$OUT/B_fence_t$t.txt")
  RC=$(grep -c 'P163-RECOVERY-COMPLETE\|foreign replay of slot [0-9]* complete' "$OUT/B_fence_t$t.txt")
  if [ "$RC" -ge 1 ]; then break; fi
  if [ "$K6" -ge 3 ]; then break; fi   # the pre-fix brick: unproven, will never advance
done
TF=$(( $(date +%s) - TDEP ))
echo "B fence/replay after ${TF}s (kind16=$K16 unproven6=$K6 replay_complete=$RC):"; cat "$OUT/B_fence_t$t.txt" | sed 's/^/  | /'

# 4. A remounts plainly
R2=$(timeout 40 $SSH "$A" "echo $MARK-REMOUNT > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrcA2=\$?; grep -q x /mnt/shared/d379b_$LABEL/f1 2>/dev/null && echo file=1 || echo file=0; dmesg | sed -n '/$MARK-REMOUNT/,\$p' | grep -a 'P305-\|P236-CLAIM\|ABORTED\|in-use inode\|Corruption' | cut -c1-220" 2>/dev/null)
echo "A remount:"; echo "$R2" | sed 's/^/  | /'
echo "$R2" > "$OUT/A_remount.txt"
P305=$(grep -c 'P305-' "$OUT/A_remount.txt"); BAD=$(grep -c 'in-use inode\|Corruption' "$OUT/A_remount.txt")

# 5. teardown
timeout 20 $SSH "$A" "umount /mnt/shared 2>&1; echo urcA3=\$?" 2>/dev/null | tr '\n' ' '
timeout 20 $SSH "$B" "umount /mnt/shared 2>&1; echo urcB=\$?" 2>/dev/null | tr '\n' ' '; echo
WALL=$(( $(date +%s) - T0 ))

OK=1
case "$R" in *"fsync-ok"*"shutdown-ok"*) case "$R2" in *"mrcA2=0"*"file=1"*) [ "$P302" -ge 1 ] && [ "$P301" = 0 ] && [ "$K16" -ge 1 ] && [ "$RC" -ge 1 ] && [ "$P305" = 0 ] && [ "$BAD" = 0 ] && OK=0;; esac;; esac
S="p302=$P302 p301=$P301 kind16=$K16 unproven6=$K6 replay_complete=$RC fence_wall=${TF}s p305=$P305 bad=$BAD wall=${WALL}s"
if [ $OK = 0 ]; then echo "RESULT: PASS | d379b_dirty_depart_peer_fence | $S"; else echo "RESULT: FAIL | d379b_dirty_depart_peer_fence | $S depart='$(echo $R | tr '\n' ' ' | cut -c1-200)' remount='$(echo $R2 | tr '\n' ' ' | cut -c1-200)'"; fi
exit $OK
