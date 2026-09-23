#!/bin/bash
# tests/lone_rsync_bench.sh — the budget rule lone-node metadata bench (sess434).
#
# One node mounts the shared LUN ALONE (dlm_caw single_node=true) and rsyncs
# /root/open-gpu-kernel-modules (659 MB, 8714 files on test1) into a fresh
# directory, then syncs.  Prints the rsync wall and the sync wall.  Used to
# measure the cost of D-0354 candidate A (0.41.0: a lone node mints real
# on-disk CAW grants) against 0.40.1 (memory-only lone grants).
#
# derived time budget: fleet umount sweep 20 s, mount 15 s, rsync (native XFS ~4 s
# for ~700 MB; the multi-node mxfs parity is the expected ceiling, the budget rule's
# 2x-native ceiling is the pass line and is asserted here), sync, umount 20 s
# => caller bound 120 s.  rsync > 60 s is reported FAIL regardless.
#
# usage: tests/lone_rsync_bench.sh <label> [A=test1] [nodes=32]
set -u
LABEL=${1:?label}; A=${2:-test1}; NN=${3:-32}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
# the shared LUN as run.sh resolves it: MXFS_DEV overrides, /dev/sda is the
# 2-node TCP rig's default (the CAW multipath rig's is /dev/mapper/mpatha)
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$A"; LUN=$MXFS_DEV_RESOLVED
SRC=/root/open-gpu-kernel-modules
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lone_rsync_bench_$LABEL
mkdir -p "$OUT"
MARK="LRB-$LABEL-$$"
echo "=== lone_rsync_bench label=$LABEL A=$A sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') out=$OUT $(date -u +%FT%TZ) ==="
for i in $(seq 1 "$NN"); do
  ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$OUT/umount_test$i.txt" 2>&1; echo "rc=$?" >> "$OUT/umount_test$i.txt" ) &
done
wait
STILL=$(grep -l '^1' "$OUT"/umount_test*.txt 2>/dev/null | wc -l)
[ "$STILL" = "0" ] || { echo "RESULT: FAIL | lone_rsync_bench | precondition: $STILL node(s) still mounted"; exit 1; }
sleep 3
R=$(timeout 100 $SSH "$A" "echo $MARK > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; mrc=\$?; echo mrc=\$mrc; [ \$mrc = 0 ] || exit 0; dmesg | sed -n '/$MARK/,\$p' | grep -ac 'single_node = true' | sed 's/^/single=/'; D=/mnt/shared/lrb_$LABEL; mkdir -p \$D; t0=\$(date +%s.%N); timeout 60 rsync -a --no-compress $SRC/ \$D/tree/ 2>&1 | tail -3; echo rsync_rc=\${PIPESTATUS[0]}; t1=\$(date +%s.%N); sync; t2=\$(date +%s.%N); echo rsync_wall=\$(echo \"\$t1 - \$t0\" | bc) sync_wall=\$(echo \"\$t2 - \$t1\" | bc); echo files=\$(find \$D/tree -type f | wc -l); dmesg | sed -n '/$MARK/,\$p' | grep -acE 'Internal error|Corruption|SHUTDOWN|P130|P131|P243|stuck for' | sed 's/^/bad=/'; t3=\$(date +%s.%N); timeout 60 umount /mnt/shared; echo urc=\$?; t4=\$(date +%s.%N); echo umount_wall=\$(echo \"\$t4 - \$t3\" | bc)" 2>/dev/null | grep -v '^Warning\|^Unauthorized\|^If you')
echo "$R" | sed 's/^/  | /' | tee "$OUT/A.txt"
RW=$(echo "$R" | grep -o 'rsync_wall=[0-9.]*' | cut -d= -f2); SW=$(echo "$R" | grep -o ' sync_wall=[0-9.]*' | cut -d= -f2); UW=$(echo "$R" | grep -o 'umount_wall=[0-9.]*' | cut -d= -f2)
FILES=$(echo "$R" | grep -o 'files=[0-9]*' | cut -d= -f2); BAD=$(echo "$R" | grep -o 'bad=[0-9]*' | cut -d= -f2); MRC=$(echo "$R" | grep -o 'mrc=[0-9]*' | cut -d= -f2); RRC=$(echo "$R" | grep -o 'rsync_rc=[0-9]*' | cut -d= -f2); URC=$(echo "$R" | grep -o 'urc=[0-9]*' | cut -d= -f2)
ST=PASS
[ "${MRC:-1}" = 0 ] && [ "${RRC:-1}" = 0 ] && [ "${URC:-1}" = 0 ] && [ "${FILES:-0}" = 8714 ] && [ "${BAD:-1}" = 0 ] || ST=FAIL
python3 -c "import sys; sys.exit(0 if float('${RW:-999}') <= 60 else 1)" || ST=FAIL
echo "RESULT: $ST | lone_rsync_bench | label=$LABEL rsync_wall=${RW:-?}s sync_wall=${SW:-?}s umount_wall=${UW:-?}s files=${FILES:-?} bad=${BAD:-?} mrc=${MRC:-?} rsync_rc=${RRC:-?} urc=${URC:-?}"
[ "$ST" = PASS ]
