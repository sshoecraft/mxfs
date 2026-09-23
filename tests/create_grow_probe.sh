#!/bin/bash
# create_grow_probe.sh — per-create cost as a directory grows (D-0349 pace).
#
# On <node>, in a fresh private directory under /mnt/shared, create <total>
# 4 KiB files in batches of <batch> and print the wall of every batch, so
# the shortform -> block -> leaf transitions show as steps in ms per create.
# Then rm -rf the directory and print that wall too.
#
# budget: measured 0.75.60 on the 2/tcp rig = 6-7 ms per create small, 13-22
# ms past ~400 entries, 27 s for 2000; the ssh bound below is 2x that.
#
# Usage: tests/create_grow_probe.sh <node> [total=2000] [batch=200]
set -u
NODE=${1:?node}
TOTAL=${2:-2000}
BATCH=${3:-200}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
BOUND=$(( TOTAL * 30 / 1000 + 20 ))
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_creategrow_$NODE
mkdir -p "$OUT"
echo "=== create_grow_probe node=$NODE total=$TOTAL batch=$BATCH bound=${BOUND}s out=$OUT $(date -u +%FT%TZ) ==="
timeout $BOUND "$SSH" "$NODE" "d=$MNT/grow_probe_\$(date +%s); mkdir -p \$d && cd \$d || exit 4;
sv=\$(cat /sys/module/mxfs/srcversion); echo SV=\$sv;
nb=\$(( $TOTAL / $BATCH )); tall=\$(date +%s%3N);
for b in \$(seq 0 \$((nb-1))); do t0=\$(date +%s%3N); for i in \$(seq 1 $BATCH); do head -c 4096 /dev/urandom > f\$((b*$BATCH+i)); done; t1=\$(date +%s%3N); echo \"BATCH b=\$b files=\$((b*$BATCH+$BATCH)) ms=\$((t1-t0)) per_create_us=\$(( (t1-t0)*1000/$BATCH ))\"; done;
tend=\$(date +%s%3N); echo \"CREATE_TOTAL files=\$(ls | wc -l) ms=\$((tend-tall))\";
cd / && t2=\$(date +%s%3N); rm -rf \$d; t3=\$(date +%s%3N); echo \"RMRF files=$TOTAL ms=\$((t3-t2))\"" 2>&1 | grep -av '^Unauthorized\|^Warning\|^If you\|^$' | tee "$OUT/probe.txt"
rc=${PIPESTATUS[0]}
echo "=== create_grow_probe rc=$rc out=$OUT/probe.txt $(date -u +%FT%TZ) ==="
exit $rc
