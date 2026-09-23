#!/bin/bash
# leaf_scan_ab.sh — controlled A/B of the dir_leaf_scan_once knob (0.75.61):
# per-create cost as a private directory grows, knob toggled between runs on
# ONE warmed mount, in an alternating sequence so elapsed time and mount age
# cannot masquerade as the knob (the s542b/s542d pair was order-confounded:
# knob=1 first after prep 15 ms/create flat, knob=0 third 6-7 ms with two
# 2 s allocation-group release stalls inside).
#
# For each value in SEQ: write the knob on <node>, run
# tests/create_grow_probe.sh <node> <total> <batch>, and record CREATE_TOTAL,
# the first and last batch's per-create cost, and RMRF.  The knob is restored
# to its starting value at the end.
#
# the budget rule (derived): create_grow_probe bounds itself at total*30/1000+20 s
# per run; four runs of 2000 = 4 x (16-32 s) + rm ~4 s each.
#
# Usage: tests/leaf_scan_ab.sh <node> [total=2000] [batch=200] [seq="1 0 1 0"]
set -u
NODE=${1:?node}
TOTAL=${2:-2000}
BATCH=${3:-200}
SEQ=${4:-"1 0 1 0"}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
KNOB=/sys/module/mxfs/parameters/dir_leaf_scan_once
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
start=$(timeout 20 $SSH "$NODE" "cat $KNOB" 2>/dev/null | filt | tr -d '\n')
echo "=== leaf_scan_ab node=$NODE total=$TOTAL batch=$BATCH seq=[$SEQ] knob_start=$start sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
i=0
for v in $SEQ; do
    i=$((i+1))
    got=$(timeout 20 $SSH "$NODE" "echo $v > $KNOB && cat $KNOB" 2>/dev/null | filt | tr -d '\n')
    if [ "$got" != "$v" ]; then echo "  FAIL knob write: wanted $v got '$got'"; exit 3; fi
    out=$(tests/create_grow_probe.sh "$NODE" "$TOTAL" "$BATCH" 2>&1)
    tot=$(echo "$out" | grep -ao 'CREATE_TOTAL files=[0-9]* ms=[0-9]*' | grep -ao 'ms=[0-9]*' | cut -d= -f2)
    first=$(echo "$out" | grep -a 'BATCH b=0 ' | grep -ao 'per_create_us=[0-9]*' | cut -d= -f2)
    last=$(echo "$out" | grep -a 'BATCH ' | tail -1 | grep -ao 'per_create_us=[0-9]*' | cut -d= -f2)
    maxb=$(echo "$out" | grep -a 'BATCH ' | grep -ao 'per_create_us=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
    rm=$(echo "$out" | grep -ao 'RMRF files=[0-9]* ms=[0-9]*' | grep -ao 'ms=[0-9]*' | cut -d= -f2)
    evid=$(echo "$out" | grep -ao 'out=tests/evidence/[^ ]*probe.txt' | head -1 | cut -d= -f2)
    echo "  AB run=$i knob=$v create_total_ms=${tot:-?} first_batch_us=${first:-?} last_batch_us=${last:-?} max_batch_us=${maxb:-?} rmrf_ms=${rm:-?} evidence=${evid:-?}"
done
timeout 20 $SSH "$NODE" "echo ${start:-1} > $KNOB" >/dev/null 2>&1
echo "=== leaf_scan_ab done knob_restored=${start:-1} $(date -u +%FT%TZ) ==="
