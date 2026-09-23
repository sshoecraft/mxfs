#!/bin/bash
# cross_grant_workload.sh — leave the two-node TCP rig with many live grants
# whose master is the PEER, then hand back.  A workload for tests/unload_laps.sh
# (WORKLOAD=tests/cross_grant_workload.sh), not a verdict on the filesystem.
#
# Why: a concurrent whole-cluster unmount only shows the release drop at a
# tearing-down master (D-0925 mechanism 2) when each node still holds grants
# the peer masters.  An idle mount holds a handful; the AG-meta reproducer
# leaves one or two.  Here every node creates COUNT files in a directory of
# its own (an EX grant per inode, cached until a BAST or the tenure ends)
# and then stats every file the peer created (a PR grant per peer inode).
# Inode resources hash to ledger pages that the two nodes master half each,
# so ~half of every node's grants are addressed to the peer at unmount.
# Nothing is removed: a removal would release the grants this leaves.
#
# the budget rule (derived): COUNT creates at 7-20 ms each on the two-node rig =
# 2-6 s per node, concurrent; COUNT peer stats at ~5 ms = 1.5 s; both bounded
# at 60 s.  Healthy wall ~10 s for COUNT=300.
#
# Usage: tests/cross_grant_workload.sh <label> [COUNT=300]
# Env:   MXFS_NODE_LIST (default test1,test2), MNT=/mnt/shared
set -u
LABEL=${1:?label}
COUNT=${2:-300}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
D=$MNT/xgrant_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_xgrant_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

echo "=== cross_grant_workload label=$LABEL A=$A B=$B count=$COUNT sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
ck "both nodes mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"

# Stage 1: each node creates COUNT one-block files in its own directory.
create_one() {  # <node>
    rs 60 "$1" "mkdir -p $D/$1 && s=\$(date +%s%N); i=0; while [ \$i -lt $COUNT ]; do echo \$i > $D/$1/f\$i || echo CREATE_ERR i=\$i; i=\$((i+1)); done; sync -f $MNT; e=\$(date +%s%N); echo CREATE node=$1 n=\$i wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/create_$1.txt"
}
create_one "$A" & create_one "$B" & wait
for n in $A $B; do echo "  INFO $(tr '\n' ' ' < "$OUT/create_$n.txt")"; done
ck "every create returned on both nodes" "$(cat "$OUT"/create_*.txt | grep -ac CREATE_ERR)" "0"

# Stage 2: each node stats every file the peer created (a PR grant per
# peer inode, plus the peer directory's PR).
stat_peer() {  # <node> <peer>
    rs 60 "$1" "s=\$(date +%s%N); n=\$(stat -c %i $D/$2/f* 2>/dev/null | wc -l); e=\$(date +%s%N); echo PEERSTAT node=$1 peer=$2 seen=\$n wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/stat_$1.txt"
}
stat_peer "$A" "$B" & stat_peer "$B" "$A" & wait
for n in $A $B; do echo "  INFO $(tr '\n' ' ' < "$OUT/stat_$n.txt")"; done
ck "$A sees every file $B created" "$(grep -ao 'seen=[0-9]*' "$OUT/stat_$A.txt")" "seen=$COUNT"
ck "$B sees every file $A created" "$(grep -ao 'seen=[0-9]*' "$OUT/stat_$B.txt")" "seen=$COUNT"

# The DLM's own count of what each node holds, from the sysfs/debug stats
# line the departure prints later; here the harness just records the wall.
wall=$(( $(date +%s) - s ))
echo "  XGRANT-MEASURE label=$LABEL count=$COUNT wall_s=$wall $(for n in $A $B; do grep -ao 'wall_ms=[0-9]*' "$OUT/create_$n.txt" | sed "s/^/${n}_create_/"; grep -ao 'wall_ms=[0-9]*' "$OUT/stat_$n.txt" | sed "s/^/${n}_stat_/"; done | tr '\n' ' ')"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
