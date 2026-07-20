#!/bin/bash
# repro_modea.sh — minimal, fast reproducer for the Mode A concurrent
# same-path-mkdir coherency bug that fails cache_coherency / the barrier
# machinery (`got 1/2`).
#
# Each iteration:
#   - both nodes concurrently:  mkdir -p $DIR ; touch $DIR/node<N> ; sync
#   - then each node lists $DIR and must see BOTH node1 and node2.
# A divergence (a node missing the peer's marker, or the two nodes
# reporting different dir inode numbers) is the Mode A bug.
#
# Usage: tests/repro_modea.sh [iters] [node1] [node2]
set -u
ITERS="${1:-20}"
N1="${2:-test1}"
N2="${3:-test2}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared

ssh1() { timeout 40 "$SSH" "$N1" "$PASS" "$*" 2>&1 | grep -vE 'Warning|Unauthorized|disconnect|^$'; }
ssh2() { timeout 40 "$SSH" "$N2" "$PASS" "$*" 2>&1 | grep -vE 'Warning|Unauthorized|disconnect|^$'; }

fails=0
for i in $(seq 1 "$ITERS"); do
    P="$MNT/modea_$$_$i"
    ( timeout 40 "$SSH" "$N1" "$PASS" "mkdir -p $P 2>/dev/null; touch $P/node1; sync" >/dev/null 2>&1 ) &
    ( timeout 40 "$SSH" "$N2" "$PASS" "mkdir -p $P 2>/dev/null; touch $P/node2; sync" >/dev/null 2>&1 ) &
    wait
    # Give the cluster a moment, then read from both nodes.
    s1=$(ssh1 "ls $P/ 2>/dev/null | tr '\n' ',' ; echo -n '|'; stat -c %i $P 2>/dev/null")
    s2=$(ssh2 "ls $P/ 2>/dev/null | tr '\n' ',' ; echo -n '|'; stat -c %i $P 2>/dev/null")
    l1="${s1%%|*}"; i1="${s1##*|}"
    l2="${s2%%|*}"; i2="${s2##*|}"
    ok=1
    echo "$l1" | grep -q node1 && echo "$l1" | grep -q node2 || ok=0
    echo "$l2" | grep -q node1 && echo "$l2" | grep -q node2 || ok=0
    [ "$i1" = "$i2" ] || ok=0
    if [ "$ok" = "1" ]; then
        echo "iter $i: OK (ino=$i1)"
    else
        fails=$((fails+1))
        echo "iter $i: FAIL  n1=[$l1] ino1=$i1   n2=[$l2] ino2=$i2"
    fi
done
echo "=== repro_modea: $fails/$ITERS failed ==="
exit $([ "$fails" = 0 ] && echo 0 || echo 1)
