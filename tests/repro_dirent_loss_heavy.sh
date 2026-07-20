#!/bin/bash
# repro_dirent_loss_heavy.sh — heavier variant of repro_dirent_loss.sh.
# N nodes EACH create K files concurrently in ONE shared directory, barrier,
# then every node verifies all N*K files are present.  The higher per-node
# fan-out (K) raises contention on the shared parent dir and reliably triggers
# the durable dirent lost-update that the 1-file/node repro only hits rarely
# (the zero_silent_loss storm's silent=11 residual).
#
# Usage: tests/repro_dirent_loss_heavy.sh [N] [K] [R]   (default N=16 K=50 R=4)
# Requires: cluster mounted on test1..testN, /tmp/.mxfs_pass present.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
N=${1:-16}
K=${2:-50}
R=${3:-4}
PASS=/tmp/.mxfs_pass
SSH="$SCRIPT_DIR/../tools/mxfs_sshpass.sh"
MNT=/mnt/shared
s() { timeout 60 "$SSH" "test$1" "$PASS" "$2" 2>/dev/null; }

total_lost=0
for r in $(seq 1 "$R"); do
    D="$MNT/.repro_dlh/round$r"
    B="$MNT/.repro_dlh/bar$r"
    s 1 "mkdir -p $D $B; sync"
    # All N nodes create K files each concurrently, then signal the barrier.
    for n in $(seq 1 "$N"); do
        s "$n" "until [ -d $D ]; do sleep 0.05; done; for k in \$(seq 1 $K); do mkdir $D/n${n}_f\$k 2>/dev/null; touch $D/n${n}_f\$k/m 2>/dev/null; done; sync; : > $B/done_$n" &
    done
    wait
    s 1 "for i in \$(seq 1 300); do c=\$(ls $B 2>/dev/null | grep -c done_); [ \"\$c\" -ge $N ] && break; sleep 0.1; done"
    # node1 counts visible vs expected; also enumerate which are missing.
    exp=$((N*K))
    got=$(s 1 "ls $D 2>/dev/null | grep -c '^n[0-9]'")
    got=${got:-0}
    lost=$((exp-got))
    echo "ROUND $r: expected=$exp visible=$got lost=$lost"
    if [ "$lost" -gt 0 ]; then
        # list first few missing names with creator
        s 1 "miss=0; for n in \$(seq 1 $N); do for k in \$(seq 1 $K); do [ -f $D/n\${n}_f\$k ] || { echo \"  MISSING n\${n}_f\$k\"; miss=\$((miss+1)); [ \$miss -ge 8 ] && break 2; }; done; done"
        total_lost=$((total_lost+lost))
    fi
done
echo "=== repro_dirent_loss_heavy done: N=$N K=$K R=$R total_lost=$total_lost ==="
[ "$total_lost" -eq 0 ] && echo "REPRO_RESULT: clean" || echo "REPRO_RESULT: REPRODUCED"
