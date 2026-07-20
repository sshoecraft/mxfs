#!/bin/bash
# repro_dirent_loss.sh — isolate the cross_write_read durable dirent-loss
# (sess49 ccloop 14d31183).  N nodes concurrently create one file each in a
# SHARED directory, sync-barrier, then EVERY node verifies that ALL N files
# are present (lookup).  A missing dirent == the durable dir lost-update under
# concurrent same-dir create.  Loops R rounds to raise the repro rate.
#
# Usage: tests/repro_dirent_loss.sh [N] [R]   (default N=16 R=10)
# Requires: cluster already mounted on test1..testN, /tmp/.mxfs_pass present.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
N=${1:-16}
R=${2:-10}
PASS=/tmp/.mxfs_pass
SSH="$SCRIPT_DIR/../tools/mxfs_sshpass.sh"
MNT=/mnt/shared
s() { timeout 25 "$SSH" "test$1" "$PASS" "$2" 2>/dev/null; }

fails=0
for r in $(seq 1 "$R"); do
    D="$MNT/.repro_dl/round$r"
    # node1 makes the shared dir, everyone waits for it to appear
    s 1 "mkdir -p $D; sync"
    # barrier dir for sync
    B="$MNT/.repro_dl/bar$r"
    s 1 "mkdir -p $B; sync"
    # All N nodes create their file concurrently, then signal the barrier.
    for n in $(seq 1 "$N"); do
        s "$n" "until [ -d $D ]; do sleep 0.05; done; echo hello_from_$n > $D/f_$n; sync; : > $B/done_$n" &
    done
    wait
    # Wait until all N nodes have signalled (or 20s), so creates are durable.
    s 1 "for i in \$(seq 1 200); do c=\$(ls $B 2>/dev/null | grep -c done_); [ \"\$c\" -ge $N ] && break; sleep 0.1; done"
    # Every node verifies all N files are present + correct.
    for n in $(seq 1 "$N"); do
        out=$(s "$n" "miss=''; for k in \$(seq 1 $N); do if [ ! -f $D/f_\$k ]; then miss=\"\$miss \$k\"; fi; done; echo \"node$n missing:\$miss\"")
        if echo "$out" | grep -q "missing: *[0-9]"; then
            echo "ROUND $r FAIL: $out"
            fails=$((fails+1))
        fi
    done
done
echo "=== repro_dirent_loss done: N=$N R=$R total_fail_observations=$fails ==="
[ "$fails" -eq 0 ] && echo "REPRO_RESULT: clean" || echo "REPRO_RESULT: REPRODUCED"
