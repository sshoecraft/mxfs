#!/bin/bash
# Controlled cross_visibility reproducer with targeted instrumentation.
# (sess54) sess53 hypothesis: a reader fast-paths (P63, no reload) a STALE
# shortform dir after a peer adds an entry, instead of reloading (P13).
#
# KEY: instr=1's 100x slowdown HIDES the race (sess53). So we keep instr
# OFF during the create phase (preserve the bug-inducing timing) and flip
# it ON only for the read phase, which still logs the reader's P63/P13
# decision without perturbing whether the stale PR was cached earlier.
#
# Faithful to tests/cluster/test_cross_visibility.sh: ALL nodes mkdir -p
# the shared dir (so all cache it) then concurrently add their file.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

NODES_LIST=(test1 test2 test3 test4)
N=${#NODES_LIST[@]}
M="$MXFS_MOUNT"
ITERS="${1:-8}"

set_instr() { local v="$1"; for n in "${NODES_LIST[@]}"; do ssh_node_quiet "$n" "echo $v > /sys/module/mxfs/parameters/instr"; done; }

echo "=== teardown + fresh mount (instr=0; flipped on only for reads) ==="
teardown_all "${NODES_LIST[*]}"
INSMOD_OPTS="instr=0" fresh_cluster_mount "${NODES_LIST[0]}" "${NODES_LIST[@]:1}" \
    || { echo MOUNT_FAIL; exit 1; }

for it in $(seq 1 "$ITERS"); do
    CV="$M/.mxfs_test/cvrepro_$it"
    set_instr 0
    for n in "${NODES_LIST[@]}"; do ssh_node_quiet "$n" "dmesg -C"; done

    # phase 1 (instr OFF, full speed): all nodes mkdir -p then add their file
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        ssh_node "$n" "mkdir -p $CV 2>/dev/null; echo 'hello from node $i' > $CV/node$i.txt; sync" >/dev/null &
    done
    wait
    sleep 2   # matches the real test's settle

    DIRINO=$(ssh_node "${NODES_LIST[0]}" "stat -c %i $CV" | tr -dc '0-9')

    # phase 2 (instr ON): each node reads; record missing peers
    set_instr 1
    anymiss=0
    declare -A MISS
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        miss=$(ssh_node "$n" "for j in \$(seq 1 $N); do [ -f $CV/node\$j.txt ] || echo -n \"node\$j.txt \"; done")
        MISS[$i]="$miss"
        [ -n "$miss" ] && anymiss=1
    done
    set_instr 0

    if [ "$anymiss" = "0" ]; then
        echo "iter $it (dir ino=$DIRINO): all nodes see all files — PASS"
        continue
    fi

    echo "=== iter $it (dir ino=$DIRINO): FAILURE REPRODUCED ==="
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        echo "  node$i ($n) MISSING=[${MISS[$i]}]"
    done
    echo "--- dmesg (P63 fast / P13 reload / bast / STARVE) for dir ino=$DIRINO ---"
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        [ -z "${MISS[$i]}" ] && continue
        echo "  ===== reader node$i ($n) (missing ${MISS[$i]}) ====="
        ssh_node "$n" "dmesg | grep -aE 'ino=$DIRINO ' | grep -aE 'P63|P13|P68|bast_notify|ACQ-FRESH|FAST-PATH|SESS50' | tail -30"
    done
    echo "=== stopping at first reproduction ==="
    break
done
echo "=== DONE ==="
