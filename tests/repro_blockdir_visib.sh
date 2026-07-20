#!/bin/bash
# sess120 (ccloop 4eef1f39): isolate the test_unlink_visibility failure —
# block-format shared-dir read coherency.  4 nodes each create N files in ONE
# shared dir (4*N entries => block format), barrier, then EVERY node counts how
# many of the 4*N files it sees.  A node seeing < 4*N = block-dir read staleness
# (peers' committed dirents invisible).  Then each node deletes its own and we
# check rm success.  instr=0 (race needs full speed).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

NODES_LIST=(test1 test2 test3 test4)
N=${#NODES_LIST[@]}
M="$MXFS_MOUNT"
FPN="${1:-30}"          # files per node
ITERS="${2:-5}"

echo "=== teardown + fresh mkfs/mount (instr=0) ==="
teardown_all "${NODES_LIST[*]}"
INSMOD_OPTS="instr=0" fresh_cluster_mount "${NODES_LIST[0]}" "${NODES_LIST[@]:1}" \
    || { echo MOUNT_FAIL; exit 1; }
for n in "${NODES_LIST[@]}"; do ssh_node_quiet "$n" "dmesg -C"; done

TOTAL=$((N * FPN))
fails=0
for it in $(seq 1 "$ITERS"); do
    D="$M/.mxfs_test/uv_$it"
    ssh_node "${NODES_LIST[0]}" "mkdir -p $D" >/dev/null 2>&1
    # phase 1: every node creates FPN files concurrently
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        ssh_node "$n" "for j in \$(seq 1 $FPN); do echo d_${i}_\$j > $D/node${i}_file\$j; done; sync" >/dev/null &
    done
    wait
    sleep 1
    # phase 2: every node counts visibility
    bad=0
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        cnt=$(ssh_node "$n" "ls $D/node*_file* 2>/dev/null | wc -l | tr -d ' '" 2>/dev/null)
        if [ "$cnt" != "$TOTAL" ]; then
            bad=1
            echo "iter $it: $n sees $cnt/$TOTAL"
        fi
    done
    # phase 3: each node deletes its own; report rm failures
    rmfail=0
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        rf=$(ssh_node "$n" "fc=0; for j in \$(seq 1 $FPN); do rm $D/node${i}_file\$j 2>/dev/null || fc=\$((fc+1)); done; echo \$fc" 2>/dev/null)
        [ "$rf" != "0" ] && { rmfail=1; echo "iter $it: $n rm-failures=$rf"; }
    done
    if [ "$bad" = "0" ] && [ "$rmfail" = "0" ]; then
        echo "iter $it: clean ($TOTAL visible on all, 0 rm-fail)"
    else
        fails=$((fails+1))
        echo "=== iter $it: ISSUE (visib_bad=$bad rmfail=$rmfail) — stopping ==="
        break
    fi
done
echo "=== DONE: $fails failing iter(s) of up to $ITERS ==="
