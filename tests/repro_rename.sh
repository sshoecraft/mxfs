#!/bin/bash
# repro_rename.sh — minimal reproducer for the cross-node rename-visibility
# coherency residual (cache_coherency's test_rename_visibility, ~7% fail at 4 nodes).
#
# Each round, on a SHARED dir D, for ALL nodes concurrently:
#   - create N files  D/node<id>_before_<i>     (id = position in node list)
#   - barrier (settle)
#   - rename          D/node<id>_before_<i> -> _after_<i>
#   - barrier (settle)
#   - each node verifies ALL nodes' renames visible: every _before_ GONE, _after_ EXISTS.
#
# Usage: tests/repro_rename.sh [rounds] [N] [nodes_csv]   default: 5 10 test1,test2,test3,test4
set -u
ROUNDS="${1:-5}"
N="${2:-10}"
NODES_CSV="${3:-test1,test2,test3,test4}"
IFS=',' read -r -a NODES <<< "$NODES_CSV"
NN=${#NODES[@]}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
rn(){ timeout 50 "$SSH" "$1" "$PASS" "$2" 2>/dev/null|grep -vE 'Warning|Unauth|disconn|^$'; }

fails=0
for R in $(seq 1 "$ROUNDS"); do
    D="$MNT/rr_$$_$R"
    rn "${NODES[0]}" "mkdir -p $D; sync" >/dev/null
    # phase 1: each node creates its files concurrently
    for idx in "${!NODES[@]}"; do id=$((idx+1))
        ( rn "${NODES[$idx]}" "for i in \$(seq 1 $N); do echo c${id}_\$i > $D/node${id}_before_\$i; done 2>/dev/null; sync" >/dev/null ) & done
    wait
    # phase 2: each node renames its files concurrently
    for idx in "${!NODES[@]}"; do id=$((idx+1))
        ( rn "${NODES[$idx]}" "for i in \$(seq 1 $N); do mv $D/node${id}_before_\$i $D/node${id}_after_\$i 2>/dev/null; done; sync" >/dev/null ) & done
    wait
    # phase 3: every node verifies all nodes' renames IMMEDIATELY (no settle),
    # including FILE CONTENT (matches test_rename_visibility).
    rfail=0
    for node in "${NODES[@]}"; do
        miss=$(timeout 50 "$SSH" "$node" "$PASS" "
            f=0
            for owner in \$(seq 1 $NN); do
              for i in \$(seq 1 $N); do
                [ -e $D/node\${owner}_before_\$i ] && f=\$((f+1))
                [ -e $D/node\${owner}_after_\$i ] || { f=\$((f+1)); continue; }
                c=\$(cat $D/node\${owner}_after_\$i 2>/dev/null)
                [ \"\$c\" = \"c\${owner}_\$i\" ] || f=\$((f+1))
              done
            done
            echo \$f" 2>/dev/null | grep -vE 'Warning|Unauth|disconn|^$' | tail -1)
        if [ "${miss:-99}" != "0" ]; then
            echo "round $R: FAIL node=$node bad=$miss"
            rfail=$((rfail+1))
        fi
    done
    [ "$rfail" = 0 ] && echo "round $R: OK" || fails=$((fails+rfail))
    rn "${NODES[0]}" "rm -rf $D 2>/dev/null" >/dev/null
done
echo "=== repro_rename: $fails fail-events / $ROUNDS rounds ($NN nodes) ==="
exit $([ "$fails" = 0 ] && echo 0 || echo 1)
