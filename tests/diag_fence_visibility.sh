#!/bin/bash
# sess76 (ccloop 14d31183) DIAGNOSTIC for fence_during_write lost=400.
# Replicates the fence_during_write workload (4 nodes, each writes 200
# files into its own subdir of a shared parent dir, victim fenced at
# ~50%), then probes NODE0's visibility of the survivors' subdirs BOTH
# live and after drop_caches, and the survivors' self-view.  Goal: decide
# whether the lost=400 is (a) live cache staleness (drop_caches fixes it =
# coherency-invalidation bug, data durable) or (b) real data loss
# (drop_caches does not fix = fence-recovery/journal bug).  Leaves the
# cluster MOUNTED for inspection (no teardown).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"
result_init "diag_fence_visibility" 2>/dev/null || true

parse_common_args "$@"
[ "${#NODES[@]}" -ge 4 ] || NODES=("${DEFAULT_NODES[@]:0:4}")
NODES=("${NODES[@]:0:4}")
VICTIM="${NODES[2]}"
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
ITEMS=200

echo "NODES=${NODES[*]} VICTIM=$VICTIM NODE0=$NODE0"
teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" || { echo "MOUNT FAIL"; exit 1; }

ssh_node_quiet "$NODE0" "rm -rf $MXFS_MOUNT/fence_test; mkdir -p $MXFS_MOUNT/fence_test; touch $MXFS_MOUNT/fence_test/.go; sync"

for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1)); HOST="${NODES[$i]}"
    (
        ssh_node "$HOST" "
            for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/fence_test/.go ] && break; sleep 0.5; done
            mkdir -p $MXFS_MOUNT/fence_test/n${NODE_ID}
            : > /tmp/fence_progress_${NODE_ID}
            for k in \$(seq 1 $ITEMS); do
                printf 'data_n%d_k%d_%s' $NODE_ID \$k \"\$(date +%s%N)\" > $MXFS_MOUNT/fence_test/n${NODE_ID}/f\$k
                echo \$k > /tmp/fence_progress_${NODE_ID}
            done
            python3 -c \"import os
fd=os.open('$MXFS_MOUNT/fence_test/n${NODE_ID}', os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)\"
            echo DONE
        " > /tmp/diag_n${NODE_ID}.log 2>&1
    ) &
done

for i in "${!NODES[@]}"; do [ "${NODES[$i]}" = "$VICTIM" ] && victim_id=$((i + 1)); done
target=${KILL_AT:-30}   # kill EARLY (mid-transaction, holding dir locks)
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    progress=$(ssh_node "$VICTIM" "cat /tmp/fence_progress_${victim_id} 2>/dev/null" 2>/dev/null | tail -1 | tr -d ' \r\n')
    progress=${progress:-0}
    [ "$progress" -ge "$target" ] && break
    sleep 0.05
done
echo "[fence] killing $VICTIM at progress=$progress"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1
wait
echo "[fence] survivors workload done; waiting 30s for eviction"
sleep 30

echo "=================== VISIBILITY PROBE ==================="
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1)); HOST="${NODES[$i]}"
    [ "$HOST" = "$VICTIM" ] && { echo "n${NODE_ID} ($HOST): VICTIM (fenced)"; continue; }
    claimed=$(ssh_node "$HOST" "cat /tmp/fence_progress_${NODE_ID} 2>/dev/null" 2>/dev/null | tail -1 | tr -d ' \r\n'); claimed=${claimed:-0}
    live=$(ssh_node "$NODE0" "find $MXFS_MOUNT/fence_test/n${NODE_ID} -type f 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
    selfview=$(ssh_node "$HOST" "find $MXFS_MOUNT/fence_test/n${NODE_ID} -type f 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
    echo "n${NODE_ID} ($HOST): claimed=$claimed  NODE0_live=$live  selfview=$selfview"
done
echo "--- NODE0 sees these subdirs (live): ---"
ssh_node "$NODE0" "ls -la $MXFS_MOUNT/fence_test 2>&1 | tail -10"
echo "--- NODE0 drop_caches then re-probe ---"
ssh_node "$NODE0" "sync; echo 3 > /proc/sys/vm/drop_caches"
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1)); HOST="${NODES[$i]}"
    [ "$HOST" = "$VICTIM" ] && continue
    cold=$(ssh_node "$NODE0" "find $MXFS_MOUNT/fence_test/n${NODE_ID} -type f 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
    echo "n${NODE_ID} ($HOST): NODE0_cold(after drop_caches)=$cold"
done
echo "--- NODE0 subdirs after drop_caches: ---"
ssh_node "$NODE0" "ls -la $MXFS_MOUNT/fence_test 2>&1 | tail -10"
echo "=================== END PROBE (cluster left mounted) ==================="
virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1
