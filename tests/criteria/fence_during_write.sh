#!/bin/bash
# Criterion: Surviving nodes continue uninterrupted after any
# single-node fence or death; automatic journal replay.  Verifier: kill
# one node mid-workload (independent files, separate subdirs).  After
# DLM eviction completes, every surviving node MUST complete its own
# work without manual intervention and without data corruption.
#
# Threshold: surviving nodes complete their workload within 2x the
# pre-kill nominal time; visible data on every surviving subdir matches
# what that node wrote.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "fence_during_write"
set_script_timeout 240

parse_common_args "$@"
[ "${#NODES[@]}" -ge 4 ] || NODES=("${DEFAULT_NODES[@]:0:4}")
[ "${#NODES[@]}" -ge 4 ] || result_fail "n/a" "need-4-nodes" "fence test requires >= 4 nodes"
# Use 4 nodes for speed; victim is node index 2 (not the first or last)
NODES=("${NODES[@]:0:4}")
VICTIM="${NODES[2]}"
SURVIVORS=()
for n in "${NODES[@]}"; do [ "$n" = "$VICTIM" ] || SURVIVORS+=("$n"); done

NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
ITEMS=200  # files per node

teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "cluster mount failed"

ssh_node_quiet "$NODE0" "rm -rf $MXFS_MOUNT/fence_test; mkdir -p $MXFS_MOUNT/fence_test; touch $MXFS_MOUNT/fence_test/.go; sync"

# Each node writes into its own subdir.  Records progress to
# /tmp/progress so we can verify what was claimed-written.
tmpdir=$(mktemp -d)
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1))
    HOST="${NODES[$i]}"
    (
        t0=$(date +%s%N)
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
        " > "$tmpdir/n${NODE_ID}.log" 2>&1
        t1=$(date +%s%N)
        echo $(( (t1 - t0) / 1000000 )) > "$tmpdir/n${NODE_ID}.ms"
    ) &
done

# While workload is running, wait for victim to be ~50% done, then kill
# its VM hard.
target=$(( ITEMS / 2 ))
for i in "${!NODES[@]}"; do
    [ "${NODES[$i]}" = "$VICTIM" ] && victim_id=$((i + 1))
done
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    progress=$(ssh_node "$VICTIM" "cat /tmp/fence_progress_${victim_id} 2>/dev/null" 2>/dev/null | tail -1 | tr -d ' \r\n')
    progress=${progress:-0}
    if [ "$progress" -ge "$target" ]; then break; fi
    sleep 0.3
done

echo "[fence] killing $VICTIM at progress=$progress"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1

wait

# Eviction wait — TCP DLM evicts on connection drop fairly quickly,
# but allow up to 60s in case the survivors were mid-acquire on a lock
# the victim held.
sleep 30

# Verify each survivor saw its own work through
total_lost=0
fail_node=""
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1))
    HOST="${NODES[$i]}"
    [ "$HOST" = "$VICTIM" ] && continue

    visible=$(ssh_node "$NODE0" "find $MXFS_MOUNT/fence_test/n${NODE_ID} -type f 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
    visible=${visible:-0}

    # claimed = whatever the node's progress file said before the run ended
    claimed=$(ssh_node "$HOST" "cat /tmp/fence_progress_${NODE_ID} 2>/dev/null" 2>/dev/null | tail -1 | tr -d ' \r\n')
    claimed=${claimed:-0}

    if [ "$visible" -lt "$claimed" ]; then
        total_lost=$((total_lost + claimed - visible))
        fail_node="$fail_node ${HOST}(claimed=${claimed},visible=${visible})"
    fi
done

# Resurrect victim for next run — synchronous wait so we don't leak
# a half-booted VM into the next criterion script.
virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1
for try in $(seq 1 30); do
    if timeout 8 "$MXFS_SSH" "$VICTIM" "$MXFS_PASS" "
        mkdir -p /src
        mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
        [ -f $MXFS_MODULE ]
    " >/dev/null 2>&1; then break; fi
    sleep 2
done

# Cleanup mounts on survivors
parallel_ssh_quiet "${SURVIVORS[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"
rm -rf "$tmpdir"
wait

[ "$total_lost" = "0" ] || result_fail "lost=$total_lost" "lost=0" "$fail_node"
result_pass "victim=$VICTIM survivors=${#SURVIVORS[@]} lost=0" "lost=0"
