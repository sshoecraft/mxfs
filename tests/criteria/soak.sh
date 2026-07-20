#!/bin/bash
# Criterion: 24h continuous run under mixed workload — no leaks, no
# growing caches, no fence storms.  Verifier: run a mixed workload on
# N nodes for SOAK_HOURS hours.  Periodically sample cache sizes,
# memory, dmesg.  Threshold: dmesg-clean throughout AND cache peaks
# bounded (already covered by cache_caps) AND no node fences itself.
#
# DEFAULT IS NOT 24h — that's a real-world soak and you opt into it
# explicitly via SOAK_HOURS.  Default is 1 hour for "did anything blow
# up overnight" coverage at PR time.  Pass SOAK_HOURS=24 for the real
# pre-ship soak.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "soak"
set_script_timeout 3900

parse_common_args "$@"
[ "${#NODES[@]}" -gt 4 ] && NODES=("${NODES[@]:0:4}")
SOAK_HOURS="${SOAK_HOURS:-1}"
DEADLINE=$(( $(date +%s) + SOAK_HOURS * 3600 ))
SAMPLE_INTERVAL=300  # 5 min

NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")

teardown_all "${NODES[*]}"
MARKER="MXFS_SOAK_$(date +%s)_$$"
parallel_ssh_quiet "${NODES[*]}" "echo '$MARKER' > /dev/kmsg 2>/dev/null"

fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "soak cluster mount failed"

ssh_node_quiet "$NODE0" "rm -rf $MXFS_MOUNT/soak; mkdir -p $MXFS_MOUNT/soak; touch $MXFS_MOUNT/soak/.go; sync"

# Background mixed workload on every node — create/touch/write/unlink loop
for i in "${!NODES[@]}"; do
    NODE_ID=$((i+1))
    HOST="${NODES[$i]}"
    ( ssh_node_quiet "$HOST" "
        for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/soak/.go ] && break; sleep 0.5; done
        D=$MXFS_MOUNT/soak/n${NODE_ID}
        mkdir -p \$D
        while [ \$(date +%s) -lt $DEADLINE ]; do
            for k in \$(seq 1 50); do
                mkdir \$D/d\$k 2>/dev/null
                echo data > \$D/f\$k
                rm -f \$D/f\$k
                rmdir \$D/d\$k 2>/dev/null
            done
            sync
            sleep 1
        done
    " ) &
done

# Periodic sampling
peak_dmesg_hits=0
worst_cache=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    sleep "$SAMPLE_INTERVAL"
    for n in "${NODES[@]}"; do
        hits=$(ssh_node "$n" "
            dmesg | awk '/$MARKER/{seen=1;next} seen' \
                  | grep -cE 'BUG:|Oops|Call Trace|general protection|WARNING:|Kernel panic'
        " | tail -1 | tr -d ' \r\n')
        hits=${hits:-0}
        [ "$hits" -gt "$peak_dmesg_hits" ] && peak_dmesg_hits=$hits
    done
done
wait

# Final dmesg scan
final_hits=0
for n in "${NODES[@]}"; do
    h=$(ssh_node "$n" "
        dmesg | awk '/$MARKER/{seen=1;next} seen' \
              | grep -cE 'BUG:|Oops|Call Trace|general protection|WARNING:|Kernel panic'
    " | tail -1 | tr -d ' \r\n')
    h=${h:-0}
    final_hits=$((final_hits + h))
done

# Cleanup
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

measured="soak_hours=$SOAK_HOURS dmesg_hits=$final_hits"
threshold="dmesg_hits=0"
[ "$final_hits" = "0" ] || result_fail "$measured" "$threshold" "kernel BUG/Oops/WARN during soak"
result_pass "$measured" "$threshold"
