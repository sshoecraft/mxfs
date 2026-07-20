#!/bin/bash
# Criterion: Cluster ops (mount, unmount) complete in seconds, not
# minutes.  Verifier: time the first-node mount, all-nodes mount, and
# all-nodes unmount.  Threshold: first mount <=15s, additional mounts
# <=10s each, unmount <=10s per node.  These reflect the architecture:
# mount = read SB + init DLM + 3s discovery; unmount = flush + drop locks.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "cluster_ops_timing"
set_script_timeout 120

parse_common_args "$@"
# Default 4 nodes — enough to exercise mesh, not too slow
[ "${#NODES[@]}" -gt 4 ] && NODES=("${NODES[@]:0:4}")
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
N=${#NODES[@]}

THRESH_FIRST_MS=15000
THRESH_REST_MS=10000
THRESH_UMOUNT_MS=10000

teardown_all "${NODES[*]}"

# First-node mount timing
t0=$(date +%s%N)
out=$(ssh_node "$NODE0" "
    $MXFS_PREP >/tmp/prep.log 2>&1
    modprobe libcrc32c
    insmod $MXFS_MODULE
    echo y | $MXFS_MKFS $MXFS_DEV >/tmp/mkfs.log 2>&1
    mount -t mxfs ${MXFS_MOUNT_OPTS} $MXFS_DEV $MXFS_MOUNT && echo MOUNT_OK
")
t1=$(date +%s%N)
first_ms=$(( (t1 - t0) / 1000000 ))
echo "$out" | grep -q MOUNT_OK || result_fail "first=${first_ms}ms" "<=${THRESH_FIRST_MS}ms" "first mount failed"

# Additional-nodes mount, in parallel, time worst case
max_rest_ms=0
tmpdir=$(mktemp -d)
for n in "${REST[@]}"; do
    (
        t0=$(date +%s%N)
        ssh_node_quiet "$n" "
            $MXFS_PREP >/tmp/prep.log 2>&1
            modprobe libcrc32c
            insmod $MXFS_MODULE 2>/dev/null
            mount -t mxfs ${MXFS_MOUNT_OPTS} $MXFS_DEV $MXFS_MOUNT
        "
        t1=$(date +%s%N)
        echo $(( (t1 - t0) / 1000000 )) > "$tmpdir/${n}.ms"
    ) &
done
wait
for n in "${REST[@]}"; do
    m=$(cat "$tmpdir/${n}.ms" 2>/dev/null); m=${m:-0}
    [ "$m" -gt "$max_rest_ms" ] && max_rest_ms=$m
done

# Verify all actually mounted
for n in "${NODES[@]}"; do
    ssh_node_quiet "$n" "mount | grep -q ' on $MXFS_MOUNT type mxfs'" \
        || { rm -rf "$tmpdir"; result_fail "first=${first_ms}ms rest=${max_rest_ms}ms" "all-mounted" "$n not mounted"; }
done

# All-nodes umount, parallel
max_umount_ms=0
for n in "${NODES[@]}"; do
    (
        t0=$(date +%s%N)
        ssh_node_quiet "$n" "umount $MXFS_MOUNT 2>/dev/null"
        t1=$(date +%s%N)
        echo $(( (t1 - t0) / 1000000 )) > "$tmpdir/${n}.umount"
    ) &
done
wait
for n in "${NODES[@]}"; do
    m=$(cat "$tmpdir/${n}.umount" 2>/dev/null); m=${m:-0}
    [ "$m" -gt "$max_umount_ms" ] && max_umount_ms=$m
done
rm -rf "$tmpdir"

# Clean up modules
for n in "${NODES[@]}"; do
    ssh_node_quiet "$n" "rmmod mxfs 2>/dev/null"
done

measured="first=${first_ms}ms rest=${max_rest_ms}ms umount=${max_umount_ms}ms"
threshold="first<=${THRESH_FIRST_MS}ms rest<=${THRESH_REST_MS}ms umount<=${THRESH_UMOUNT_MS}ms"

[ "$first_ms" -le "$THRESH_FIRST_MS" ] || result_fail "$measured" "$threshold" "first-mount too slow"
[ "$max_rest_ms" -le "$THRESH_REST_MS" ] || result_fail "$measured" "$threshold" "additional-mount too slow"
[ "$max_umount_ms" -le "$THRESH_UMOUNT_MS" ] || result_fail "$measured" "$threshold" "umount too slow"
result_pass "$measured" "$threshold"
