#!/bin/bash
# Criterion: Online add/remove node (mount/unmount nodes while others
# stay online).  Verifier: start with 2 nodes mounted, run a background
# write workload on node 1, mount a 3rd node mid-workload, then unmount
# it.  Threshold: 3rd node mounts within 15s; node 1's workload is
# never interrupted (no broken pipe / IO error in writer log).

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "online_membership"
set_script_timeout 180

parse_common_args "$@"
[ "${#NODES[@]}" -ge 3 ] || NODES=("${DEFAULT_NODES[@]:0:3}")
[ "${#NODES[@]}" -ge 3 ] || result_fail "n/a" "need-3-nodes" "needs >= 3 nodes"
NODES=("${NODES[@]:0:3}")
N1="${NODES[0]}"; N2="${NODES[1]}"; N3="${NODES[2]}"

teardown_all "${NODES[*]}"

# Start with N1 and N2
fresh_cluster_mount "$N1" "$N2" \
    || result_fail "n/a" "mount-ok" "initial cluster mount failed"

ssh_node_quiet "$N1" "rm -rf $MXFS_MOUNT/online_test; mkdir -p $MXFS_MOUNT/online_test"

# Background workload on N1: write 1000 files, 50ms each = 50s.  We log
# any non-zero exit so we can detect interruption.
( ssh_node "$N1" "
    : > /tmp/online_workload.err
    for k in \$(seq 1 1000); do
        if ! echo data > $MXFS_MOUNT/online_test/n1_f\$k 2>>/tmp/online_workload.err; then
            echo FAIL=\$k >> /tmp/online_workload.err
        fi
        usleep 50000
    done
    echo DONE
" >/tmp/n1_workload.log 2>&1 ) &
WL=$!

# Let workload run a few seconds, then mount N3
sleep 3
t0=$(date +%s%N)
out=$(ssh_node "$N3" "
    $MXFS_PREP >/tmp/prep.log 2>&1
    modprobe libcrc32c
    insmod $MXFS_MODULE 2>/dev/null
    mount -t mxfs ${MXFS_MOUNT_OPTS} $MXFS_DEV $MXFS_MOUNT && echo MOUNT_OK
")
t1=$(date +%s%N)
mount_ms=$(( (t1 - t0) / 1000000 ))
echo "$out" | grep -q MOUNT_OK \
    || { kill -9 $WL 2>/dev/null; result_fail "mount_ms=$mount_ms" "<=15000ms" "N3 mount failed"; }

# Let N3 do some work too while N1 keeps going
ssh_node_quiet "$N3" "
    for k in \$(seq 1 100); do echo data > $MXFS_MOUNT/online_test/n3_f\$k; done
    sync
"

# Unmount N3 mid-workload
ssh_node_quiet "$N3" "umount $MXFS_MOUNT"
n3_still=$(ssh_node "$N3" "mount | grep -c ' on $MXFS_MOUNT type mxfs'" | tail -1 | tr -d ' \r\n')
ssh_node_quiet "$N3" "rmmod mxfs 2>/dev/null"

# Wait for N1 workload to finish
wait $WL || true

# Check N1 workload didn't see any I/O failures
errs=$(ssh_node "$N1" "cat /tmp/online_workload.err 2>/dev/null | wc -l" | tail -1 | tr -d ' \r\n')
errs=${errs:-0}
done_marker=$(grep -c '^DONE' /tmp/n1_workload.log 2>/dev/null); done_marker=${done_marker:-0}

# Cleanup
for n in "$N1" "$N2"; do
    ssh_node_quiet "$n" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"
done

measured="n3_mount_ms=$mount_ms n1_errs=$errs n1_done=$done_marker n3_still_mounted=$n3_still"
threshold="n3_mount_ms<=15000 n1_errs=0 n1_done=1 n3_still_mounted=0"

[ "$mount_ms" -le 15000 ] || result_fail "$measured" "$threshold" "online add too slow"
[ "$errs" = "0" ]         || result_fail "$measured" "$threshold" "N1 workload saw errors during membership change"
[ "$done_marker" = "1" ]  || result_fail "$measured" "$threshold" "N1 workload didn't complete"
[ "$n3_still" = "0" ]     || result_fail "$measured" "$threshold" "N3 didn't actually unmount"
result_pass "$measured" "$threshold"
