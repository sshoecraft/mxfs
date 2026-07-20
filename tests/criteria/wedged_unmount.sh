#!/bin/bash
# Criterion: No wedged unmounts (sysrq-b / virsh destroy not required).
# Verifier: drive a brief metadata storm on N nodes, then issue a clean
# `umount`.  Threshold: umount returns within 30s on every node AND no
# node needs sysrq-b/virsh-destroy to recover.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "wedged_unmount"
set_script_timeout 120

parse_common_args "$@"
[ "${#NODES[@]}" -gt 4 ] && NODES=("${NODES[@]:0:4}")
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
THRESH_MS=30000

teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "cluster mount failed"

# Brief metadata storm: 50 mkdir per node, parallel
ssh_node_quiet "$NODE0" "rm -rf $MXFS_MOUNT/wedge_test; mkdir -p $MXFS_MOUNT/wedge_test; touch $MXFS_MOUNT/wedge_test/.go; sync"
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1))
    HOST="${NODES[$i]}"
    ( ssh_node_quiet "$HOST" "
        for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/wedge_test/.go ] && break; sleep 0.5; done
        for k in \$(seq 1 50); do mkdir $MXFS_MOUNT/wedge_test/n${NODE_ID}_d\$k 2>/dev/null; done
        sync
    " ) &
done
wait

# Time the unmount on every node
tmpdir=$(mktemp -d)
for n in "${NODES[@]}"; do
    (
        t0=$(date +%s%N)
        timeout 60 "$MXFS_SSH" "$n" "$MXFS_PASS" "umount $MXFS_MOUNT" >/dev/null 2>&1
        rc=$?
        t1=$(date +%s%N)
        echo "rc=$rc ms=$(( (t1 - t0) / 1000000 ))" > "$tmpdir/${n}.r"
    ) &
done
wait

max_ms=0
fail_node=""
for n in "${NODES[@]}"; do
    r=$(cat "$tmpdir/${n}.r" 2>/dev/null)
    rc=$(echo "$r" | sed -n 's/.*rc=\([0-9]*\).*/\1/p')
    ms=$(echo "$r" | sed -n 's/.*ms=\([0-9]*\).*/\1/p')
    ms=${ms:-0}
    [ "$rc" = "0" ] || fail_node="$n (rc=$rc)"
    [ "$ms" -gt "$max_ms" ] && max_ms=$ms
done

# Confirm nothing still mounted (in parallel; sequential 60s timeouts would blow the script budget)
wedged=""
declare -A wedged_check
for n in "${NODES[@]}"; do
    ( ssh_node_quiet "$n" "mount | grep -q ' on $MXFS_MOUNT type mxfs'" && echo WEDGED > "$tmpdir/${n}.wedged" || echo OK > "$tmpdir/${n}.wedged" ) &
done
wait
for n in "${NODES[@]}"; do
    [ "$(cat "$tmpdir/${n}.wedged" 2>/dev/null)" = "WEDGED" ] && wedged="$wedged $n"
done
parallel_ssh_quiet "${NODES[*]}" "rmmod mxfs 2>/dev/null"

rm -rf "$tmpdir"

[ -z "$fail_node" ] || result_fail "max_umount=${max_ms}ms" "<=${THRESH_MS}ms" "umount failed on $fail_node"
[ -z "$wedged"    ] || result_fail "max_umount=${max_ms}ms" "<=${THRESH_MS}ms" "still mounted:$wedged"
[ "$max_ms" -le "$THRESH_MS" ] || result_fail "max_umount=${max_ms}ms" "<=${THRESH_MS}ms" "umount too slow"
result_pass "max_umount=${max_ms}ms" "<=${THRESH_MS}ms"
