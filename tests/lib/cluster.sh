#!/bin/bash
# MXFS Test Framework — cluster.sh
# SSH wrappers, node enumeration, barriers, mount helpers

# ---------- Configuration ----------
MXFS_SSH_TOOL="${MXFS_SSH_TOOL:-/home/steve/src/mxfs/tools/mxfs_sshpass.sh}"
MXFS_PASS_FILE="${MXFS_PASS_FILE:-/home/steve/.mxfs/pass}"
MXFS_TESTS_DIR="${MXFS_TESTS_DIR:-/mnt/mxfs-src/tests}"
MXFS_MOUNT_POINT="${MXFS_MOUNT_POINT:-/mnt/shared}"
MXFS_DEVICE="${MXFS_DEVICE:-/dev/sdb}"
MXFS_BARRIER_TIMEOUT="${MXFS_BARRIER_TIMEOUT:-120}"

# ---------- Node enumeration ----------
get_node_hostname() {
    local num="$1"
    # sess46: optional MXFS_HOST_OFFSET lets the run use a different physical VM
    # set without renumbering test logic — e.g. MXFS_HOST_OFFSET=1 maps node-id
    # 1,2,3 -> test2,test3,test4 (to skip a broken test1). Default 0 = unchanged.
    echo "test$(( num + ${MXFS_HOST_OFFSET:-0} )).vm.localdomain"
}

get_node_list() {
    local total="$1"
    local nodes=""
    for i in $(seq 1 "$total"); do
        [ -n "$nodes" ] && nodes="$nodes "
        nodes="${nodes}test${i}.vm.localdomain"
    done
    echo "$nodes"
}

# ---------- SSH wrappers ----------
# Run command on a single node. Returns exit code of remote command.
ssh_node() {
    local node_num="$1"
    shift
    local cmd="$*"
    local host
    host=$(get_node_hostname "$node_num")
    "$MXFS_SSH_TOOL" "$host" "$MXFS_PASS_FILE" "$cmd"
}

# Run command on all N nodes in parallel, wait for all to complete.
# Returns 0 only if all nodes succeed.
ssh_all_nodes() {
    local total="$1"
    shift
    local cmd="$*"
    local pids=()
    local tmpdir
    tmpdir=$(mktemp -d /tmp/mxfs_ssh_all.XXXXXX)
    local rc=0

    for i in $(seq 1 "$total"); do
        local host
        host=$(get_node_hostname "$i")
        "$MXFS_SSH_TOOL" "$host" "$MXFS_PASS_FILE" "$cmd" \
            > "$tmpdir/node${i}.stdout" 2> "$tmpdir/node${i}.stderr" &
        pids+=($!)
    done

    for idx in "${!pids[@]}"; do
        local node_num=$((idx + 1))
        if ! wait "${pids[$idx]}"; then
            log_warn "Node $node_num failed: $(cat "$tmpdir/node${node_num}.stderr" 2>/dev/null)"
            rc=1
        fi
    done

    rm -rf "$tmpdir"
    return $rc
}

# Run command on all N nodes in parallel, capture stdout per node.
# Outputs: "NODE_NUM:stdout_line" for each line.
ssh_all_nodes_capture() {
    local total="$1"
    shift
    local cmd="$*"
    local pids=()
    local tmpdir
    tmpdir=$(mktemp -d /tmp/mxfs_ssh_cap.XXXXXX)

    for i in $(seq 1 "$total"); do
        local host
        host=$(get_node_hostname "$i")
        "$MXFS_SSH_TOOL" "$host" "$MXFS_PASS_FILE" "$cmd" \
            > "$tmpdir/node${i}.stdout" 2> "$tmpdir/node${i}.stderr" &
        pids+=($!)
    done

    for idx in "${!pids[@]}"; do
        wait "${pids[$idx]}" 2>/dev/null || true
    done

    for i in $(seq 1 "$total"); do
        if [ -f "$tmpdir/node${i}.stdout" ]; then
            while IFS= read -r line; do
                echo "${i}:${line}"
            done < "$tmpdir/node${i}.stdout"
        fi
    done

    rm -rf "$tmpdir"
}

# ---------- Mount helpers ----------
# Mount mxfs on a single node
mount_node() {
    local node_num="$1"
    local device="${2:-$MXFS_DEVICE}"
    local mount_point="${3:-$MXFS_MOUNT_POINT}"
    ssh_node "$node_num" "sudo mount -t mxfs $device $mount_point"
}

# Unmount mxfs on a single node
umount_node() {
    local node_num="$1"
    local mount_point="${2:-$MXFS_MOUNT_POINT}"
    ssh_node "$node_num" "sudo umount $mount_point 2>/dev/null; true"
}

# Mount mxfs on N nodes sequentially (node 1 first, then rest)
mount_all_nodes() {
    local total="$1"
    local device="${2:-$MXFS_DEVICE}"
    local mount_point="${3:-$MXFS_MOUNT_POINT}"

    # Mount node 1 first (it may need to do initial setup)
    log_info "Mounting node 1..."
    if ! mount_node 1 "$device" "$mount_point"; then
        log_fail "Failed to mount node 1"
        return 1
    fi
    sleep 1

    # Mount remaining nodes
    if [ "$total" -gt 1 ]; then
        log_info "Mounting nodes 2-${total}..."
        local pids=()
        for i in $(seq 2 "$total"); do
            mount_node "$i" "$device" "$mount_point" &
            pids+=($!)
        done
        local rc=0
        for idx in "${!pids[@]}"; do
            if ! wait "${pids[$idx]}"; then
                log_warn "Mount failed on node $((idx + 2))"
                rc=1
            fi
        done
        [ $rc -ne 0 ] && return 1
    fi

    # Wait for discovery to establish mesh
    local wait_sec=3
    [ "$total" -ge 8 ] && wait_sec=5
    [ "$total" -ge 16 ] && wait_sec=10
    log_info "Waiting ${wait_sec}s for discovery mesh..."
    sleep "$wait_sec"
    return 0
}

# Unmount mxfs on all N nodes
umount_all_nodes() {
    local total="$1"
    local mount_point="${2:-$MXFS_MOUNT_POINT}"
    ssh_all_nodes "$total" "sudo umount $mount_point 2>/dev/null; true"
}

# Check if a node has mxfs mounted
is_mounted() {
    local node_num="$1"
    local mount_point="${2:-$MXFS_MOUNT_POINT}"
    ssh_node "$node_num" "mountpoint -q $mount_point 2>/dev/null"
}

# Wait until mount appears on a node (timeout in seconds)
wait_for_mount() {
    local node_num="$1"
    local timeout="${2:-30}"
    local mount_point="${3:-$MXFS_MOUNT_POINT}"
    local elapsed=0
    while [ $elapsed -lt "$timeout" ]; do
        if is_mounted "$node_num" "$mount_point"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Verify all N nodes are mounted
verify_all_mounted() {
    local total="$1"
    local mount_point="${2:-$MXFS_MOUNT_POINT}"
    local rc=0
    for i in $(seq 1 "$total"); do
        if ! is_mounted "$i" "$mount_point"; then
            log_fail "Node $i not mounted at $mount_point"
            rc=1
        fi
    done
    return $rc
}

# ---------- Barriers ----------
# Barriers use a directory on the shared filesystem. Each node creates a marker
# file. A node waits until the expected number of markers exist.

barrier_create() {
    local name="$1"
    local barrier_dir="${MOUNT_POINT:?}/.mxfs_barriers/${name}"
    mkdir -p "$barrier_dir" 2>/dev/null
    echo "$barrier_dir"
}

barrier_signal() {
    local name="$1"
    local node_id="${2:-$NODE_ID}"
    local barrier_dir="${MOUNT_POINT:?}/.mxfs_barriers/${name}"
    mkdir -p "$barrier_dir" 2>/dev/null
    # sess42 diag: the probe-run cm_verify/ct_ready misses showed ONE node's
    # signal absent for every observer INCLUDING itself, with a 120s+ reload
    # BAIL storm (i_lock held) on the barrier dir.  Time the touch and check
    # its rc so the node log shows whether the signal write itself stalled
    # (create wedged in DLM/CAW) or failed outright.
    local t0 t1 rc
    t0=$(date +%s)
    touch "$barrier_dir/node${node_id}"
    rc=$?
    t1=$(date +%s)
    # Always record the signal's view: which dir incarnation we wrote into
    # (inode #), and whether our own entry is visible via lookup vs readdir.
    # A later timeout re-logs the same triple — a changed dir_ino proves the
    # concurrent-mkdir incarnation race; same ino with the readdir entry gone
    # proves a durable shortform lost update.
    local d_ino lk rd
    d_ino=$(stat -c %i "$barrier_dir" 2>/dev/null)
    [ -e "$barrier_dir/node${node_id}" ] && lk=1 || lk=0
    ls "$barrier_dir" 2>/dev/null | grep -qx "node${node_id}" && rd=1 || rd=0
    log_debug "barrier_signal '$name' node${node_id}: rc=$rc ${t1}-${t0}s dir_ino=$d_ino lookup=$lk readdir=$rd"
    if [ $rc -ne 0 ] || [ $((t1 - t0)) -ge 5 ] || [ "$rd" != 1 ]; then
        log_warn "barrier_signal '$name' node${node_id}: touch rc=$rc took $((t1 - t0))s dir_ino=$d_ino lookup=$lk readdir=$rd"
    fi
}

barrier_wait() {
    local name="$1"
    local expected="$2"
    local timeout="${3:-$MXFS_BARRIER_TIMEOUT}"
    local barrier_dir="${MOUNT_POINT:?}/.mxfs_barriers/${name}"
    local elapsed=0

    while [ $elapsed -lt "$timeout" ]; do
        local count
        count=$(find "$barrier_dir" -maxdepth 1 -name 'node*' 2>/dev/null | wc -l)
        count=$(echo "$count" | tr -d ' ')
        if [ "$count" -ge "$expected" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    # sess41 diag: on timeout, record WHICH node entries this observer sees,
    # so we can tell a lost signal-write (same node missing for everyone) from
    # a per-observer visibility gap (different node missing per observer).
    local present
    present=$(find "$barrier_dir" -maxdepth 1 -name 'node*' -printf '%f\n' 2>/dev/null | sed 's/node//' | sort -n | tr '\n' ',')
    # sess42: re-log this observer's own-signal view at timeout (pairs with
    # the barrier_signal line; see comment there).
    local d_ino lk rd
    d_ino=$(stat -c %i "$barrier_dir" 2>/dev/null)
    [ -e "$barrier_dir/node${NODE_ID:-0}" ] && lk=1 || lk=0
    ls "$barrier_dir" 2>/dev/null | grep -qx "node${NODE_ID:-0}" && rd=1 || rd=0
    log_warn "Barrier '$name' timed out after ${timeout}s (got $(find "$barrier_dir" -maxdepth 1 -name 'node*' 2>/dev/null | wc -l)/${expected}) observer=node${NODE_ID:-?} present=[${present}] dir_ino=$d_ino own_lookup=$lk own_readdir=$rd"
    return 1
}

barrier_cleanup() {
    local name="$1"
    rm -rf "${MOUNT_POINT:?}/.mxfs_barriers/${name}" 2>/dev/null
}

# ---------- Test working directory ----------
# Clean test working area on shared mount (run from coordinator or node 1)
clean_test_area() {
    local mount_point="${1:-$MXFS_MOUNT_POINT}"
    ssh_node 1 "rm -rf ${mount_point}/.mxfs_test ${mount_point}/.mxfs_results ${mount_point}/.mxfs_barriers 2>/dev/null; mkdir -p ${mount_point}/.mxfs_test ${mount_point}/.mxfs_results"
}

# Prepare results directory for a node
prepare_results_dir() {
    local node_id="$1"
    local mount_point="${2:-$MXFS_MOUNT_POINT}"
    mkdir -p "${mount_point}/.mxfs_results/node${node_id}" 2>/dev/null
}
