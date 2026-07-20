#!/bin/bash
# MXFS Ship-Criteria Verifier Library
#
# Shared helpers for the per-criterion verifier scripts under
# tests/criteria/.  Each criterion script sources this file, drives
# the test, and emits one line:
#
#   RESULT: PASS  criterion=<name>  measured=<value>  threshold=<value>
#   RESULT: FAIL  criterion=<name>  measured=<value>  threshold=<value>  reason=...
#
# Exit 0 = PASS, nonzero = FAIL.
#
# Threshold rule:  pick the threshold that reflects what the workload
# *should* take given the architecture, not an arbitrary "big enough"
# cap.  Single-node rsync of 8K files on this LUN is ~4s; the 2-node
# variant must finish in roughly the same wall (not 30s).  If a criterion
# routinely runs much longer than expected, that's structural breakage —
# investigate, don't widen the threshold.

set -u

# ---------- Coordinator-side paths ----------
: "${MXFS_REPO:=/src/mxfs}"
: "${MXFS_MODULE:=${MXFS_REPO}/mxfs.ko}"
: "${MXFS_MKFS:=${MXFS_REPO}/tools/mkfs_mxfs}"
: "${MXFS_CHK:=${MXFS_REPO}/tools/chk_mxfs}"
: "${MXFS_RESIZE:=${MXFS_REPO}/tools/resize_mxfs}"
: "${MXFS_PREP:=${MXFS_REPO}/tools/prep_tcm_node_scst.sh}"
: "${MXFS_SSH:=${MXFS_REPO}/tools/mxfs_sshpass.sh}"
: "${MXFS_PASS:=/tmp/.mxfs_pass}"
: "${MXFS_BENCH_JSON:=${MXFS_REPO}/bench.json}"

# ---------- Node-side paths ----------
: "${MXFS_MOUNT:=/mnt/shared}"
: "${MXFS_DEV:=/dev/sda}"

# ---------- Mount transport (v5 vs mxfs.1) ----------
# mxfs.1 selected DLM transport via a mount option:  -o dlm_transport=tcp.
# v5 (this repo) has NO such mount option — transport is chosen by the
# `force_transport` module param (0 = auto, default CAW; 1 = TCP), and
# the canonical v5 config is plain CAW with no extra mount opts.  So
# MXFS_MOUNT_OPTS defaults to empty here.  To force TCP on v5, load the
# module with `INSMOD_OPTS=force_transport=1` instead of a mount opt.
: "${MXFS_MOUNT_OPTS:=}"

# ---------- Default node pool (test1-test16 = mxfs v5 cluster) ----------
# v5 uses test1..test16; mxfs.1 uses test17..test32.  Do NOT point this at
# the .1 pool or the verifiers will clobber the other project's cluster.
DEFAULT_NODES=(test1 test2 test3 test4 test5 test6 test7 test8
               test9 test10 test11 test12 test13 test14 test15 test16)

# ---------- Result reporting ----------
# Every result_pass / result_fail also persists to a JSON file in the
# repo so the model can pick up where it left off across sessions
# without re-running already-green criteria.
: "${CRITERIA_RESULTS_FILE:=${MXFS_REPO}/.criteria_results.json}"
CRITERION_NAME=""
result_init() { CRITERION_NAME="$1"; }

_persist_result() {
    local status="$1" measured="$2" threshold="$3" reason="${4:-}"
    command -v jq >/dev/null 2>&1 || return 0
    [ -f "$CRITERIA_RESULTS_FILE" ] || echo '{}' > "$CRITERIA_RESULTS_FILE"
    local now
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local tmp
    tmp=$(mktemp)
    jq --arg n "$CRITERION_NAME" \
       --arg s "$status" \
       --arg t "$now" \
       --arg m "$measured" \
       --arg th "$threshold" \
       --arg r "$reason" \
       '.[$n] = {status:$s, last_run_iso:$t, measured:$m, threshold:$th, reason:$r}' \
       "$CRITERIA_RESULTS_FILE" > "$tmp" && mv "$tmp" "$CRITERIA_RESULTS_FILE"
}

result_pass() {
    local measured="$1" threshold="$2"
    _persist_result PASS "$measured" "$threshold" ""
    echo "RESULT: PASS  criterion=${CRITERION_NAME}  measured=${measured}  threshold=${threshold}"
    exit 0
}
result_fail() {
    local measured="$1" threshold="$2" reason="${3:-}"
    _persist_result FAIL "$measured" "$threshold" "$reason"
    echo "RESULT: FAIL  criterion=${CRITERION_NAME}  measured=${measured}  threshold=${threshold}  reason=${reason}"
    exit 1
}

# ---------- SSH wrapper ----------
# Per-call SSH timeout — prevents one wedged node from hanging the whole
# script.  Default 60s per call; override with MXFS_SSH_TIMEOUT.
: "${MXFS_SSH_TIMEOUT:=60}"
ssh_node() {
    local host="$1"; shift
    timeout "$MXFS_SSH_TIMEOUT" "$MXFS_SSH" "$host" "$MXFS_PASS" "$*" 2>&1 \
        | grep -vE '^Warning|^Unauthorized|^If you'
}
ssh_node_quiet() {
    local host="$1"; shift
    timeout "$MXFS_SSH_TIMEOUT" "$MXFS_SSH" "$host" "$MXFS_PASS" "$*" >/dev/null 2>&1
}

# ---------- Per-script wall-clock guard ----------
# Call this once near the top of every criterion script.  If the script
# hasn't returned within $1 seconds, force-fail with a clear timeout
# reason.  Implemented by spawning a watchdog that kills the script.
#
# The watchdog redirects its own stdout/stderr to /dev/null so it does
# not hold the script's pipe FDs open after the script exits.  Without
# this, callers like `bash criterion.sh | tail -3` would block on the
# pipe until the full timeout elapsed because the backgrounded
# watchdog still had the pipe's write end.
set_script_timeout() {
    local seconds="$1"
    local me=$$
    (
        exec >/dev/null 2>/dev/null </dev/null
        sleep "$seconds"
        if kill -0 "$me" 2>/dev/null; then
            # Persist the watchdog FAIL too so it shows up in --status
            CRITERION_NAME="${CRITERION_NAME:-unknown}" _persist_result \
                FAIL "elapsed>${seconds}s" "elapsed<=${seconds}s" "script wall-clock timeout"
            kill -9 "$me" 2>/dev/null
        fi
    ) &
    SCRIPT_WATCHDOG_PID=$!
    # Disown the watchdog so it doesn't show up in `wait` calls
    # elsewhere in the script.  Without this, any bare `wait` would
    # block on the watchdog's sleep instead of returning when the
    # script's own background jobs finish.
    disown "$SCRIPT_WATCHDOG_PID" 2>/dev/null
    # Kill watchdog on normal exit
    trap '[ -n "${SCRIPT_WATCHDOG_PID:-}" ] && kill "$SCRIPT_WATCHDOG_PID" 2>/dev/null; true' EXIT
}

# Fan out one command across all nodes in parallel, wait, throw away
# output.  Uses the standard MXFS_SSH_TIMEOUT per node, but since all
# nodes run concurrently, total wall is bounded by MXFS_SSH_TIMEOUT, not
# (n * MXFS_SSH_TIMEOUT).  Returns 0 if all nodes succeed.
# Usage: parallel_ssh_quiet "node1 node2 ..." "command"
parallel_ssh_quiet() {
    local nodes_str="$1"; shift
    local cmd="$*"
    local n pid pids=()
    for n in $nodes_str; do
        ( ssh_node_quiet "$n" "$cmd" ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
}

# Run cmd in parallel on all nodes, wait, capture each node's stdout into
# $1.$host.log.  $1 = log-dir prefix; $2 = nodes array passed as one arg.
ssh_all() {
    local logdir="$1"; shift
    local nodes_str="$1"; shift
    local cmd="$*"
    mkdir -p "$logdir"
    local n
    for n in $nodes_str; do
        ( ssh_node "$n" "$cmd" > "$logdir/${n}.log" 2>&1 ) &
    done
    wait
}

# ---------- Cluster lifecycle ----------
# Tear down mxfs on every node, force virsh-reset if a node refuses to
# unmount or rmmod cleanly.  Used at iteration boundaries.
teardown_all() {
    local nodes_str="$*"
    local n
    local pids=()
    for n in $nodes_str; do
        ( timeout 30 "$MXFS_SSH" "$n" "$MXFS_PASS" "
            fuser -k $MXFS_MOUNT 2>/dev/null
            umount $MXFS_MOUNT 2>/dev/null
            sleep 1
            rmmod mxfs 2>/dev/null
            mount | grep -q ' on $MXFS_MOUNT type mxfs' && exit 7
            lsmod | grep -q '^mxfs ' && exit 8
            exit 0
          " >/dev/null 2>&1
          rc=$?
          if [ "$rc" != "0" ]; then
              virsh -c qemu:///system destroy "$n" 2>/dev/null
              sleep 2
              virsh -c qemu:///system start "$n" 2>/dev/null
              # Wait for SSH to respond AND for /src NFS to be mountable
              # AND for the module file to be visible.  Each probe is
              # capped at 8s so a wedged ssh can't hang the loop.  Total
              # bound: ~15 tries * (8s+2s) = ~150s.
              for try in $(seq 1 15); do
                  if timeout 8 "$MXFS_SSH" "$n" "$MXFS_PASS" "
                      mkdir -p /src
                      mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
                      [ -f $MXFS_MODULE ]
                  " >/dev/null 2>&1; then
                      break
                  fi
                  sleep 2
              done
          fi ) &
        pids+=($!)
    done
    # Wait only on our spawned PIDs — never bare `wait`, which would
    # also block on the script-timeout watchdog's sleep.
    local pid
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
}

# Prep + insmod on every node.  First node mkfs's, then all nodes mount.
# Args: $1 = first node, $2... = rest of nodes.
# Env:  TRANSPORT=tcp|caw (default tcp)
#       MKFS_OPTS extra options for mkfs (default empty)
#       INSMOD_OPTS extra options for insmod (default empty)
fresh_cluster_mount() {
    local first="$1"; shift
    local rest=("$@")
    local transport="${TRANSPORT:-tcp}"
    local mkfs_opts="${MKFS_OPTS:-}"
    local insmod_opts="${INSMOD_OPTS:-}"

    # Snippet that aggressively ensures /src is NFS-mounted and the
    # module file is visible.  Retried up to 5 times.  Fails the per-node
    # ssh with a clear ENV_FAIL marker if it can't get the module.
    local ENSURE_NFS='
        for try in 1 2 3 4 5; do
            mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
            [ -f '"$MXFS_MODULE"' ] && break
            sleep 2
        done
        [ -f '"$MXFS_MODULE"' ] || { echo ENV_FAIL_no_module; exit 50; }
    '

    local out
    out=$(ssh_node "$first" "
        $ENSURE_NFS
        $MXFS_PREP >/tmp/prep.log 2>&1
        modprobe libcrc32c
        # sess18: if mxfs is already loaded (e.g. left by cluster_reset),
        # insmod fails File-exists SILENTLY and INSMOD_OPTS params are
        # swallowed.  Force a fresh load so params always apply.
        lsmod | grep -q '^mxfs ' && { umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs || echo RMMOD_FAIL; }
        insmod $MXFS_MODULE $insmod_opts || echo INSMOD_FAIL
        # Cold cluster form: clear any stale SCSI Persistent Reservation left
        # by a node that died uncleanly.  SCST enforces PR, so a stale WE-RO
        # holder blocks our mkfs/mount with a Reservation Conflict.  We are
        # the forming node on a LUN we're about to reformat, so preempting any
        # prior reservation is correct.  register-ignore lets us register our
        # key regardless of existing keys; clear then drops all keys + resv.
        sg_persist --out --register-ignore --param-sark=0x5eed $MXFS_DEV >/dev/null 2>&1
        sg_persist --out --clear --param-rk=0x5eed $MXFS_DEV >/dev/null 2>&1
        echo y | $MXFS_MKFS $mkfs_opts $MXFS_DEV >/tmp/mkfs.log 2>&1 && echo MKFS_OK
        mount -t mxfs $MXFS_MOUNT_OPTS $MXFS_DEV $MXFS_MOUNT && echo MOUNT_OK
    ")
    # sess18: MKFS_OK was echoed but never CHECKED — when mkfs_mxfs failed
    # (e.g. binary missing after `make clean` without `make tools`), the
    # mount silently reused the PREVIOUS filesystem and every criterion ran
    # on stale state.  A fresh cluster means a fresh filesystem: no MKFS_OK
    # is a hard fail.
    if ! echo "$out" | grep -q MKFS_OK; then
        echo "fresh_cluster_mount: mkfs failed on $first (no MKFS_OK): $out" >&2
        return 1
    fi
    if ! echo "$out" | grep -q MOUNT_OK; then
        echo "fresh_cluster_mount: first node $first failed: $out" >&2
        return 1
    fi

    local n pid pids=()
    local tmpdir
    tmpdir=$(mktemp -d /tmp/mxfs_fresh.XXXXXX)
    for n in "${rest[@]}"; do
        ( ssh_node "$n" "
            $ENSURE_NFS
            $MXFS_PREP >/tmp/prep.log 2>&1
            modprobe libcrc32c
            # sess18: force fresh load so INSMOD_OPTS params always apply
            lsmod | grep -q '^mxfs ' && { umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null; }
            insmod $MXFS_MODULE $insmod_opts 2>/dev/null
            mount -t mxfs $MXFS_MOUNT_OPTS $MXFS_DEV $MXFS_MOUNT && echo MOUNTED
        " > "$tmpdir/${n}.log" 2>&1 ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done

    # Verify every node really mounted; print per-node detail on failure
    local mounted=0
    local total=$(( ${#rest[@]} + 1 ))
    local bad=""
    for n in "$first" "${rest[@]}"; do
        if ssh_node_quiet "$n" "mount | grep -q ' on $MXFS_MOUNT type mxfs'"; then
            mounted=$((mounted+1))
        else
            bad="$bad $n"
        fi
    done
    if [ "$mounted" -ne "$total" ]; then
        echo "fresh_cluster_mount: $mounted/$total mounted; failed:${bad}" >&2
        for n in $bad; do
            [ -f "$tmpdir/${n}.log" ] && \
                echo "  --- ${n}.log ---" >&2 && sed 's/^/    /' "$tmpdir/${n}.log" >&2
        done
        rm -rf "$tmpdir"
        return 1
    fi
    rm -rf "$tmpdir"
    return 0
}

# ---------- dmesg-clean assertion ----------
# Return 0 if dmesg on the given node has no kernel BUG/oops/panic/WARN
# since the marker time (epoch ms from `dmesg -T --since`). $1 = node,
# $2 = optional since-marker (e.g. "5 min ago"; defaults to whole boot).
node_dmesg_dirty_count() {
    local node="$1"
    local since="${2:-}"
    local cmd
    if [ -n "$since" ]; then
        cmd="dmesg -T --since='$since' 2>/dev/null"
    else
        cmd="dmesg -T 2>/dev/null"
    fi
    # Count BUG:, kernel BUG, Oops, Call Trace, general protection,
    # WARNING:, Kernel panic.  Filter out the benign "WARNING: CPU: N
    # PID: N at ... mxfs_..." that some non-fatal pathways emit during
    # normal teardown — explicitly NONE for now; if such WARNs exist
    # they should be classified or removed.
    ssh_node "$node" "$cmd | grep -cE 'BUG:|Oops|Call Trace|general protection|WARNING:|Kernel panic|kernel NULL pointer'" \
        | tail -1 | tr -d ' \r\n'
}

# ---------- Native XFS reference ----------
# Run a workload twice: once with the device formatted as native XFS,
# once with mxfs.  Both runs use the same node, same device, same
# command.  Returns the two wall times in ms via stdout
# "xfs_ms=N mxfs_ms=M".  Caller computes ratio.
#
# $1 = node, $2 = "cmd to run inside $MXFS_MOUNT".  The cmd should be
# self-contained and reproducible.
paired_workload_wall_ms() {
    local node="$1"; shift
    local cmd="$*"

    # XFS leg
    local xfs_ms
    xfs_ms=$(ssh_node "$node" "
        umount $MXFS_MOUNT 2>/dev/null
        rmmod mxfs 2>/dev/null
        mkfs.xfs -f $MXFS_DEV >/tmp/xfs_mkfs.log 2>&1
        mount $MXFS_DEV $MXFS_MOUNT
        sync; echo 3 > /proc/sys/vm/drop_caches
        t0=\$(date +%s%N)
        ( cd $MXFS_MOUNT && $cmd ) >/tmp/xfs_run.log 2>&1
        t1=\$(date +%s%N)
        umount $MXFS_MOUNT
        echo \$(( (t1 - t0) / 1000000 ))
    " | tail -1 | tr -d ' \r\n')

    # mxfs leg
    local mxfs_ms
    mxfs_ms=$(ssh_node "$node" "
        $MXFS_PREP >/tmp/prep.log 2>&1
        modprobe libcrc32c
        insmod $MXFS_MODULE 2>/dev/null
        echo y | $MXFS_MKFS $MXFS_DEV >/tmp/mxfs_mkfs.log 2>&1
        mount -t mxfs $MXFS_MOUNT_OPTS $MXFS_DEV $MXFS_MOUNT
        sync; echo 3 > /proc/sys/vm/drop_caches
        t0=\$(date +%s%N)
        ( cd $MXFS_MOUNT && $cmd ) >/tmp/mxfs_run.log 2>&1
        t1=\$(date +%s%N)
        umount $MXFS_MOUNT
        rmmod mxfs 2>/dev/null
        echo \$(( (t1 - t0) / 1000000 ))
    " | tail -1 | tr -d ' \r\n')

    echo "xfs_ms=$xfs_ms mxfs_ms=$mxfs_ms"
}

# ---------- bench.json append ----------
# Append a paired result entry.  $1 = key, $2 = json fragment (string of
# inner object body, no surrounding braces).  bench.json is JSON-as-dict;
# we keep it append-friendly by using jq.
bench_append() {
    local key="$1" body="$2"
    if ! command -v jq >/dev/null 2>&1; then
        echo "warn: jq not installed, skipping bench.json append" >&2
        return 0
    fi
    [ -f "$MXFS_BENCH_JSON" ] || echo '{}' > "$MXFS_BENCH_JSON"
    local tmp
    tmp=$(mktemp)
    jq --arg k "$key" --argjson v "{$body}" '. + {($k): $v}' \
        "$MXFS_BENCH_JSON" > "$tmp" && mv "$tmp" "$MXFS_BENCH_JSON"
}

# ---------- Common arg parsing ----------
# Sets NODES array, MODULE, DEV from --nodes / --module / --device.
# Defaults: NODES=DEFAULT_NODES, MODULE=$MXFS_MODULE, DEV=$MXFS_DEV.
parse_common_args() {
    NODES=("${DEFAULT_NODES[@]}")
    while [ $# -gt 0 ]; do
        case "$1" in
            --nodes)
                # comma- or space-separated list, OR an integer (1..16)
                # meaning "first N from default pool".
                if [[ "$2" =~ ^[0-9]+$ ]]; then
                    NODES=("${DEFAULT_NODES[@]:0:$2}")
                else
                    IFS=', ' read -ra NODES <<<"$2"
                fi
                shift 2 ;;
            --module) MXFS_MODULE="$2"; shift 2 ;;
            --device) MXFS_DEV="$2"; shift 2 ;;
            --mount)  MXFS_MOUNT="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
}
