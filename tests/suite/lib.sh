# tests/suite/lib.sh — helpers for agnostic MXFS FS tests.
#
# Sourced by test scripts that run ON a node. A test knows ONLY its mount point
# (passed as $1, default /mnt/shared) and — for coordinated tests later — a
# coord handle. It must NEVER reference device, module, transport, or node id.
#
# A test sources this, runs a series of ck/ckeq checks, then calls finish,
# which prints the parseable RESULT line the runner records:
#   RESULT: PASS | test=<name> | nodes=<n> | measured=<...> | reason=<...>

: "${SUITE_TEST_NAME:=$(basename "${0%.sh}")}"
: "${MNT:=${1:-/mnt/shared}}"
: "${NODES:=${MXFS_NODES:-1}}"
# RANK — this node's 1-based index within the run (harness sets MXFS_RANK).
# Coordinated tests use it to carve their own per-node namespace.
: "${RANK:=${MXFS_RANK:-1}}"

# Coordination primitive — sourced so every test has coord_* available
# (no-ops on a single node). Lives beside this lib.
if [ -f "$(dirname -- "${BASH_SOURCE[0]}")/coord.sh" ]; then
    # shellcheck source=/dev/null
    source "$(dirname -- "${BASH_SOURCE[0]}")/coord.sh"
fi

PASS_N=0
FAIL_N=0
FAILED=()

# ck "<desc>" cmd args...   — pass if cmd exits 0
ck() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        PASS_N=$((PASS_N + 1))
    else
        FAIL_N=$((FAIL_N + 1)); FAILED+=("$desc")
    fi
}

# ckeq "<desc>" <expected> <actual>   — pass if equal
ckeq() {
    local desc="$1" exp="$2" act="$3"
    if [ "$exp" = "$act" ]; then
        PASS_N=$((PASS_N + 1))
    else
        FAIL_N=$((FAIL_N + 1)); FAILED+=("$desc(exp=$exp got=$act)")
    fi
}

# finish — emit RESULT and exit 0 (all passed) / 1 (any failed).
finish() {
    local status="PASS" measured reason=""
    # sess10(a9a03929): watch-ino hygiene.  Tests that arm the kernel
    # storm-dir probe scope (dir_reuse, fence) must not leak it into the
    # NEXT test via inode-number reuse — the armed probes do per-op platter
    # reads and collapsed tcp_dlm_scaling's pace (s10 iter3: 42/150 rounds).
    # Reset to the impossible-ino sentinel at every test exit.
    [ -w /sys/module/mxfs/parameters/watch_ino ] && \
        echo 1 > /sys/module/mxfs/parameters/watch_ino 2>/dev/null
    measured="checks=$((PASS_N + FAIL_N)) passed=$PASS_N failed=$FAIL_N"
    if [ "$FAIL_N" -gt 0 ]; then
        status="FAIL"
        reason="${FAILED[*]}"
    fi
    echo "RESULT: $status | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$measured | reason=$reason"
    [ "$FAIL_N" -eq 0 ]
}

# finish_state <STATE> [detail...] — like finish(), but for a terminal
# condition other than plain correctness PASS/FAIL: a hang, a barrier
# timeout, a peer-broadcast abort, etc.  STATE lands in the RESULT line's
# status field (same position finish() puts PASS/FAIL in), so run.sh's
# existing `[ "$status" = PASS ]` aggregation keeps working unmodified —
# anything other than PASS already falls through to its failure branch.
# Distinguishing WHICH non-pass state occurred is what lets the aggregator
# (and a human) tell "N independent correctness failures" apart from "one
# node hung and everyone else stopped cooperating" instead of both reading
# as an undifferentiated nodes_pass=0/N (see ccmemory
# gpt-consult-dir_reuse32-architectural-review, 2026-07-11).
finish_state() {
    local state="$1"; shift
    [ -w /sys/module/mxfs/parameters/watch_ino ] && \
        echo 1 > /sys/module/mxfs/parameters/watch_ino 2>/dev/null
    local measured="checks=$((PASS_N + FAIL_N)) passed=$PASS_N failed=$FAIL_N"
    echo "RESULT: $state | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$measured | reason=$*"
    [ "$state" = "PASS" ]
}

# finish_hang <op> [detail...] — a bounded background op (see run_bounded)
# didn't complete in time.  Distinct from a correctness FAIL: the test
# couldn't finish checking anything, so this says nothing about coherency
# either way — it says the kernel didn't return from a syscall.
finish_hang() {
    local op="$1"; shift
    finish_state SYSCALL_HANG "op=$op $*"
}

# finish_aborted <reason...> — a peer broadcast a fatal abort (its own hang
# or shutdown, via coord_signal_abort); this node stopped cooperating
# rather than independently burning a full timeout on every remaining
# barrier.
finish_aborted() {
    finish_state ABORTED_BY_PEER "$*"
}

# run_bounded <label> <threshold_s> <command...> — run an EXTERNAL command
# (not a shell builtin/function) in the background and poll once a second
# for up to <threshold_s>.  Returns 0 if it finished in time.  On a hang:
# the process is very likely D-state (uninterruptible kernel wait) and
# cannot be killed — there is nothing to do but capture its wchan/kernel
# stack for the record and return 1 so the caller can decide what to do
# (broadcast an abort, degrade gracefully, etc.) instead of blocking on the
# same hang itself.  Generalizes the drop_caches bounded-wait idiom
# introduced in dir_reuse_coherency.sh (sess14/a9a03929).
run_bounded() {
    local label="$1" threshold="$2"; shift 2
    "$@" 2>/dev/null &
    # sess10 (ccloop 72513a13): poll at 100ms, not 1s.  The 1s lap quantized
    # every bounded op UP to the next whole second (drc rank1 paid a constant
    # ~1s/round on rm-rf + ~1s on mkdir in pure sleep — measured: rm-done
    # spans pinned at exactly 4.02s while the isolated rm takes ~1.1-1.65s).
    # The hang THRESHOLD semantics are unchanged (threshold is in seconds).
    local pid=$! i=0 ok=0 laps=$(( threshold * 10 ))
    while [ "$i" -lt "$laps" ]; do
        kill -0 "$pid" 2>/dev/null || { ok=1; break; }
        sleep 0.1; i=$((i + 1))
    done
    if [ "$ok" != 1 ]; then
        echo "mxfs-HANG label=$label pid=$pid threshold=${threshold}s wchan=[$(cat /proc/$pid/wchan 2>/dev/null)] comm=[$(cat /proc/$pid/comm 2>/dev/null)]" > /dev/kmsg 2>/dev/null
        while IFS= read -r stackln; do
            echo "mxfs-HANGSTACK label=$label $stackln" > /dev/kmsg 2>/dev/null
        done < "/proc/$pid/stack" 2>/dev/null
        return 1
    fi
    return 0
}
