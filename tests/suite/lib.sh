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

# ─── dirent window scoping (ccloop c7ee71c6 sess24) ────────────────────────
#
# dirent_durability stamps MXFS_DIRENT_WINDOW to /dev/kmsg at the start of its
# workload, and the P8 scanners (dirent_publish_integrity, dirent_type_integrity)
# scope their ring scan to everything after it.  Scoping is load-bearing: dmesg
# survives a module reload and prep_cluster does not clear it, so an unscoped
# scan re-reports an hour-old hit forever and the cell can never go green again.
#
# But the marker alone is not durable evidence, because dmesg is a RING whose
# retention varies wildly across nodes of one cluster.  Measured right after
# dirent_durability PASSED 32/32 (118s wall):
#
#     test19   1964 lines /  109s of ring   <- window start already rotated out
#     test1  123109 lines /  709s
#     test25 136966 lines / 1107s
#
# On the short-ring nodes the marker was gone, and both scanners then reported
# FAIL with the reason "the workload has not run in this boot" -- false: it had
# just passed on that node.  That is an evidence-retention failure being
# published as a correctness defect (5 of 32 nodes red), the same class of board
# lie as the sess23 reconvergence-beacon ring bug.
#
# dirent_window_scope sets, on stdout, the scoped window text; and in globals:
# CALL IT AS  dirent_window_scope <outfile>  -- NOT as $(dirent_window_scope).
# Command substitution runs the function in a SUBSHELL, so globals set inside it
# are lost; the first cut of this helper did exactly that, which left DW_HAVE
# EMPTY.  `[ "$have_window" = 0 ]` is then false for an empty string, so both
# scanners skipped their no-evidence FAIL branch and reported PASS with every
# count at zero -- a VACUOUS GREEN, strictly worse than the false red it
# replaced.  Hence: window text goes to a FILE, metadata goes to globals.
#
# Sets:
#   DW_HAVE      1 if a window could be established at all, else 0
#   DW_SOURCE    marker | timestamp | none
#   DW_TRUNC     1 if the ring no longer reaches back to the window start
#                (evidence is incomplete -- the count is a LOWER BOUND)
#
# Order of preference:
#   1. the marker line is still in the ring        -> exact scope (unchanged)
#   2. the durable start timestamp file exists     -> scope the ring by the
#      kernel timestamp prefix, which still works after the marker rotated out
#   3. neither                                     -> genuinely never ran
dirent_window_scope() {
    local out="$1" start ring_oldest raw
    DW_HAVE=0; DW_SOURCE=none; DW_TRUNC=0
    : > "$out"
    raw=$(mktemp) || return 1
    dmesg > "$raw" 2>/dev/null

    # ccloop c7ee71c6 sess27 BUGFIX: scope from the LAST marker, not the first.
    # The old body was `awk '/MXFS_DIRENT_WINDOW/{seen=1;next} seen{print}'`,
    # which latches on the OLDEST marker still in the ring and then prints every
    # later line -- so with two runs since boot the window spans BOTH and every
    # criterion using it re-counts the previous run's hits forever.  That is the
    # precise failure the marker exists to prevent (see the header of
    # dirent_type_integrity.sh), and it was live: on a 107k-line ring holding two
    # markers (20020.8 and 20656.9), dirent_type_integrity reported test1
    # unresolved=6 win_src=marker win_trunc=0 while the current run's window
    # (after 20656.9) contained ZERO P95B/P201 lines -- all six belonged to the
    # previous run and to the prep between them.  A criterion that cannot be
    # driven green by fixing the defect is not a measurement.
    local mln
    mln=$(grep -n 'MXFS_DIRENT_WINDOW' "$raw" | tail -1 | cut -d: -f1)
    if [ -n "$mln" ]; then
        DW_HAVE=1; DW_SOURCE=marker
        tail -n +$((mln + 1)) "$raw" > "$out"
        rm -f "$raw"
        return 0
    fi

    start=$(cat /run/mxfs_dirent_window_start 2>/dev/null || \
            cat /tmp/mxfs_dirent_window_start 2>/dev/null)
    case "$start" in
        ''|*[!0-9.]*) rm -f "$raw"; return 0 ;;   # no durable record either
    esac
    DW_HAVE=1; DW_SOURCE=timestamp
    # dmesg's "[   1234.567890]" prefix is the same clock as /proc/uptime.
    ring_oldest=$(grep -oE '^\[[[:space:]]*[0-9]+\.[0-9]+\]' "$raw" \
                  | head -1 | tr -d '[] ')
    if [ -n "$ring_oldest" ] && \
       awk -v a="$ring_oldest" -v b="$start" 'BEGIN{exit !(a > b)}'; then
        DW_TRUNC=1
    fi
    awk -v s="$start" '
        match($0, /^\[[ ]*[0-9]+\.[0-9]+\]/) {
            t = substr($0, RSTART + 1, RLENGTH - 2) + 0
            if (t >= s) print
        }' "$raw" > "$out"
    rm -f "$raw"
    return 0
}
