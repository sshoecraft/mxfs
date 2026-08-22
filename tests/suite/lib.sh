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

# ─── RULE-0 TERMINAL-RECORD GUARANTEE (sess384) ────────────────────────────
#
# D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374, root cause: run.sh runs
# each node under `timeout <RULE-0 budget> ssh ...` and aggregates by grepping
# ^RESULT: out of the captured stdout.  The node-side rendezvous cap
# (COORD_TIMEOUT, default 120s) was larger than that budget for every criterion
# except dir_reuse_coherency, so a genuine stall was SIGKILLed before the
# barrier layer could print its BARRIER_TIMEOUT record: the board showed
# `nodes_pass=0/32 states:NO_TERMINAL_RECORD=32` and nothing else.  Proof that
# the reporting path was structurally unreachable: BARRIER_TIMEOUT has never
# once appeared in criteria.json's recorded history.
#
# The guarantee now has THREE delivery paths, in precedence order:
#   1. the test's own finish/finish_state record          (src=test)
#   2. this node's watchdog, fired at the reporting deadline   (src=watchdog)
#   3. a state the HARNESS synthesizes from `timeout`'s exit status when
#      neither of the above was delivered (src=harness, in run.sh)
# Path 3 is the only one that cannot fail, because it runs outside the ssh
# session; 1 and 2 are strictly enrichment.  Every record is ALSO spooled
# node-locally (MXFS_SPOOL), because ssh block-buffering has been observed to
# lose unflushed stdout when the kill lands — run.sh fetches the spool before
# it synthesizes.
#
# Harness-provided (all optional; absent = every guard below is inert):
#   MXFS_DEADLINE_MS  epoch ms at which the harness will SIGKILL this ssh
#   MXFS_RESERVE_MS   margin reserved for emitting the record (default 4000)
#   MXFS_SPOOL        node-local path for the terminal-record spool
: "${MXFS_DEADLINE_MS:=}"
: "${MXFS_RESERVE_MS:=4000}"
: "${MXFS_SPOOL:=}"

SUITE_T0_S=$(date +%s)
SUITE_REPORT_S=""          # seconds from SUITE_T0_S to the reporting deadline
SUITE_STEP_FILE=""
SUITE_STEP="startup"
SUITE_WD_PID=""
SUITE_EMITTED=0

if [ -n "$MXFS_DEADLINE_MS" ]; then
    # Convert the absolute deadline to a RELATIVE remaining interval ONCE, here,
    # and use relative waits from now on: an NTP correction mid-test would
    # otherwise move the watchdog.  The absolute value is kept only for logging.
    suite_now_ms=$(date +%s%3N)
    SUITE_REPORT_S=$(( (MXFS_DEADLINE_MS - MXFS_RESERVE_MS - suite_now_ms) / 1000 ))
    unset suite_now_ms
fi

# Breadcrumb lives on tmpfs under /run on a node (root); anywhere else, fall
# back to TMPDIR so the guarantee still works when the suite lib is exercised
# off-cluster (tests/d384_terminal_record_guarantee.sh).
if mkdir -p /run/mxfs-suite 2>/dev/null && [ -w /run/mxfs-suite ]; then
    SUITE_STEP_FILE="/run/mxfs-suite/step.$$"
else
    SUITE_STEP_FILE="${TMPDIR:-/tmp}/mxfs-suite-step.$$"
fi

# suite_step "<label>" — breadcrumb.  Records WHERE this node is, so a watchdog
# record can name the step instead of just saying "budget gone".  Written with
# the shell BUILTIN printf and a single redirection: no fork, one write(2), so
# it is cheap enough to call on every check (cache_coherency runs 654).  The
# O_TRUNC-then-write window means a reader can catch the file momentarily
# EMPTY; suite_step_read retries once for that, which is the whole race.
suite_step() {
    SUITE_STEP="${1//|/ }"
    [ -n "$SUITE_STEP_FILE" ] || return 0
    printf 'step=%s|checks=%s|passed=%s|failed=%s\n' \
        "$SUITE_STEP" "$((PASS_N + FAIL_N))" "$PASS_N" "$FAIL_N" \
        > "$SUITE_STEP_FILE" 2>/dev/null
    return 0
}

suite_step_read() {
    local v=""
    [ -n "$SUITE_STEP_FILE" ] || return 1
    v=$(cat "$SUITE_STEP_FILE" 2>/dev/null)
    if [ -z "$v" ]; then sleep 0.05; v=$(cat "$SUITE_STEP_FILE" 2>/dev/null); fi
    [ -n "$v" ] || return 1
    printf '%s' "$v"
}

# suite_emit <state> <src> <measured> <reason...> — the ONE place a terminal
# record is produced.  Prints the single-line RESULT record on stdout (inherited
# by the watchdog subshell, so it reaches the same ssh channel) and spools it
# node-locally via write-then-rename so run.sh can fetch a record whose stdout
# was lost to buffering.  `src=` sits BEFORE `reason=` so an arbitrary reason
# string can never shadow it.
suite_emit() {
    local state="$1" src="$2" measured="$3"; shift 3
    local ln="RESULT: $state | test=$SUITE_TEST_NAME | nodes=$NODES | src=$src | measured=$measured | reason=$*"
    printf '%s\n' "$ln"
    if [ -n "$MXFS_SPOOL" ]; then
        printf '%s\n' "$ln" > "$MXFS_SPOOL.tmp.$BASHPID" 2>/dev/null &&
            mv -f "$MXFS_SPOOL.tmp.$BASHPID" "$MXFS_SPOOL" 2>/dev/null
    fi
    SUITE_EMITTED=1
}

# suite_proc_starttime <pid> — field 22 of /proc/<pid>/stat, the process start
# time.  (pid, starttime) is a stable identity across PID reuse.  Uses the read
# builtin so a poll costs no fork.  Empty output = the process is gone.
suite_proc_starttime() {
    local st=""
    { read -r st < "/proc/$1/stat"; } 2>/dev/null || return 1
    # comm (field 2) is parenthesised and may contain spaces; count from its ')'
    st="${st#*) }"
    set -- $st
    printf '%s' "${20:-}"
}

# suite_watchdog_start — best-effort node-side reporter.  NOT the guarantee (a
# wedged scheduler, a dead ssh channel or a host reset all defeat it); run.sh's
# synthesized state is.  Explicitly started, and idempotent, rather than a
# source-time side effect, because lib.sh is sourced from subshells too.
#
# It does NOT try to kill the workload: the stall that fires it is normally a
# D-state kernel wait, which cannot take a signal at all, and blind
# process-group kills would reach processes this script does not own.  run.sh
# already sweeps leftovers after the budget.  The watchdog's job is one line.
#
# It POLLS for the main shell rather than sleeping the whole interval, because
# a background subshell INHERITS stdout — i.e. it holds the ssh channel's pipe
# open, and sshd will not close the session until every holder exits.  A
# one-shot `sleep $SUITE_REPORT_S` would therefore stretch EVERY passing test to
# its full budget whenever the test exits without reaching finish() (several set
# their own EXIT trap, so a lib.sh trap cannot be relied on).  Liveness is
# checked by (pid, starttime) from /proc/<pid>/stat, not by `kill -0` alone: a
# bare pid check is a PID-reuse TOCTOU, which is the same trap that once wedged
# every barrier criterion cluster-wide (see coord_barrier_or_abort's header).
# Reading /proc/<pid>/stat is safe on a wedged node; /proc/<pid>/cmdline is not.
suite_watchdog_start() {
    [ -n "$SUITE_REPORT_S" ] || return 0
    [ -z "$SUITE_WD_PID" ] || return 0
    if [ "$SUITE_REPORT_S" -le 0 ]; then
        suite_emit BUDGET_EXHAUSTED watchdog "checks=0 passed=0 failed=0" \
            "insufficient_time_after_ssh_connect report_s=$SUITE_REPORT_S deadline_ms=$MXFS_DEADLINE_MS"
        exit 1
    fi
    local main=$BASHPID mainst=""
    mainst=$(suite_proc_starttime "$main")
    (
        local i=0 st
        while [ "$i" -lt "$SUITE_REPORT_S" ]; do
            sleep 1
            st=$(suite_proc_starttime "$main")
            [ -n "$st" ] && [ "$st" = "$mainst" ] || exit 0
            i=$((i + 1))
        done
        local snap ck pa fa lbl
        snap=$(suite_step_read) || snap=""
        lbl=$(printf '%s' "$snap" | sed -n 's/^step=\([^|]*\).*/\1/p')
        ck=$(printf '%s' "$snap" | sed -n 's/.*|checks=\([0-9]*\).*/\1/p')
        pa=$(printf '%s' "$snap" | sed -n 's/.*|passed=\([0-9]*\).*/\1/p')
        fa=$(printf '%s' "$snap" | sed -n 's/.*|failed=\([0-9]*\)/\1/p')
        suite_emit BUDGET_EXHAUSTED watchdog \
            "checks=${ck:-0} passed=${pa:-0} failed=${fa:-0}" \
            "step=${lbl:-unknown} report_s=$SUITE_REPORT_S elapsed_s=$(( $(date +%s) - SUITE_T0_S ))"
    ) &
    SUITE_WD_PID=$!
    return 0
}

suite_watchdog_stop() {
    [ -n "$SUITE_WD_PID" ] || return 0
    kill "$SUITE_WD_PID" 2>/dev/null
    wait "$SUITE_WD_PID" 2>/dev/null
    SUITE_WD_PID=""
    return 0
}

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
    suite_step "$desc"
    if "$@" >/dev/null 2>&1; then
        PASS_N=$((PASS_N + 1))
    else
        FAIL_N=$((FAIL_N + 1)); FAILED+=("$desc")
    fi
}

# ckeq "<desc>" <expected> <actual>   — pass if equal
ckeq() {
    local desc="$1" exp="$2" act="$3"
    suite_step "$desc"
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
    suite_watchdog_stop
    suite_emit "$status" test "$measured" "$reason"
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
    suite_watchdog_stop
    suite_emit "$state" test "$measured" "$*"
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

# ─── arm the watchdog (sess384) ────────────────────────────────────────────
# Armed here, at the END of lib.sh, so every helper it needs is defined; the
# exported marker makes it once-per-process-tree, so a subshell that re-sources
# this lib cannot fork a second reporter that emits a spurious record.
if [ -z "${MXFS_WD_ARMED:-}" ]; then
    export MXFS_WD_ARMED=1
    suite_watchdog_start
fi

# ─── stall injection (sess384) ─────────────────────────────────────────────
# The ONLY way to exercise the terminal-record guarantee is to make a node miss
# its deadline on purpose.  MXFS_STALL_RANK=<rank> MXFS_STALL_S=<seconds> stalls
# exactly that rank, here at the top of the test, BEFORE it reaches any barrier
# — the shape that actually happened in the sess384 incident (test1 printed
# nothing at all in 60s because it never got as far as a rendezvous).  Its peers
# then stall at the first barrier, so one run exercises both halves: the
# watchdog path on the stalled rank and the deadline-clamped barrier path on the
# other 31.
#
# Inert unless MXFS_STALL_RANK is set, and it touches no filesystem state — it
# is a sleep.  Set through the harness with:
#     MXFS_TEST_ENV="MXFS_STALL_RANK=7 MXFS_STALL_S=300" ./run.sh 32 caw <test>
if [ -n "${MXFS_STALL_RANK:-}" ] && [ "${MXFS_STALL_RANK}" = "$RANK" ]; then
    suite_step "injected-stall"
    echo "mxfs-INJECTED-STALL rank=$RANK for ${MXFS_STALL_S:-600}s" > /dev/kmsg 2>/dev/null
    sleep "${MXFS_STALL_S:-600}"
fi
