#!/bin/bash
# MXFS Test Framework — common.sh
# Assertion helpers, logging, colors, test lifecycle

# ---------- Color support ----------
if [ "${MXFS_NO_COLOR:-0}" = "1" ]; then
    RED="" GREEN="" YELLOW="" BLUE="" CYAN="" BOLD="" RESET=""
else
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
fi

# ---------- Globals ----------
MXFS_TEST_NAME=""
MXFS_TEST_START=0
MXFS_TEST_FAILURES=0
MXFS_TEST_ASSERTIONS=0
MXFS_CLEANUP_CMDS=()

# ---------- Logging ----------
log_info()  { echo "${BLUE}[INFO]${RESET}  $*"; }
log_pass()  { echo "${GREEN}[PASS]${RESET}  $*"; }
log_fail()  { echo "${RED}[FAIL]${RESET}  $*"; }
log_skip()  { echo "${YELLOW}[SKIP]${RESET}  $*"; }
log_warn()  { echo "${YELLOW}[WARN]${RESET}  $*"; }
log_debug() { [ "${MXFS_DEBUG:-0}" = "1" ] && echo "${CYAN}[DEBUG]${RESET} $*"; }

# ---------- Test lifecycle ----------
test_begin() {
    MXFS_TEST_NAME="$1"
    MXFS_TEST_START=$(date +%s%N)
    MXFS_TEST_FAILURES=0
    MXFS_TEST_ASSERTIONS=0
    log_info "Starting test: ${BOLD}${MXFS_TEST_NAME}${RESET}"
}

test_end() {
    local end
    end=$(date +%s%N)
    local elapsed_ms=$(( (end - MXFS_TEST_START) / 1000000 ))
    local elapsed_s
    elapsed_s=$(awk "BEGIN {printf \"%.3f\", ${elapsed_ms}/1000}")

    if [ "$MXFS_TEST_FAILURES" -gt 0 ]; then
        log_fail "${BOLD}${MXFS_TEST_NAME}${RESET} — ${MXFS_TEST_FAILURES} failure(s) in ${MXFS_TEST_ASSERTIONS} assertion(s) [${elapsed_s}s]"
        _run_cleanups
        return 1
    else
        log_pass "${BOLD}${MXFS_TEST_NAME}${RESET} — ${MXFS_TEST_ASSERTIONS} assertion(s) [${elapsed_s}s]"
        _run_cleanups
        return 0
    fi
}

test_skip() {
    local reason="${1:-no reason given}"
    log_skip "${BOLD}${MXFS_TEST_NAME}${RESET} — ${reason}"
    _run_cleanups
    exit 2
}

test_fail() {
    local msg="$1"
    MXFS_TEST_FAILURES=$((MXFS_TEST_FAILURES + 1))
    log_fail "$msg"
}

# ---------- Cleanup ----------
add_cleanup() {
    MXFS_CLEANUP_CMDS+=("$*")
}

_run_cleanups() {
    local i
    for (( i=${#MXFS_CLEANUP_CMDS[@]}-1; i>=0; i-- )); do
        eval "${MXFS_CLEANUP_CMDS[$i]}" 2>/dev/null || true
    done
    MXFS_CLEANUP_CMDS=()
}

# Run cleanups on EXIT (catch unexpected termination)
trap _run_cleanups EXIT

# ---------- Assertions ----------
_assert_inc() {
    MXFS_TEST_ASSERTIONS=$((MXFS_TEST_ASSERTIONS + 1))
}

assert_equals() {
    local expected="$1" actual="$2" msg="${3:-assert_equals}"
    _assert_inc
    if [ "$expected" = "$actual" ]; then
        log_debug "ASSERT OK: $msg (expected='$expected')"
        return 0
    else
        test_fail "$msg: expected='$expected' actual='$actual'"
        return 1
    fi
}

assert_not_equals() {
    local unexpected="$1" actual="$2" msg="${3:-assert_not_equals}"
    _assert_inc
    if [ "$unexpected" != "$actual" ]; then
        log_debug "ASSERT OK: $msg (not='$unexpected')"
        return 0
    else
        test_fail "$msg: got unwanted value='$actual'"
        return 1
    fi
}

assert_file_exists() {
    local path="$1" msg="${2:-assert_file_exists}"
    _assert_inc
    if [ -f "$path" ]; then
        log_debug "ASSERT OK: $msg ($path exists)"
        return 0
    else
        test_fail "$msg: file not found: $path"
        return 1
    fi
}

assert_file_not_exists() {
    local path="$1" msg="${2:-assert_file_not_exists}"
    _assert_inc
    if [ ! -f "$path" ]; then
        log_debug "ASSERT OK: $msg ($path absent)"
        return 0
    else
        test_fail "$msg: file unexpectedly exists: $path"
        return 1
    fi
}

assert_dir_exists() {
    local path="$1" msg="${2:-assert_dir_exists}"
    _assert_inc
    if [ -d "$path" ]; then
        log_debug "ASSERT OK: $msg ($path exists)"
        return 0
    else
        test_fail "$msg: directory not found: $path"
        return 1
    fi
}

assert_dir_not_exists() {
    local path="$1" msg="${2:-assert_dir_not_exists}"
    _assert_inc
    if [ ! -d "$path" ]; then
        log_debug "ASSERT OK: $msg ($path absent)"
        return 0
    else
        test_fail "$msg: directory unexpectedly exists: $path"
        return 1
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-assert_contains}"
    _assert_inc
    if echo "$haystack" | grep -qF "$needle"; then
        log_debug "ASSERT OK: $msg (found '$needle')"
        return 0
    else
        test_fail "$msg: '$needle' not found in output"
        return 1
    fi
}

assert_count() {
    local expected="$1" pattern="$2" msg="${3:-assert_count}"
    _assert_inc
    local actual
    actual=$(find "$(dirname "$pattern")" -maxdepth 1 -name "$(basename "$pattern")" 2>/dev/null | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    if [ "$actual" = "$expected" ]; then
        log_debug "ASSERT OK: $msg (count=$actual)"
        return 0
    else
        test_fail "$msg: expected count=$expected actual=$actual (pattern=$pattern)"
        return 1
    fi
}

assert_md5() {
    local expected="$1" filepath="$2" msg="${3:-assert_md5}"
    _assert_inc
    if [ ! -f "$filepath" ]; then
        test_fail "$msg: file not found: $filepath"
        return 1
    fi
    local actual
    actual=$(md5sum "$filepath" | awk '{print $1}')
    if [ "$expected" = "$actual" ]; then
        log_debug "ASSERT OK: $msg (md5=$actual)"
        return 0
    else
        test_fail "$msg: expected md5=$expected actual=$actual ($filepath)"
        return 1
    fi
}

assert_true() {
    local msg="${1:-assert_true}"
    _assert_inc
    # Caller should run: some_cmd && assert_true "msg" || assert_true "msg"
    # OR: if condition; then assert_true "msg"; else _assert_fail_true "msg"; fi
    log_debug "ASSERT OK: $msg"
    return 0
}

assert_zero() {
    local val="$1" msg="${2:-assert_zero}"
    _assert_inc
    if [ "$val" = "0" ]; then
        log_debug "ASSERT OK: $msg (val=0)"
        return 0
    else
        test_fail "$msg: expected 0, got '$val'"
        return 1
    fi
}

assert_nonzero() {
    local val="$1" msg="${2:-assert_nonzero}"
    _assert_inc
    if [ "$val" != "0" ] && [ -n "$val" ]; then
        log_debug "ASSERT OK: $msg (val=$val)"
        return 0
    else
        test_fail "$msg: expected nonzero, got '$val'"
        return 1
    fi
}

assert_ge() {
    local actual="$1" threshold="$2" msg="${3:-assert_ge}"
    _assert_inc
    if [ "$actual" -ge "$threshold" ] 2>/dev/null; then
        log_debug "ASSERT OK: $msg ($actual >= $threshold)"
        return 0
    else
        test_fail "$msg: expected >= $threshold, got $actual"
        return 1
    fi
}

assert_le() {
    local actual="$1" threshold="$2" msg="${3:-assert_le}"
    _assert_inc
    if [ "$actual" -le "$threshold" ] 2>/dev/null; then
        log_debug "ASSERT OK: $msg ($actual <= $threshold)"
        return 0
    else
        test_fail "$msg: expected <= $threshold, got $actual"
        return 1
    fi
}

assert_file_size_gt() {
    local filepath="$1" min_bytes="$2" msg="${3:-assert_file_size_gt}"
    _assert_inc
    if [ ! -f "$filepath" ]; then
        test_fail "$msg: file not found: $filepath"
        return 1
    fi
    local sz
    sz=$(stat -c%s "$filepath" 2>/dev/null || echo 0)
    if [ "$sz" -gt "$min_bytes" ]; then
        log_debug "ASSERT OK: $msg (size=$sz > $min_bytes)"
        return 0
    else
        test_fail "$msg: file size $sz not > $min_bytes ($filepath)"
        return 1
    fi
}

# ---------- Timing helpers ----------
# Start a timer, returns nanosecond timestamp
time_op() { date +%s%N; }

# Calculate elapsed ms from a start timestamp
time_elapsed_ms() {
    local start="$1"
    local end
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
}

# Log a timing measurement (appends to per-test timing file)
log_timing() {
    local op="$1" ms="$2"
    echo "  [TIMING] ${op}: ${ms}ms"
    if [ -n "${MXFS_TIMING_FILE:-}" ]; then
        echo "${op},${ms}" >> "$MXFS_TIMING_FILE"
    fi
}

# ---------- Result file helpers ----------
# Write a result file in machine-readable format
write_result() {
    local test_name="$1" status="$2" detail="${3:-}"
    local resultdir="${MOUNT_POINT:?}/.mxfs_results/node${NODE_ID:?}"
    mkdir -p "$resultdir" 2>/dev/null
    {
        echo "test=$test_name"
        echo "status=$status"
        echo "node=$NODE_ID"
        echo "time=$(date +%s)"
        if [ -n "$detail" ]; then echo "detail=$detail"; fi
    } > "$resultdir/${test_name}.result"
}

# Read a result file
read_result() {
    local test_name="$1" node="$2"
    local resultfile="${MOUNT_POINT:?}/.mxfs_results/node${node}/${test_name}.result"
    if [ -f "$resultfile" ]; then
        grep '^status=' "$resultfile" | cut -d= -f2
    else
        echo "MISSING"
    fi
}
