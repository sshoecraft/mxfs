#!/bin/bash
# MXFS Test Framework — run_tests.sh
# Master orchestrator. Runs from the dev/coordinator machine.
#
# Usage:
#   ./tests/run_tests.sh --nodes 32 --phase all
#   ./tests/run_tests.sh --nodes 4 --phase single
#   ./tests/run_tests.sh --nodes 32 --phase cluster
#   ./tests/run_tests.sh --nodes 32 --phase stress
#   ./tests/run_tests.sh --nodes 32 --test test_concurrent_touch
#   ./tests/run_tests.sh --list
#
# Prerequisite: Deploy first with tools/mxfs_deploy.sh --nodes N

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ---------- Defaults ----------
NUM_NODES=1
PHASE="all"
SINGLE_TEST=""
LIST_TESTS=0
MOUNT_POINT="/mnt/shared"
DEVICE="/dev/sdb"
PASS_FILE="/home/steve/.mxfs/pass"
RESULTS_DIR="/home/steve/.mxfs/results"
NO_COLOR=0
DEBUG=0

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
    case "$1" in
        --nodes)       NUM_NODES="$2"; shift 2 ;;
        --phase)       PHASE="$2"; shift 2 ;;
        --test)        SINGLE_TEST="$2"; shift 2 ;;
        --list)        LIST_TESTS=1; shift ;;
        --mount-point) MOUNT_POINT="$2"; shift 2 ;;
        --device)      DEVICE="$2"; shift 2 ;;
        --pass-file)   PASS_FILE="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --no-color)    NO_COLOR=1; shift ;;
        --debug)       DEBUG=1; shift ;;
        -h|--help)
            echo "Usage: run_tests.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --nodes N          Number of test nodes (1,2,4,8,16,32). Default: 1"
            echo "  --phase PHASE      single, cluster, stress, or all. Default: all"
            echo "  --test NAME        Run a specific test by name (without .sh)"
            echo "  --list             List all available tests"
            echo "  --mount-point PATH Shared mount point. Default: /mnt/shared"
            echo "  --device DEV       Block device. Default: /dev/sdb"
            echo "  --pass-file PATH   SSH password file. Default: /home/steve/.mxfs/pass"
            echo "  --results-dir PATH Where to write results. Default: /home/steve/.mxfs/results/"
            echo "  --no-color         Disable colored output"
            echo "  --debug            Enable debug output"
            echo ""
            echo "Prerequisite: Deploy first with tools/mxfs_deploy.sh --nodes N"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---------- Setup color/environment ----------
[ "$NO_COLOR" = "1" ] && export MXFS_NO_COLOR=1
[ "$DEBUG" = "1" ] && export MXFS_DEBUG=1
export MXFS_PASS_FILE="$PASS_FILE"
export MXFS_MOUNT_POINT="$MOUNT_POINT"
export MXFS_DEVICE="$DEVICE"

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/cluster.sh"

# ---------- Test discovery ----------
discover_tests() {
    local phase="$1"
    local tests=()
    local dirs=()

    case "$phase" in
        single)  dirs=("${SCRIPT_DIR}/single") ;;
        cluster) dirs=("${SCRIPT_DIR}/cluster") ;;
        stress)  dirs=("${SCRIPT_DIR}/stress") ;;
        all)     dirs=("${SCRIPT_DIR}/single" "${SCRIPT_DIR}/cluster" "${SCRIPT_DIR}/stress") ;;
        *)       log_fail "Unknown phase: $phase"; exit 1 ;;
    esac

    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            for f in "$dir"/test_*.sh; do
                [ -f "$f" ] || continue
                local name
                name=$(basename "$f" .sh)
                local pname
                pname=$(basename "$(dirname "$f")")
                tests+=("${pname}/${name}")
            done
        fi
    done
    echo "${tests[@]}"
}

# ---------- List mode ----------
if [ "$LIST_TESTS" = "1" ]; then
    echo "Available tests:"
    echo ""
    for pdir in single cluster stress; do
        if [ -d "${SCRIPT_DIR}/${pdir}" ]; then
            local_tests=()
            for f in "${SCRIPT_DIR}/${pdir}"/test_*.sh; do
                [ -f "$f" ] || continue
                local_tests+=("$(basename "$f" .sh)")
            done
            if [ ${#local_tests[@]} -gt 0 ]; then
                echo "  ${BOLD}${pdir}/${RESET}"
                for t in "${local_tests[@]}"; do
                    echo "    $t"
                done
                echo ""
            fi
        fi
    done
    exit 0
fi

# ---------- Validate ----------
if [ ! -f "$PASS_FILE" ]; then
    log_fail "Password file not found: $PASS_FILE"
    exit 1
fi

# ---------- Results setup ----------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="${RESULTS_DIR}/${TIMESTAMP}"
mkdir -p "$RUN_DIR"

# ---------- Summary tracking ----------
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
FAILED_NAMES=()
RUN_START=$(date +%s)

# ---------- Timing ----------
TIMING_DIR="${RUN_DIR}/timing"
mkdir -p "$TIMING_DIR"

summary_header() {
    echo ""
    echo "${BOLD}============================================${RESET}"
    echo "${BOLD}  MXFS Test Run — $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo "${BOLD}  Nodes: ${NUM_NODES}  Phase: ${PHASE}  Device: ${DEVICE}${RESET}"
    echo "${BOLD}============================================${RESET}"
    echo ""
}

summary_footer() {
    local run_end
    run_end=$(date +%s)
    local elapsed=$((run_end - RUN_START))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))

    echo ""
    echo "${BOLD}============================================${RESET}"
    echo "${BOLD}  Results: ${TOTAL_TESTS} tests${RESET}"
    echo "    ${GREEN}PASS: ${PASSED_TESTS}${RESET}"
    echo "    ${RED}FAIL: ${FAILED_TESTS}${RESET}"
    echo "    ${YELLOW}SKIP: ${SKIPPED_TESTS}${RESET}"
    echo "    Time: ${mins}m ${secs}s"
    if [ ${#FAILED_NAMES[@]} -gt 0 ]; then
        echo ""
        echo "  ${RED}Failed tests:${RESET}"
        for name in "${FAILED_NAMES[@]}"; do
            echo "    ${RED}- ${name}${RESET}"
        done
    fi
    echo "${BOLD}============================================${RESET}"
    echo ""

    # Show timing summary if any timing data was collected
    local timing_files
    # find (not ls): under set -euo pipefail, ls on a non-matching glob
    # exits 2 and pipefail aborts the whole script AFTER the summary
    # prints — the criterion then sees passed=N failed=0 rc=2 (sess129).
    timing_files=$(find "$TIMING_DIR" -name '*.csv' 2>/dev/null | wc -l)
    timing_files=$(echo "$timing_files" | tr -d ' ')
    if [ "$timing_files" -gt 0 ]; then
        echo ""
        echo "  ${BOLD}Timing data saved to: ${TIMING_DIR}/${RESET}"
    fi

    # Write summary file
    {
        echo "timestamp=$TIMESTAMP"
        echo "nodes=$NUM_NODES"
        echo "phase=$PHASE"
        echo "total=$TOTAL_TESTS"
        echo "passed=$PASSED_TESTS"
        echo "failed=$FAILED_TESTS"
        echo "skipped=$SKIPPED_TESTS"
        echo "elapsed=${elapsed}s"
        for name in "${FAILED_NAMES[@]}"; do
            echo "failed_test=$name"
        done
    } > "${RUN_DIR}/summary.txt"
}

# ---------- Run a single-node test ----------
run_single_test() {
    local test_name="$1"
    local phase_dir="$2"
    log_info "Running: ${BOLD}${test_name}${RESET} (single-node)"

    local output_file="${RUN_DIR}/${test_name}.log"
    local rc=0

    ssh_node 1 "export MXFS_TIMING_FILE=/tmp/mxfs_timing_${test_name}_node1.csv; \
        bash ${MXFS_TESTS_DIR}/mxfs_test.sh \
        --test ${test_name} \
        --node-id 1 \
        --total-nodes 1 \
        --mount ${MOUNT_POINT} \
        --device ${DEVICE} \
        --phase ${phase_dir} \
        ${NO_COLOR:+--no-color} \
        ${DEBUG:+--debug}" \
        > "$output_file" 2>&1 || rc=$?

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    case $rc in
        0) PASSED_TESTS=$((PASSED_TESTS + 1)); log_pass "$test_name" ;;
        2) SKIPPED_TESTS=$((SKIPPED_TESTS + 1)); log_skip "$test_name" ;;
        *)
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_NAMES+=("$test_name")
            log_fail "$test_name (see ${output_file})"
            # Show last 10 lines of output for context
            tail -10 "$output_file" 2>/dev/null | while IFS= read -r line; do
                echo "    $line"
            done
            ;;
    esac
}

# ---------- Run a cluster/stress test ----------
run_cluster_test() {
    local test_name="$1"
    local phase_dir="$2"
    local num_nodes="$3"
    log_info "Running: ${BOLD}${test_name}${RESET} (${num_nodes} nodes)"

    local output_dir="${RUN_DIR}/${test_name}"
    mkdir -p "$output_dir"

    # Clean test area on shared filesystem
    ssh_node 1 "rm -rf ${MOUNT_POINT}/.mxfs_test/${test_name} ${MOUNT_POINT}/.mxfs_barriers/${test_name}* 2>/dev/null; \
        mkdir -p ${MOUNT_POINT}/.mxfs_test/${test_name} ${MOUNT_POINT}/.mxfs_results" 2>/dev/null

    # Prepare per-node results directories
    for i in $(seq 1 "$num_nodes"); do
        ssh_node "$i" "mkdir -p ${MOUNT_POINT}/.mxfs_results/node${i}" 2>/dev/null &
    done
    wait

    # Launch test on all nodes in parallel
    local pids=()
    for i in $(seq 1 "$num_nodes"); do
        local host
        host=$(get_node_hostname "$i")
        "$MXFS_SSH_TOOL" "$host" "$PASS_FILE" \
            "export MXFS_TIMING_FILE=/tmp/mxfs_timing_${test_name}_node${i}.csv; \
                bash ${MXFS_TESTS_DIR}/mxfs_test.sh \
                --test ${test_name} \
                --node-id ${i} \
                --total-nodes ${num_nodes} \
                --mount ${MOUNT_POINT} \
                --device ${DEVICE} \
                --phase ${phase_dir} \
                ${NO_COLOR:+--no-color} \
                ${DEBUG:+--debug}" \
            > "${output_dir}/node${i}.log" 2>&1 &
        pids+=($!)
    done

    # Wait for all nodes, collect per-node exit codes
    local node_results=()
    for idx in "${!pids[@]}"; do
        local node_num=$((idx + 1))
        local nrc=0
        wait "${pids[$idx]}" || nrc=$?
        node_results+=("$nrc")
    done

    # Determine overall result
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local all_pass=1
    local any_skip=0
    for idx in "${!node_results[@]}"; do
        local nrc="${node_results[$idx]}"
        local node_num=$((idx + 1))
        case $nrc in
            0) ;;
            2) any_skip=1 ;;
            *)
                all_pass=0
                log_warn "  Node ${node_num} FAILED (rc=${nrc}, see ${output_dir}/node${node_num}.log)"
                tail -5 "${output_dir}/node${node_num}.log" 2>/dev/null | while IFS= read -r line; do
                    echo "      $line"
                done
                ;;
        esac
    done

    if [ "$all_pass" = "1" ] && [ "$any_skip" = "0" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_pass "$test_name (${num_nodes} nodes)"
    elif [ "$all_pass" = "1" ] && [ "$any_skip" = "1" ]; then
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        log_skip "$test_name"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_NAMES+=("$test_name")
        log_fail "$test_name (${num_nodes} nodes)"
    fi

    # Collect timing data from each node
    local timing_file="${TIMING_DIR}/${test_name}.csv"
    for i in $(seq 1 "$num_nodes"); do
        local host
        host=$(get_node_hostname "$i")
        local remote_timing
        remote_timing=$("$MXFS_SSH_TOOL" "$host" "$PASS_FILE" \
            "cat /tmp/mxfs_timing_${test_name}_node${i}.csv 2>/dev/null; rm -f /tmp/mxfs_timing_${test_name}_node${i}.csv" 2>/dev/null || true)
        if [ -n "$remote_timing" ]; then
            while IFS= read -r tline; do
                echo "node${i},${tline}" >> "$timing_file"
            done <<< "$remote_timing"
        fi
    done

    # Display timing summary for this test
    if [ -f "$timing_file" ]; then
        echo "  ${CYAN}Timing:${RESET}"
        # Group by operation, show min/max/avg across nodes
        local ops
        ops=$(cut -d',' -f2 "$timing_file" 2>/dev/null | sort -u)
        while IFS= read -r op; do
            [ -z "$op" ] && continue
            local values
            values=$(grep ",${op}," "$timing_file" 2>/dev/null | cut -d',' -f3)
            if [ -n "$values" ]; then
                local count=0 total=0 min=999999999 max=0
                while IFS= read -r v; do
                    [ -z "$v" ] && continue
                    count=$((count + 1))
                    total=$((total + v))
                    [ "$v" -lt "$min" ] 2>/dev/null && min=$v
                    [ "$v" -gt "$max" ] 2>/dev/null && max=$v
                done <<< "$values"
                if [ "$count" -gt 0 ]; then
                    local avg=$((total / count))
                    if [ "$count" -gt 1 ]; then
                        echo "    ${op}: avg=${avg}ms min=${min}ms max=${max}ms (${count} nodes)"
                    else
                        echo "    ${op}: ${avg}ms"
                    fi
                fi
            fi
        done <<< "$ops"
    fi

    # Copy results from shared filesystem to local results dir
    for i in $(seq 1 "$num_nodes"); do
        local result_file
        result_file=$(ssh_node 1 "cat ${MOUNT_POINT}/.mxfs_results/node${i}/${test_name}.result 2>/dev/null" || true)
        if [ -n "$result_file" ]; then
            echo "$result_file" > "${output_dir}/node${i}.result"
        fi
    done
}

# ---------- Verify environment ----------
verify_environment() {
    log_info "Verifying environment on ${NUM_NODES} node(s)..."

    # Check all nodes have module loaded and mxfs mounted
    if ! verify_all_mounted "$NUM_NODES" "$MOUNT_POINT"; then
        echo ""
        log_fail "Not all nodes are ready. Deploy first:"
        log_fail "  tools/mxfs_deploy.sh --nodes ${NUM_NODES}"
        exit 1
    fi

    # Clean test working area (from node 1)
    ssh_node 1 "rm -rf ${MOUNT_POINT}/.mxfs_test ${MOUNT_POINT}/.mxfs_results ${MOUNT_POINT}/.mxfs_barriers 2>/dev/null; \
        mkdir -p ${MOUNT_POINT}/.mxfs_test ${MOUNT_POINT}/.mxfs_results" 2>/dev/null

    log_info "Environment verified."
}

# ---------- Cleanup test artifacts ----------
cleanup_test_area() {
    if [ "${MXFS_NO_CLEANUP:-0}" = "1" ]; then
        log_info "MXFS_NO_CLEANUP=1 — leaving test artifacts intact for inspection"
        return 0
    fi
    log_info "Cleaning up test artifacts..."
    ssh_node 1 "rm -rf ${MOUNT_POINT}/.mxfs_test ${MOUNT_POINT}/.mxfs_results ${MOUNT_POINT}/.mxfs_barriers 2>/dev/null" || true
}

# ---------- Main ----------
summary_header

# Run a specific test?
if [ -n "$SINGLE_TEST" ]; then
    verify_environment

    # Find which phase the test is in
    found_phase=""
    for pdir in single cluster stress; do
        if [ -f "${SCRIPT_DIR}/${pdir}/${SINGLE_TEST}.sh" ]; then
            found_phase="$pdir"
            break
        fi
    done

    if [ -z "$found_phase" ]; then
        log_fail "Test not found: ${SINGLE_TEST}"
        exit 1
    fi

    if [ "$found_phase" = "single" ]; then
        run_single_test "$SINGLE_TEST" "$found_phase"
    else
        run_cluster_test "$SINGLE_TEST" "$found_phase" "$NUM_NODES"
    fi

    cleanup_test_area
    summary_footer
    [ "$FAILED_TESTS" -gt 0 ] && exit 1
    exit 0
fi

# Run by phase
verify_environment

run_phase() {
    local pdir="$1"
    local tests_dir="${SCRIPT_DIR}/${pdir}"

    if [ ! -d "$tests_dir" ]; then
        return
    fi

    local test_scripts=()
    for f in "$tests_dir"/test_*.sh; do
        [ -f "$f" ] || continue
        test_scripts+=("$(basename "$f" .sh)")
    done

    if [ ${#test_scripts[@]} -eq 0 ]; then
        log_info "No tests in ${pdir}/"
        return
    fi

    echo ""
    echo "${BOLD}--- Phase: ${pdir} (${#test_scripts[@]} tests) ---${RESET}"
    echo ""

    for test_name in "${test_scripts[@]}"; do
        if [ "$pdir" = "single" ]; then
            run_single_test "$test_name" "$pdir"
        else
            run_cluster_test "$test_name" "$pdir" "$NUM_NODES"
        fi
    done
}

case "$PHASE" in
    single)  run_phase "single" ;;
    cluster) run_phase "cluster" ;;
    stress)  run_phase "stress" ;;
    all)
        run_phase "single"
        run_phase "cluster"
        run_phase "stress"
        ;;
    *)
        log_fail "Unknown phase: $PHASE"
        exit 1
        ;;
esac

cleanup_test_area
summary_footer

[ "$FAILED_TESTS" -gt 0 ] && exit 1
exit 0
