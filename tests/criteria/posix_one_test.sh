#!/bin/bash
# posix_one_test.sh — diagnostic: mount a fresh N-node cluster (exactly
# like posix_semantics.sh), clear dmesg on every node, run ONE named
# test via run_tests.sh --test, then dump per-node dmesg tail.  For
# fast RULE-4 iteration on a single failing cluster test (e.g.
# test_dir_stress) without paying for the whole --phase all run.
#
# Usage: POSIX_TEST=test_dir_stress bash tests/criteria/posix_one_test.sh --nodes 16
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

parse_common_args "$@"
N=${#NODES[@]}
export MXFS_NODE_OFFSET=16
: "${MXFS_TESTS_DIR:=${MXFS_REPO}/tests}"; export MXFS_TESTS_DIR
: "${POSIX_TEST:?set POSIX_TEST=test_name}"
NODE0="${NODES[0]}"; REST=("${NODES[@]:1}")

echo "=== teardown + fresh mount on $N nodes $(date -u +%T) ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" || { echo "MOUNT FAILED"; exit 1; }
echo "=== clearing dmesg on all nodes ==="
parallel_ssh_quiet "${NODES[*]}" "dmesg -C 2>/dev/null"
echo "=== mounted, running $POSIX_TEST $(date -u +%T) ==="

t0=$SECONDS
MXFS_NODE_OFFSET=16 "$MXFS_REPO/tests/run_tests.sh" --nodes "$N" --test "$POSIX_TEST" \
    --pass-file "$MXFS_PASS" --device "$MXFS_DEV" --mount-point "$MXFS_MOUNT" 2>&1
rc=$?
echo "=== $POSIX_TEST done rc=$rc elapsed=$((SECONDS-t0))s $(date -u +%T) ==="

echo "=== per-node dmesg (mxfs/shutdown/assert lines) ==="
for n in "${NODES[@]}"; do
  echo "--- $n ---"
  timeout 12 "$MXFS_SSH" "$n" "$MXFS_PASS" \
    "dmesg 2>/dev/null | grep -iE 'mxfs|shutdown|corrupt|EFSBADCRC|assert|BUG|P-|metadata I/O' | tail -25" 2>/dev/null \
    | grep -v -iE "unauthorized|authorized user|disconnect|warning: perman"
done

if [ "${POSIX_KEEP_MOUNTED:-0}" != "1" ]; then
  echo "=== teardown $(date -u +%T) ==="
  parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"
fi
