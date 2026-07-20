#!/bin/bash
# posix_phase_timing.sh — diagnostic: run the posix_semantics 16-node
# workload (run_tests.sh --phase all) with a per-test wall-clock stamp
# so we can see WHICH test makes the criterion exceed its 600s budget.
#
# Not a gate criterion; a timing probe.  Mounts a fresh 16-node cluster
# exactly like posix_semantics.sh, then streams run_tests.sh output with
# an epoch+delta prefix on every "Running:" / "[PASS]" / "[FAIL]" line.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

parse_common_args "$@"
N=${#NODES[@]}
export MXFS_NODE_OFFSET=16
: "${MXFS_TESTS_DIR:=${MXFS_REPO}/tests}"; export MXFS_TESTS_DIR
NODE0="${NODES[0]}"; REST=("${NODES[@]:1}")

echo "=== teardown + fresh mount on $N nodes $(date -u +%T) ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" || { echo "MOUNT FAILED"; exit 1; }
echo "=== mounted, starting run_tests.sh --phase ${PHASE:-all} $(date -u +%T) ==="

PHASE_RUN="${POSIX_PHASE:-all}"
MXFS_NODE_OFFSET=16 "$MXFS_REPO/tests/run_tests.sh" --nodes "$N" --phase "$PHASE_RUN" \
    --pass-file "$MXFS_PASS" --device "$MXFS_DEV" --mount-point "$MXFS_MOUNT" 2>&1 \
  | awk 'BEGIN{t0=systime();last=t0}
         /Running:|\[PASS\]|\[FAIL\]|\[SKIP\]|--- Phase/{
            now=systime(); printf "[+%4ds d=%3ds] %s\n", now-t0, now-last, $0; last=now; next}
         {print}'

echo "=== done $(date -u +%T) ==="
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"
