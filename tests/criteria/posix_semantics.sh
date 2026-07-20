#!/bin/bash
# Criterion: POSIX semantics preserved on every operation, from every
# node, under every concurrency pattern.  Verifier: run the existing
# tests/run_tests.sh single + cluster phases against N nodes and assert
# every test reports PASS.  Threshold: 0 failed tests.
#
# Deliberately wraps the existing harness rather than re-implementing
# it.  If you want to verify just POSIX coverage without spinning up
# the cluster, pass --nodes 1 (single phase only on 1 node).

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

parse_common_args "$@"
N=${#NODES[@]}
PHASE="all"
if [ "$N" -lt 2 ]; then PHASE="single"; fi
# Distinct results key per phase: the gate runs this criterion twice
# (--nodes 1 and --nodes 16); a shared key let the later run mask the
# earlier one in .criteria_results.json.
if [ "$N" -lt 2 ]; then
    result_init "posix_semantics_single"
else
    result_init "posix_semantics_multi${N}"
fi
set_script_timeout 600

# run_tests.sh requires mxfs pre-mounted on every node
export MXFS_NODE_OFFSET=16
# Default MXFS_TESTS_DIR (/mnt/mxfs-src/tests) does not exist on the
# mxfs.1 test VMs — they mount /src from clyde via NFS instead.  Point
# the runner at that path so the harness scripts are reachable.
: "${MXFS_TESTS_DIR:=${MXFS_REPO}/tests}"
export MXFS_TESTS_DIR
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
teardown_all "${NODES[*]}"
if [ "$N" -lt 2 ]; then
    fresh_cluster_mount "$NODE0" \
        || result_fail "n/a" "mount-ok" "cluster mount failed before harness"
else
    fresh_cluster_mount "$NODE0" "${REST[@]}" \
        || result_fail "n/a" "mount-ok" "cluster mount failed before harness"
fi

LOG=$(mktemp -t posix_semantics.XXXXXX.log)
MXFS_NODE_OFFSET=16 "$MXFS_REPO/tests/run_tests.sh" --nodes "$N" --phase "$PHASE" \
    --pass-file "$MXFS_PASS" --device "$MXFS_DEV" --mount-point "$MXFS_MOUNT" \
    > "$LOG" 2>&1
rc=$?

parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

# run_tests.sh prints PASS/FAIL per test, wrapped in ANSI color escapes.
# Strip the escapes before counting so the regex matches.
SAN=$(mktemp -t posix_sanitised.XXXXXX.log)
sed 's/\x1b\[[0-9;]*m//g' "$LOG" > "$SAN"
passed=$(grep -cE '^\[PASS\]' "$SAN"); passed=${passed:-0}
failed=$(grep -cE '^\[FAIL\]' "$SAN"); failed=${failed:-0}
skipped=$(grep -cE '^\[SKIP\]' "$SAN"); skipped=${skipped:-0}
rm -f "$SAN"

measured="phase=$PHASE nodes=$N passed=$passed failed=$failed skipped=$skipped"
threshold="failed=0"

[ "$rc" = "0" ] && [ "$failed" = "0" ] \
    || result_fail "$measured rc=$rc" "$threshold" "see $LOG"
result_pass "$measured" "$threshold"
