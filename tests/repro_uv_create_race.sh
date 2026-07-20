#!/bin/bash
# repro_uv_create_race.sh — sess127: reproduce the test_unlink_visibility
# create-phase failure in isolation, with PER-COMPONENT userspace diagnosis.
#
# All 4 nodes simultaneously: mkdir -p SHARED_DIR ; loop 30x echo > nodeN_fileM.
# On EVERY failed create, immediately stat each path component to identify
# WHICH component returns ENOENT (parent .mxfs_test vs the shared dir vs the
# create itself), with ms timestamps for correlation against kernel realns.
#
# Usage: tests/repro_uv_create_race.sh [iteration-tag]
# Output: /tmp/uv_race_nodeN.log on each node (collected to stdout at end).
set -u
TAG=${1:-r1}
PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SSH="$SCRIPT_DIR/../tools/mxfs_sshpass.sh"

# Clean any prior run's dir (from node1, best effort)
$SSH test1 $PASS "rm -rf /mnt/shared/.mxfs_test/uvrace_* 2>/dev/null" >/dev/null 2>&1

D="/mnt/shared/.mxfs_test/uvrace_$TAG"

i=0
for n in $NODES; do
    i=$((i+1))
    $SSH $n $PASS "
        N=$i
        D='$D'
        LOG=/tmp/uv_race_node\$N.log
        : > \$LOG
        ts() { date -u +%s.%3N; }
        # synchronize: poll for a common start file in the (existing) parent
        mkdir -p /mnt/shared/.mxfs_test 2>>\$LOG
        tries=0
        while [ ! -e /mnt/shared/.mxfs_test/uvrace_go_$TAG ]; do
            sleep 0.05
            tries=\$((tries+1))
            if [ \$tries -gt 600 ]; then echo \"\$(ts) POLL-TIMEOUT\" >> \$LOG; exit 9; fi
        done
        echo \"\$(ts) START\" >> \$LOG
        mkdir -p \$D 2>>\$LOG
        echo \"\$(ts) MKDIR rc=\$?\" >> \$LOG
        ok=0; fail=0
        for m in \$(seq 1 30); do
            F=\$D/node\${N}_file\$m
            if echo data_\$N_\$m > \$F 2>>\$LOG; then
                ok=\$((ok+1))
            else
                rc=\$?
                fail=\$((fail+1))
                echo \"\$(ts) CREATE-FAIL m=\$m rc=\$rc\" >> \$LOG
                stat -c '%n ino=%i' /mnt/shared/.mxfs_test >> \$LOG 2>&1
                stat -c '%n ino=%i' \$D >> \$LOG 2>&1
            fi
        done
        echo \"\$(ts) DONE ok=\$ok fail=\$fail\" >> \$LOG
        ls \$D 2>/dev/null | wc -l >> \$LOG
    " >/dev/null 2>&1 &
done

sleep 2
# fire the start gun from node1
$SSH test1 $PASS "touch /mnt/shared/.mxfs_test/uvrace_go_$TAG" >/dev/null 2>&1
wait

echo "=== collected logs ==="
for n in $NODES; do
    echo "--- $n ---"
    $SSH $n $PASS "cat /tmp/uv_race_node*.log 2>/dev/null" 2>/dev/null
done
echo "=== final dir content (from test1) ==="
$SSH test1 $PASS "ls $D 2>&1 | wc -l; ls $D 2>&1 | head -8" 2>/dev/null
$SSH test1 $PASS "rm -f /mnt/shared/.mxfs_test/uvrace_go_$TAG" >/dev/null 2>&1
