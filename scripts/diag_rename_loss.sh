#!/bin/bash
# diag_rename_loss.sh — instrument the cache_coherency rename_visibility
# batch-loss (sess30 run14d).  Repro recipe (proven 2026-06-12):
#   fresh 4-node cluster -> test_cross_visibility (PASS) ->
#   test_rename_visibility FAILS: ONE node's whole batch of same-dir
#   dir-block modifications (creates, renames, or unlinks depending on
#   run) reverts.  Standalone rename on a fresh FS passes 8/8 — the
#   trigger is inode/dir-block REUSE from cross_visibility's cleanup.
#
# This driver:
#   1. reset4 fresh cluster
#   2. runs test_cross_visibility (the churn that frees inodes)
#   3. starts per-node watchers that snapshot `ls` of the rename dir
#      every 0.5s (timestamped) + records the dir ino as soon as it exists
#   4. runs test_rename_visibility
#   5. saves all 4 nodes' dmesg + the snapshots under /tmp/diag_rl.<pid>/
#
# Usage: scripts/diag_rename_loss.sh
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
DIR=$MNT/.mxfs_test/rename_visibility
OUT=/tmp/diag_rl.$$
mkdir -p "$OUT"
export MXFS_TESTS_DIR=/src/mxfs/tests

rn(){ timeout 50 "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -vE 'Warning|Unauth|disconn|^$'; }

echo "=== reset cluster"
bash /src/mxfs/tests/reset4.sh 4 | tail -1

echo "=== cross_visibility churn"
timeout 200 /src/mxfs/tests/run_tests.sh --nodes 4 --phase cluster \
    --test test_cross_visibility --pass-file "$PASS" \
    --device /dev/sda --mount-point "$MNT" > "$OUT/cv.log" 2>&1
echo "cv rc=$?"

# Loop rename attempts until one fails (the loss is intermittent;
# active ls-watchers perturb the locking and suppress it — observer
# effect proven attempt 1, 2026-06-12).  Passive: capture the dir ino
# with a single stat per attempt, no polling.
MAX_ATTEMPTS=${1:-6}
for A in $(seq 1 "$MAX_ATTEMPTS"); do
    echo "=== attempt $A: clearing dmesg"
    for n in 1 2 3 4; do rn test$n "dmesg -C" >/dev/null; done

    (
        timeout 100 "$SSH" test1 "$PASS" '
            for i in $(seq 1 300); do
                ino=$(stat -c %i '"$DIR"' 2>/dev/null) && { echo "INO=$ino"; exit 0; }
                sleep 0.2
            done; echo INO=none' 2>/dev/null \
            | grep -E '^INO=' > "$OUT/ino_a$A.log"
    ) &
    WPID=$!

    timeout 200 /src/mxfs/tests/run_tests.sh --nodes 4 --phase cluster \
        --test test_rename_visibility --pass-file "$PASS" \
        --device /dev/sda --mount-point "$MNT" > "$OUT/rv_a$A.log" 2>&1
    rv_rc=$?
    wait "$WPID" 2>/dev/null
    echo "attempt $A: rv rc=$rv_rc ino=$(cat "$OUT/ino_a$A.log" 2>/dev/null)"

    if [ "$rv_rc" != "0" ]; then
        echo "=== FAILURE CAUGHT at attempt $A — collecting dmesg"
        for n in 1 2 3 4; do
            rn test$n "dmesg" > "$OUT/dmesg_t$n.log"
        done
        grep -m2 -hE "failure\(s\)" "$OUT/rv_a$A.log" || true
        echo "=== out=$OUT"
        exit 1
    fi
done
echo "=== no failure in $MAX_ATTEMPTS attempts: out=$OUT"
exit 0
