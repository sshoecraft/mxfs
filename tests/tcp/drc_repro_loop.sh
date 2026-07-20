#!/bin/bash
# drc_repro_loop.sh [ITERS] [MODARGS] — reboot all 8 nodes (so the first prep
# insmods fresh with MODARGS), then loop 8/tcp dir_reuse_coherency until a
# single-dirent loss (readdir!=800) / DUP (readdir>800), or ITERS exhausted.
# sess31: hunt the rare durable single-dirent loss now the duplicate-IQN infra
# noise is gone. Logs HIT to stdout (steve cannot write /root for a marker).
set -u
ITERS="${1:-8}"; MA="${2:-}"; RNDS="${3:-24}"
cd /src/mxfs
SSH=/src/mxfs/tools/mxfs_sshpass.sh
for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
sleep 7
for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
for w in $(seq 1 40); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
echo "nodes_up=$up after reboot $(date -u +%H:%M:%S)"
for n in 1 2 3 4 5 6 7 8; do timeout 6 $SSH test$n /tmp/.mxfs_pass "rm -f /root/drc_failrounds.txt" >/dev/null 2>&1; done
export MXFS_EXTRA_MODARGS="$MA"
for it in $(seq 1 "$ITERS"); do
    echo "=== iter $it $(date -u +%H:%M:%S) MA=[$MA] ==="
    MXFS_TEST_ENV="DRC_STREAM=1 DRC_ROUNDS=$RNDS" timeout 540 ./run.sh 8 tcp dir_reuse_coherency 2>&1 \
        | grep -vE '^Warning:|^Unauthorized|^If you' | grep -E "  (PASS|FAIL)  |prep OK|ABORT"
    if [ "$it" = 1 ]; then
        echo -n "  param dir_write_merge="
        timeout 6 $SSH test1 /tmp/.mxfs_pass "cat /sys/module/mxfs/parameters/dir_write_merge 2>/dev/null" 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'
    fi
    hit=0
    for n in 1 2 3 4 5 6 7 8; do
        fr=$(timeout 8 $SSH test$n /tmp/.mxfs_pass "cat /root/drc_failrounds.txt 2>/dev/null | head -2" 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you')
        [ -n "$fr" ] && { echo "  >>> test$n FAILROUND: $fr"; hit=1; }
    done
    [ "$hit" = 1 ] && { echo "=== HIT iter $it ==="; break; }
done
echo "=== loop done $(date -u +%H:%M:%S) ==="
