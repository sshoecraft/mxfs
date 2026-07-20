#!/bin/bash
# measure_clean_rate.sh — measure the per-run clean (16/16) rate of the 2/tcp
# suite on FRESHLY-REBOOTED clusters (one suite run per fresh boot, so the
# cumulative back-to-back wedge doesn't confound the per-run coherency result).
# Usage: tests/tcp/measure_clean_rate.sh [iters]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO"
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
ITERS="${1:-4}"
VIRSH="virsh -c qemu:///system"

clean=0
for it in $(seq 1 "$ITERS"); do
    echo "===== ITER $it: reboot test1/test2 ====="
    for n in test1 test2; do $VIRSH destroy "$n" >/dev/null 2>&1; done
    sleep 3
    for n in test1 test2; do $VIRSH start "$n" >/dev/null 2>&1; done
    # wait for ssh
    for w in $(seq 1 30); do
        if timeout 8 bash "$SSH" test1 "$PASS" true >/dev/null 2>&1 && \
           timeout 8 bash "$SSH" test2 "$PASS" true >/dev/null 2>&1; then break; fi
        sleep 5
    done
    sleep 5
    echo "----- ITER $it: run suite -----"
    out=$(timeout 560 ./run.sh 2 tcp 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you')
    fails=$(echo "$out" | grep -cE '  FAIL ')
    echo "$out" | grep -E '  (PASS|FAIL) ' | sed "s/^/it$it: /"
    if [ "$fails" = 0 ] && echo "$out" | grep -q 'ran=16'; then
        clean=$((clean+1)); echo "ITER $it: CLEAN 16/16"
    else
        echo "ITER $it: $fails FAIL(s)"
    fi
done
echo "===== RESULT: $clean / $ITERS runs CLEAN 16/16 ====="
