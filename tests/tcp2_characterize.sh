#!/bin/bash
# tcp2_characterize.sh — repeatedly run the full 2/tcp suite (or a subset),
# clean-rebooting both nodes before each run, and log per-test PASS/FAIL plus
# any dmesg shutdown/oops markers from both nodes.  Used to measure the true
# flake rate of the 2/tcp criterion and capture failure evidence (RULE 4).
#
# Usage: tcp2_characterize.sh <iters> [test ...]
#   <iters>      number of full clean-reboot suite runs
#   [test ...]   optional explicit subset (default: all 2/tcp tests)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
ITERS="${1:?usage: tcp2_characterize.sh <iters> [test...]}"; shift || true
ONLY=("$@")
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
LOG="$REPO/tests/tcp2_characterize.log"
echo "=== characterize start $(date -u) iters=$ITERS only='${ONLY[*]:-ALL}' ===" | tee -a "$LOG"
for i in $(seq 1 "$ITERS"); do
    echo "----- ITER $i/$ITERS $(date -u +%T) -----" | tee -a "$LOG"
    bash "$REPO/tests/reboot_cluster.sh" 2 >/dev/null 2>&1
    # snapshot dmesg cursor on both nodes
    for n in test1 test2; do
        timeout 8 "$SSH" "$n" "$PF" 'dmesg --clear 2>/dev/null' >/dev/null 2>&1
    done
    out=$(timeout 1500 ./run.sh 2 tcp "${ONLY[@]}" 2>&1)
    echo "$out" | grep -E '  (PASS|FAIL) ' | tee -a "$LOG"
    # capture shutdown/oops/corruption markers
    for n in test1 test2; do
        hits=$(timeout 8 "$SSH" "$n" "$PF" "dmesg 2>/dev/null | grep -iE 'shutdown|corruption|EFSBADCRC|EFSCORRUPTED|BUG:|Oops|call trace|DLM AG lock failed|trans_cancel' | tail -20")
        if [ -n "$hits" ]; then
            echo "  >>> $n dmesg:" | tee -a "$LOG"
            echo "$hits" | sed 's/^/      /' | tee -a "$LOG"
        fi
    done
done
echo "=== characterize done $(date -u) ===" | tee -a "$LOG"
