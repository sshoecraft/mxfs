#!/bin/bash
# validate_drc4.sh — clean-reset 4-node TCP cluster (virsh destroy+start
# test1-4), wait until reachable, then run the dir_reuse_coherency suite test
# under run.sh.  A dir_reuse FAIL wedges a node, so the per-run virsh reset is
# MANDATORY for a valid result (see ccmemory sess10run-REFUTED-fua_disable0).
#
# Usage:  bash tests/tcp/validate_drc4.sh [RUNS]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
SSH="$REPO/tools/mxfs_sshpass.sh"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
RUNS="${1:-1}"
NODES=(test1 test2 test3 test4)
V="virsh -c qemu:///system"

boot_wait() {
    for n in "${NODES[@]}"; do $V destroy "$n" >/dev/null 2>&1; done
    sleep 4
    for n in "${NODES[@]}"; do $V start "$n" >/dev/null 2>&1; done
    for i in $(seq 1 50); do
        ok=0
        for n in "${NODES[@]}"; do
            timeout 5 bash "$SSH" "$n" "$P" true >/dev/null 2>&1 && ok=$((ok+1))
        done
        [ "$ok" -eq "${#NODES[@]}" ] && { echo "boot_wait: all ${#NODES[@]} up (after $((i*5))s)"; return 0; }
        sleep 5
    done
    echo "boot_wait FAILED (only $ok/${#NODES[@]} up)"; return 1
}

pass=0; fail=0
for run in $(seq 1 "$RUNS"); do
    echo "============================================================"
    echo "=== VALIDATE run $run/$RUNS — $(date -u +%H:%M:%SZ) ==="
    echo "============================================================"
    boot_wait || { echo "run $run: BOOT FAIL"; fail=$((fail+1)); continue; }
    out=$(./run.sh 4 tcp dir_reuse_coherency 2>&1)
    echo "$out" | grep -vE '^Warning:|^Unauthorized|^If you' | tail -25
    if echo "$out" | grep -qE '  PASS  dir_reuse_coherency'; then
        echo ">>> run $run: PASS"; pass=$((pass+1))
    else
        echo ">>> run $run: FAIL"; fail=$((fail+1))
    fi
    echo ">>> tally: PASS=$pass FAIL=$fail"
done
echo "============================================================"
echo "FINAL: PASS=$pass FAIL=$fail of $RUNS"
