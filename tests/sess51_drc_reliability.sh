#!/bin/bash
# sess51_drc_reliability.sh — run 8/tcp dir_reuse_coherency N times, recovering
# the teardown rmmod-wedge (D-state [mxfs-worker] pins the module so prep ABORTs)
# by virsh-rebooting any node whose module won't unload before each iteration.
#
# Usage: tests/sess51_drc_reliability.sh [iters] [N] [dlm] [test]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
ITERS="${1:-5}"
N="${2:-8}"
DLM="${3:-tcp}"
TEST="${4:-dir_reuse_coherency}"
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
mapfile -t NODES < <(seq 1 "$N")

full_reboot() {
    # Always cold-reboot EVERY node before a run.  A partial reboot leaves the
    # non-rebooted nodes' SCSI-PR registrations + disklock slot claims live from
    # the prior mount; the fresh cluster then forms against stale fencing state
    # and a node gets isolated -> MASS readdir=0 (sess46).  A uniform clean slate
    # (all nodes fresh, like sess51 repro4 which passed 8/8) removes that variance.
    local n
    echo "  [reboot] cold-rebooting all ${#NODES[@]} nodes"
    for n in "${NODES[@]}"; do
        virsh -c qemu:///system destroy "test$n" >/dev/null 2>&1
    done
    sleep 2
    for n in "${NODES[@]}"; do
        virsh -c qemu:///system start "test$n" >/dev/null 2>&1
    done
    local i ok
    for i in $(seq 1 40); do
        ok=1
        for n in "${NODES[@]}"; do
            timeout 6 "$SSH" "test$n" "$PASS" "ls /src/mxfs/mxfs.ko >/dev/null 2>&1 && ! lsmod | grep -q '^mxfs '" >/dev/null 2>&1 || ok=0
        done
        [ "$ok" = 1 ] && { echo "  [reboot] all nodes up + clean (~$((i*8))s)"; break; }
        sleep 8
    done
    sleep 5   # brief settle for network/iscsi
}

pass=0; fail=0
for it in $(seq 1 "$ITERS"); do
    echo "==================== ITER $it/$ITERS ($N/$DLM $TEST) ===================="
    full_reboot
    for n in "${NODES[@]}"; do
        timeout 8 "$SSH" "test$n" "$PASS" "rm -f /root/drc_failrounds.txt 2>/dev/null" >/dev/null 2>&1 &
    done
    wait
    out=$(MXFS_EXTRA_MODARGS="${MXFS_EXTRA_MODARGS:-}" MXFS_TEST_ENV="DRC_STREAM=1" ./run.sh "$N" "$DLM" "$TEST" 2>&1)
    res=$(echo "$out" | grep -E "  (PASS|FAIL)  $TEST" | tail -1)
    if echo "$res" | grep -q PASS; then
        pass=$((pass+1)); echo "  ITER $it: PASS   [$res]"
    else
        fail=$((fail+1)); echo "  ITER $it: FAIL   [$res]"
        echo "$out" | grep -E "PREP FAIL|ABORT|nodes_pass" | head
    fi
    echo "  running tally: PASS=$pass FAIL=$fail"
done
echo "==================== DONE: PASS=$pass FAIL=$fail / $ITERS ===================="
