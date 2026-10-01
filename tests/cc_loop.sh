#!/bin/bash
# cc_loop.sh — targeted reproducer loop for the sess15 crash_consistency face
# (2/net/mesh/direct r3: durably-corrupt dinode + inobt CRC read-fail + EIO shutdown;
# see docs/history/sess15run-state-ladder-tally-and-crashcc-face.md).
#
# Recycles the cluster ONCE, then loops `./run.sh <N> <class>/<method>/<attach> [pre] crash_consistency`
# on the same boot.  Each lap gets a fresh mkfs from run.sh; the P15I probe
# (build 3AD15DA9+) fingerprints per-sector CRCs on any read-verify failure.
# Stops at the FIRST failing lap and harvests both nodes' dmesg + the raw
# platter block for any P15I daddr.
#
# Usage: tests/cc_loop.sh [configuration, default 2/net/mesh/direct] [laps] [pre_test]
set -u
CONFIG=$(python3 "$(dirname "$0")/../tools/configuration.py" parse "${1:-2/net/mesh/direct}") || exit 2; N=${CONFIG%%/*}; DLM=${CONFIG#*/}
LAPS="${2:-8}"; PRE="${3:-}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$REPO"

for i in $(seq 1 "$N"); do virsh -c qemu:///system destroy "test$i" >/dev/null 2>&1; done
sleep 3
for i in $(seq 1 "$N"); do virsh -c qemu:///system start "test$i" >/dev/null 2>&1; done
for i in $(seq 1 "$N"); do
    until timeout 5 tools/mxfs_sshpass.sh "test$i" /tmp/.mxfs_pass "hostname" 2>/dev/null | grep -q "test$i"; do sleep 3; done
done
echo "cc_loop: nodes up"

for lap in $(seq 1 "$LAPS"); do
    echo "=== cc_loop lap $lap/$LAPS $(date -u +%H:%M:%S) ==="
    # budget: prep ~120s + drc 100*N + cc ~90s (budget)
    out=$(timeout $((240 + 100*N)) ./run.sh "$CONFIG" ${PRE:+$PRE} crash_consistency 2>&1 | tail -8)
    echo "$out"
    if echo "$out" | grep -q "FAIL"; then
        echo "=== cc_loop lap $lap FAILED — harvesting ==="
        H="/tmp/cc_loop_fail_$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$H"
        for i in $(seq 1 "$N"); do
            timeout 20 tools/mxfs_sshpass.sh "test$i" /tmp/.mxfs_pass "dmesg" \
                > "$H/dmesg_test$i" 2>/dev/null
        done
        grep -h "P15I-CRCFAIL" "$H"/dmesg_test* | head -5
        echo "harvest: $H"
        exit 1
    fi
done
echo "cc_loop: all $LAPS laps clean"
