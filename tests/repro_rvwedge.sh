#!/bin/bash
# sess109: reproduce the AG-AIL push wedge that hangs test_rename_visibility
# in the cache_coherency criterion.  Runs cross_visibility (warm-up) then
# rename_visibility under the in-FS-barrier harness, while polling every
# node's dmesg for the P67-INSTR AG-AIL-STALL line.  On first stall, dumps
# the enhanced stall lines + blocked-task stacks from all nodes and kills
# the run so we don't wait the 900s timeout.
#
# Assumes the cluster is ALREADY mounted (run tests/reset4.sh 4 first).
# Usage: tests/repro_rvwedge.sh [N]
set -u
N=${1:-4}
NODES=(test1 test2 test3 test4)
PASS=/tmp/.mxfs_pass
SSH=tools/mxfs_sshpass.sh
export MXFS_NODE_OFFSET=16
export MXFS_TESTS_DIR=/src/mxfs/tests
OUT=/tmp/rvwedge.$$.log
: > "$OUT"

ssh_out() { timeout 25 bash "$SSH" "$1" "$PASS" "$2" 2>/dev/null; }
# returns 0 if dmesg on $1 contains AG-AIL-STALL
has_stall() { ssh_out "$1" "dmesg 2>/dev/null | grep -q AG-AIL-STALL && echo YES" | grep -q YES; }

for h in "${NODES[@]}"; do ssh_out "$h" "dmesg -C" >/dev/null & done; wait

RT=/src/mxfs/tests/run_tests.sh

echo "=== test_cross_visibility (warm-up) ==="
timeout 200 "$RT" --nodes "$N" --phase cluster --test test_cross_visibility \
  --pass-file "$PASS" --device /dev/sda --mount-point /mnt/shared >> "$OUT" 2>&1
echo "cross_visibility rc=$?"

echo "=== test_rename_visibility with wedge watcher ==="
( timeout 300 "$RT" --nodes "$N" --phase cluster --test test_rename_visibility \
    --pass-file "$PASS" --device /dev/sda --mount-point /mnt/shared >> "$OUT" 2>&1
  echo "RV_DONE rc=$?" >> "$OUT" ) &
RUNPID=$!

stall=0
for s in $(seq 1 50); do
  kill -0 "$RUNPID" 2>/dev/null || { echo "harness exited at ~$((s*6))s"; break; }
  for h in "${NODES[@]}"; do
    if has_stall "$h"; then echo ">>> AG-AIL-STALL on $h (~$((s*6))s)"; stall=1; break; fi
  done
  [ "$stall" = 1 ] && break
  sleep 6
done

if [ "$stall" = 1 ]; then
  for h in "${NODES[@]}"; do
    echo "================= $h: stall + edeadlk ================="
    ssh_out "$h" "dmesg | grep -E 'AG-AIL-STALL|P109-EDEADLK|P106-STALE' | tail -12"
    echo "----------------- $h: blocked tasks -----------------"
    ssh_out "$h" "echo w > /proc/sysrq-trigger; sleep 1; dmesg | sed -n '/Show Blocked State/,\$p' | grep -A20 -E 'rm |mv |kworker|run_tests|cat |task:' | tail -90"
  done
  kill -9 "$RUNPID" 2>/dev/null
fi
wait "$RUNPID" 2>/dev/null
echo "=== harness log tail ==="
tail -25 "$OUT"
echo "stall=$stall"
