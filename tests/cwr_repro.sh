#!/bin/bash
# cwr_repro.sh — fast 2-node cross_write_read reproducer with instr=1.
# Cleans the module (force rmmod to avoid "File exists" reset failures),
# fresh-mounts N nodes, enables mxfs.instr, clears dmesg, runs the
# cross_write_read cluster test once, and dumps the P97/P98/P99 detector
# lines from every node's dmesg.  Lives in the source tree per RULE 3.
#
# Usage: tests/cwr_repro.sh [N]   (default 2 nodes: test1..testN)
set -u
cd "$(dirname "$0")/.."
N=${1:-2}
NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done
PASS=/tmp/.mxfs_pass
SSH=tools/mxfs_sshpass.sh
clean() { for n in "${NODES[@]}"; do timeout 30 "$SSH" "$n" "$PASS" \
  "umount -f /mnt/shared 2>/dev/null; umount -l /mnt/shared 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null; lsmod|grep -c mxfs" >/dev/null 2>&1; done; }

echo "== force-clean ${NODES[*]} =="
clean
echo "== fresh mount =="
timeout 200 bash tests/reset4.sh "$N" > /tmp/cwr_reset.log 2>&1
grep -qE 'RESET_OK' /tmp/cwr_reset.log || { echo "RESET_FAIL"; tail -8 /tmp/cwr_reset.log; exit 1; }
echo "== enable instr + clear dmesg =="
for n in "${NODES[@]}"; do timeout 12 "$SSH" "$n" "$PASS" \
  "echo 1 > /sys/module/mxfs/parameters/instr; dmesg -C" >/dev/null 2>&1; done
echo "== run cross_write_read =="
export MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests
timeout 200 tests/run_tests.sh --nodes "$N" --phase cluster \
  --test test_cross_write_read --pass-file "$PASS" \
  --device /dev/sda --mount-point /mnt/shared > /tmp/cwr_run.log 2>&1
rc=$?
echo "run rc=$rc"
grep -iE 'PASS:|FAIL:|file is 1MB|correct md5' /tmp/cwr_run.log | head
echo "== detector lines =="
for n in "${NODES[@]}"; do
  echo "--- $n ---"
  timeout 15 "$SSH" "$n" "$PASS" \
    "dmesg | grep -E 'P97-INSTR|P98-GETATTR|P99-IGET' | tail -40" 2>&1 \
    | grep -v 'Warning\|Unauthorized\|authorized user'
done
