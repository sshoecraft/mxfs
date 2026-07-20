#!/bin/bash
# Loop isolated concurrent_mkdir until it FAILS (the non-deterministic
# durable dirent lost-update).  Clears dmesg on all 16 before each iter,
# so on failure the per-node dmesg holds ONLY the failing run's probes.
# Usage: tests/loop_cmkdir.sh [max_iters]
set -u
cd /src/mxfs
P=/tmp/.mxfs_pass
MAX=${1:-8}
for i in $(seq 1 "$MAX"); do
  for n in $(seq 1 16); do
    timeout 8 tools/mxfs_sshpass.sh test$n $P 'dmesg -C >/dev/null 2>&1' >/dev/null 2>&1 &
  done
  wait
  echo "=== iter $i $(date -u +%T) ==="
  out=$(MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests timeout 120 \
        bash tests/run_tests.sh --nodes 16 --test test_concurrent_mkdir \
        --pass-file "$P" --device /dev/sda --mount-point /mnt/shared --no-color 2>&1 \
        | grep -v -E "Permanently added|Unauthorized|disconnect immediately|^$")
  line=$(echo "$out" | grep -iE "expected.*actual|test_concurrent_mkdir \(16" | head -3)
  echo "$line"
  if echo "$out" | grep -qiE "\[FAIL\] +test_concurrent_mkdir|expected=.*actual="; then
    echo "FAILURE on iter $i — dmesg preserved on all nodes"
    exit 1
  fi
done
echo "no failure in $MAX iters"
exit 0
