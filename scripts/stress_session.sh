#!/bin/bash
# v0.3.3 stress reproducer (sess23 v3: robust mark capture, exit-code checks)
# Args: $1 = iterations, $2 = MB per dd
ITERS=${1:-15}
MB=${2:-512}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
T1=192.168.120.186
T2=192.168.120.182

# Strip SSH banner / warnings; trim to single value when expected.
runclean() { "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you|^$' ; }
run()      { "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you' ; }

# Use journalctl --since to scope kernel logs to "since this run started".
# Buffer-wrap-safe (journal is persistent).
# Test nodes run in UTC; we may run in any TZ.  Use UTC timestamp.
START_TS=$(date -u '+%Y-%m-%d %H:%M:%S')
echo "=== run start: $START_TS ==="

since_start() {
  local N=$1
  runclean "$N" "sudo journalctl -k --since='$START_TS' --no-pager"
}

dump_new_dmesg() {
  local N=$1
  since_start "$N" | grep -E 'Internal error|Shutting down|SHUTDOWN|Corruption|Free inode|DLM inode lock failed|DLM inode lock unrecoverable|MX-INSTR|P28|P29|P30|FREE-AG-EXTENT|RIGHT-FAIL|LEFT-FAIL|bnobt' | tail -40
}

shutdown_check() {
  local got=0
  local t1new t2new
  t1new=$(since_start "$T1" | grep -cE 'Internal error|Shutting down|SHUTDOWN|Corruption|Free inode|DLM inode lock failed|DLM inode lock unrecoverable')
  t2new=$(since_start "$T2" | grep -cE 'Internal error|Shutting down|SHUTDOWN|Corruption|Free inode|DLM inode lock failed|DLM inode lock unrecoverable')
  if [ "$t1new" -gt 0 ]; then echo "  *** T1 has $t1new failure markers ***"; dump_new_dmesg "$T1"; got=1; fi
  if [ "$t2new" -gt 0 ]; then echo "  *** T2 has $t2new failure markers ***"; dump_new_dmesg "$T2"; got=1; fi
  return $got
}

for i in $(seq 1 $ITERS); do
  echo "=== iter $i / $ITERS ==="

  T1_PRE=$(run "$T1" "sudo dd if=/dev/zero of=/mnt/shared/perf_w bs=1M count=$MB conv=fdatasync status=none && sudo rm -f /mnt/shared/perf_w && sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null && echo T1_PRE_OK") &
  P1=$!
  T2_PRE=$(run "$T2" "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null && echo T2_PRE_OK") &
  P2=$!
  wait $P1; wait $P2
  # NOTE: The above `T1_PRE=$(...) &` doesn't actually capture, but we don't use
  #       the captured values — we just need both to finish.

  rm -f /tmp/_t1dd.$$ /tmp/_t2dd.$$
  ( run "$T1" "sudo dd if=/dev/zero of=/mnt/shared/perf_t1 bs=1M count=$MB conv=fdatasync status=none && echo T1_DD_OK || echo T1_DD_FAIL" > /tmp/_t1dd.$$ 2>&1 ) &
  PT1=$!
  ( run "$T2" "sudo dd if=/dev/zero of=/mnt/shared/perf_t2 bs=1M count=$MB conv=fdatasync status=none && echo T2_DD_OK || echo T2_DD_FAIL" > /tmp/_t2dd.$$ 2>&1 ) &
  PT2=$!
  wait $PT1; wait $PT2

  T1_DD=$(cat /tmp/_t1dd.$$ 2>/dev/null)
  T2_DD=$(cat /tmp/_t2dd.$$ 2>/dev/null)
  rm -f /tmp/_t1dd.$$ /tmp/_t2dd.$$

  T1_OK=0; T2_OK=0
  echo "$T1_DD" | grep -q T1_DD_OK && T1_OK=1
  echo "$T2_DD" | grep -q T2_DD_OK && T2_OK=1

  if [ "$T1_OK" != 1 ] || [ "$T2_OK" != 1 ]; then
    echo "*** dd FAILED at iter $i (T1_OK=$T1_OK T2_OK=$T2_OK) ***"
    echo "--- T1 output ---"
    echo "$T1_DD"
    echo "--- T2 output ---"
    echo "$T2_DD"
    shutdown_check
    exit 1
  fi

  T1_RM=$(run "$T1" "sudo rm -f /mnt/shared/perf_t1 && echo T1_RM_OK || echo T1_RM_FAIL")
  T2_RM=$(run "$T2" "sudo rm -f /mnt/shared/perf_t2 && echo T2_RM_OK || echo T2_RM_FAIL")

  if ! echo "$T1_RM" | grep -q T1_RM_OK; then
    echo "*** T1 rm failed at iter $i: $T1_RM ***"; shutdown_check; exit 1
  fi
  if ! echo "$T2_RM" | grep -q T2_RM_OK; then
    echo "*** T2 rm failed at iter $i: $T2_RM ***"; shutdown_check; exit 1
  fi

  if ! shutdown_check; then
    echo "*** FAILED at iter $i — dmesg corruption marker ***"
    exit 1
  fi
  echo "  iter $i OK (T1+T2 dd+rm ok)"
done
echo
echo "=== ALL $ITERS ITERS PASSED (genuine: both nodes dd+rm ok every iter) ==="
