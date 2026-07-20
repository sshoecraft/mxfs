#!/bin/bash
# Sess29 4-node TCP stress harness.  Same logic as mxfs_stress_v033.sh
# but runs dd+rm in parallel across N nodes.
# Args: $1 = iterations, $2 = MB per dd, [$3+ = node IPs]
ITERS=${1:-15}
MB=${2:-256}
shift 2
NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(192.168.120.186 192.168.120.182 192.168.120.140 192.168.120.174)
fi
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass

run() { "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you' ; }

START_TS=$(date -u '+%Y-%m-%d %H:%M:%S')
echo "=== run start: $START_TS, ${#NODES[@]} nodes: ${NODES[*]} ==="

since_start() {
  local N=$1
  run "$N" "sudo journalctl -k --since='$START_TS' --no-pager" 2>/dev/null
}

shutdown_check() {
  local got=0
  for N in "${NODES[@]}"; do
    local n
    n=$(since_start "$N" | grep -cE 'Internal error|Shutting down|SHUTDOWN|Corruption|removename rc=|DLM inode lock failed|DLM inode lock unrecoverable')
    if [ "${n:-0}" -gt 0 ]; then
      echo "  *** $N has $n failure markers ***"
      since_start "$N" | grep -E 'Internal error|Shutting down|SHUTDOWN|Corruption|removename rc=|DLM inode' | head -3
      got=1
    fi
  done
  return $got
}

for i in $(seq 1 "$ITERS"); do
  echo "=== iter $i / $ITERS ==="

  # Warmup + drop_caches on all nodes
  pids=()
  for N in "${NODES[@]}"; do
    nodeshort=$(echo "$N" | awk -F. '{print $4}')
    ( run "$N" "sudo dd if=/dev/zero of=/mnt/shared/perf_w$nodeshort bs=1M count=$MB conv=fdatasync status=none && sudo rm -f /mnt/shared/perf_w$nodeshort && sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null && echo PRE_OK_$nodeshort" >/tmp/_pre_$nodeshort.$$ ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done

  # Parallel dd: each node creates its own perf_t<lastoctet>
  pids=()
  rm -f /tmp/_dd_*.$$
  for N in "${NODES[@]}"; do
    nodeshort=$(echo "$N" | awk -F. '{print $4}')
    ( run "$N" "sudo dd if=/dev/zero of=/mnt/shared/perf_t$nodeshort bs=1M count=$MB conv=fdatasync status=none && echo DD_OK_$nodeshort || echo DD_FAIL_$nodeshort" >/tmp/_dd_$nodeshort.$$ ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done

  # Verify all dd's succeeded
  fail=0
  for N in "${NODES[@]}"; do
    nodeshort=$(echo "$N" | awk -F. '{print $4}')
    out=$(cat /tmp/_dd_$nodeshort.$$ 2>/dev/null)
    if ! echo "$out" | grep -q DD_OK_$nodeshort; then
      echo "*** dd FAILED on $N at iter $i ***"
      echo "$out"
      fail=1
    fi
  done
  rm -f /tmp/_dd_*.$$
  if [ $fail -ne 0 ]; then
    shutdown_check
    exit 1
  fi

  # Sequential rm: one node at a time
  for N in "${NODES[@]}"; do
    nodeshort=$(echo "$N" | awk -F. '{print $4}')
    out=$(run "$N" "sudo rm -f /mnt/shared/perf_t$nodeshort && echo RM_OK_$nodeshort || echo RM_FAIL_$nodeshort")
    if ! echo "$out" | grep -q RM_OK_$nodeshort; then
      echo "*** rm FAILED on $N at iter $i: $out ***"
      shutdown_check
      exit 1
    fi
  done

  if ! shutdown_check; then
    echo "*** FAILED at iter $i — dmesg corruption marker ***"
    exit 1
  fi
  echo "  iter $i OK (all ${#NODES[@]} nodes dd+rm ok)"
done
echo
echo "=== ALL $ITERS ITERS PASSED across ${#NODES[@]} nodes ==="
