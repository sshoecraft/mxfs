#!/bin/bash
# loop_tds.sh — run the real tcp_dlm_scaling criterion repeatedly to measure the
# true 2/tcp failure rate and capture dmesg + residual on the first failure.
# Usage: loop_tds.sh [ITERS]
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh; P=/tmp/.mxfs_pass
ITERS="${1:-25}"
clean(){ grep -vE '^Warning|^Unauthorized|^If you'; }
export MXFS_EXTRA_MODARGS='dirwr=1'
pass=0; fail=0
for i in $(seq 1 "$ITERS"); do
  for n in test1 test2; do "$SSH" "$n" "$P" 'dmesg -C >/dev/null 2>&1' >/dev/null 2>&1; done
  out=$(timeout 200 ./run.sh 2 tcp tcp_dlm_scaling 2>&1)
  line=$(echo "$out" | grep -E '(PASS|FAIL) +tcp_dlm_scaling +\(nodes_pass')
  if echo "$line" | grep -q 'PASS'; then
    pass=$((pass+1)); echo "iter $i: PASS"
  else
    fail=$((fail+1)); echo "iter $i: FAIL -> $line"
    echo "$out" | grep -iE 'reason|logs:' | head
    for n in test1 test2; do
      echo "  --- $n dmesg tail (stale/RMW/DEFER/REACQUIRE/STALE-EX/CLUSTER-PROTECT) ---"
      "$SSH" "$n" "$P" "echo 'P-TDS-RMW total='\$(dmesg|grep -c P-TDS-RMW)' held0='\$(dmesg|grep P-TDS-RMW|grep -c 'held=0'); dmesg | grep -iE 'P-TDS-RMW|STALE-RMW|P106|P108|REACQUIRE|DOUBLEGRANT|CLUSTER-PROTECT' | tail -25" 2>/dev/null | clean
    done
  fi
done
echo "=== LOOP TALLY pass=$pass fail=$fail / $ITERS ==="
