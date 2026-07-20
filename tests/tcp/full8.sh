#!/bin/bash
# full8.sh [N] [MODARGS] — clean-reboot all 8 nodes, then run the FULL N/tcp
# suite (all tests) with the given module args.  Records PASS/FAIL per test.
# sess29: validate the dir_release_invalidate + relinval_clean config across the
# whole suite, not just dir_reuse_coherency.
set -u
N="${1:-8}"
MODARGS="${2:-}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
SCR="$(dirname "$0")/drc_cap"; mkdir -p "$SCR"
LOG="$SCR/full${N}.log"
nodes=$(seq 1 "$N")
for n in $nodes; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
sleep 7
for n in $nodes; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
for w in $(seq 1 40); do up=0; for n in $nodes; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = "$N" ] && break; sleep 3; done
echo "=== full${N} modargs=[$MODARGS] nodes_up=$up $(date -u) ===" | tee "$LOG"
t0=$(date +%s)
MXFS_EXTRA_MODARGS="$MODARGS" timeout 1500 /src/mxfs/run.sh "$N" tcp > "$SCR/full${N}_run.log" 2>&1
t1=$(date +%s)
echo "wall=$((t1-t0))s" | tee -a "$LOG"
echo "--- per-test results ---" | tee -a "$LOG"
grep -E "  (PASS|FAIL)  " "$SCR/full${N}_run.log" | tee -a "$LOG"
P=$(grep -cE "  PASS  " "$SCR/full${N}_run.log")
F=$(grep -cE "  FAIL  " "$SCR/full${N}_run.log")
echo "=== TOTAL pass=$P fail=$F ===" | tee -a "$LOG"
echo "=== done $(date -u) ===" | tee -a "$LOG"
