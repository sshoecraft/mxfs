#!/bin/bash
# Full CAW ladder re-validation under fua_disable=1 (the SCST-correct read mode).
# Runs the COMPLETE 17-test suite at each node count, fresh-booting before each level.
# Usage: caw_ladder_fua.sh [levels...]   (default: 1 2 4 8 16 32)
# RULE 3: lives in tree so it survives reboots.
cd /src/mxfs
LEVELS="${*:-1 2 4 8 16 32}"
boot_n() { local n=$1; for i in $(seq 1 $n); do virsh -c qemu:///system destroy test$i >/dev/null 2>&1; done; sleep 3; for i in $(seq 1 $n); do virsh -c qemu:///system start test$i >/dev/null 2>&1; done; }
wait_n() { local n=$1 s exp up; if [ "$n" -le 4 ]; then s=$(seq 1 $n); else s="1 $((n/4)) $((n/2)) $((3*n/4)) $n"; fi; exp=$(echo $s|wc -w); for w in $(seq 1 70); do up=0; for i in $s; do timeout 5 tools/mxfs_sshpass.sh test$i /tmp/.mxfs_pass 'echo ok' >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" -ge "$exp" ] && break; sleep 4; done; echo "nodes up=$up/$exp"; }

for N in $LEVELS; do
  echo "################ LADDER LEVEL: $N/caw (fua_disable=1) ################"
  boot_n $N; wait_n $N
  t0=$SECONDS
  # No outer timeout wrapper: run.sh enforces per-test RULE-0 budgets
  # (tests/criteria/TIMEOUT_BUDGETS.md). A slow test is a FAIL to diagnose,
  # not something to pad an arbitrary wall-clock around.
  MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="fua_disable=1 caw_fair_handoff=1" ./run.sh $N caw 2>&1 | tail -6
  echo "=== level $N elapsed $((SECONDS-t0))s ==="
  ./showstat.sh $N caw 2>/dev/null | tail -3
done
echo "################ LADDER COMPLETE ################"
for N in $LEVELS; do printf "%2d/caw: " $N; ./showstat.sh $N caw 2>/dev/null | grep -E "Total:" ; done
