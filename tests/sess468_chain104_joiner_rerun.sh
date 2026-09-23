#!/bin/bash
# sess468 chain 104: D-0523 joiner arm re-run on a clean, freshly prepped fleet.
#
# Chain 99's joiner lap (tests/evidence/sess467_chain99_guard_joiner_s467a.log,
# RESULT FAIL 'no survivor entered P99-UBSWEEP-HOLD within 150s and no adopt')
# is INVALID, not evidence: its prep_joiner failed rc=3 on /tmp/mxfs_run.lock
# because chain 98b's orphaned crash_consistency run.sh (GNU timeout puts its
# child in its own process group, so the chain's group kill missed it) was
# still driving the same 32 nodes when the arm destroyed test2 — two
# workloads on one fleet.  Same invocation as chain 99, on the module the
# tree carries at gate time (chain 103 leaves the frozen 0.64.6 installed).
# budget: prep 300 (80-117 s measured); joiner 560 (chain 94 measured 189 s
# mount inside a 180 s hold + 240 s budget; chain 99 harness cap).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s468c}
GATE=${GATE:-tests/evidence/sess468_chain103_dirshard_intentsB_s468b.log}
LOG=tests/evidence/sess468_chain104_joiner_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess468 chain104 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lock_holders=$(fuser /tmp/mxfs_run.lock 2>/dev/null | wc -w) ==="
  lap 300 prep_joiner ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 560 tests/guard_race_arms.sh joiner test2 test1 > tests/evidence/sess468_chain104_guard_joiner_$LABEL.log 2>&1; echo "STAGE guard_race joiner rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a 'RESULT' tests/evidence/sess468_chain104_guard_joiner_$LABEL.log | tail -1 | cut -c1-200)"
  grep -a 'P300-CLAIM-WAIT\|claimed heartbeat\|SAFETY\|mount rc' tests/evidence/sess468_chain104_guard_joiner_$LABEL.log | head -12 | cut -c1-200
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
