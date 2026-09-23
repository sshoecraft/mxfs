#!/bin/bash
# sess450 chain 69: 0.59.0 RETIRE_PENDING two-phase departure —
# tests/pr_unregister_fail_restamp.sh in both modes on the production build:
#   lap 1 restamp (victim test2)  — the 0.58.0 arm + the clean-path control
#   lap 2 crash   (victim test11) — peers settle a RETIRE_PENDING record alone
#   lap 3 crash   (victim test20) — second victim for the expiry arm
# Rebuilds + re-preps itself if the tree's mxfs.ko lacks the P304 string.
# budget: restamp bound 300 s, crash bound 330 s (derived in the harness
# header); build 420 (full rebuild measured ~4-5 min at -j8 on a loaded
# host — chain 59's 300 s was too short and killed the build); prep 300.
# Gated on chain 68 DONE (which ends with a prep).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess449_chain68_pr_restamp_s449d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s450a}
LOG=tests/evidence/sess450_chain69_retire_pending_$LABEL.log
{
  echo "=== sess450 chain69 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p304=$(strings -a mxfs.ko | grep -c 'P304-RETIRE') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P304-RETIRE-EXPIRED-WITHDRAWN')" = 0 ]; then
    T0=$(date +%s); timeout 420 make modules -j8 > tests/evidence/sess450_chain69_build_$LABEL.log 2>&1; echo "STAGE build rc=$? wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') p304=$(strings -a mxfs.ko | grep -c 'P304-RETIRE')"
    timeout 120 make tools > tests/evidence/sess450_chain69_tools_$LABEL.log 2>&1; echo "STAGE tools rc=$?"
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  fi
  T0=$(date +%s); timeout 300 tests/pr_unregister_fail_restamp.sh 32 test2 test1 restamp; echo "STAGE pr_restamp mode=restamp victim=test2 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 330 tests/pr_unregister_fail_restamp.sh 32 test11 test1 crash; echo "STAGE pr_restamp mode=crash victim=test11 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 330 tests/pr_unregister_fail_restamp.sh 32 test20 test1 crash; echo "STAGE pr_restamp mode=crash victim=test20 rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
