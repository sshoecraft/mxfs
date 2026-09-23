#!/bin/bash
# sess468 chain 106: D-0523 STOP-SHIP 4 second half — the peerloss arm again,
# sess469: arm budget 900 s (chain 99 measured 640 s to an EARLY rc=127; the fixed
# arm waits for the mount, then a 45 s post-bootstrap settle + probes (D-0525
# verdict), then restores 31 survivors).
# with the harness's bare `wait` fixed (tests/guard_race_arms.sh sess468: the
# parallel-destroy wait also reaped the backgrounded boot_rejoin, so chain
# 99's lap lost the mount's exit status and sampled 'mounted' the instant the
# job was gone).  Chain 99's kernel-side facts stand: peers_lost=1,
# restarts=2, P-BOOT-SEALED and P-BOOT-ADOPT rc=0 on the joiner — the arm
# must now show the mount landing under the sealed term within 480 s.
# budget: prep 300; peerloss 700 (480 mount cap + 150 restore + setup; chain
# 99 measured 423 s to RESULT plus the restore).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s468e}
GATE=${GATE:-tests/evidence/sess468_chain105_intentsA_s468d.log}
LOG=tests/evidence/sess468_chain106_peerloss_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess468 chain106 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lock_holders=$(fuser /tmp/mxfs_run.lock 2>/dev/null | wc -w) ==="
  lap 300 prep_peerloss ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 900 tests/guard_race_arms.sh peerloss test2 test1 > tests/evidence/sess468_chain106_guard_peerloss_$LABEL.log 2>&1; echo "STAGE guard_race peerloss rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a 'RESULT' tests/evidence/sess468_chain106_guard_peerloss_$LABEL.log | tail -1 | cut -c1-240)"
  grep -a 'peerloss: mount rc\|refusal lines\|fleet restore' tests/evidence/sess468_chain106_guard_peerloss_$LABEL.log | cut -c1-300
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
