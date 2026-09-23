#!/bin/bash
# sess466 chain 98: D-32NODE-SHARED-DIR-CREATE-PACE stage-2 pace evidence
# (docs/dir-sharding.md "Pre-stage-3 rig evidence": N=16/32/64 plus the
# unsharded and CC_PRIVATE=1 baselines, >= 5 clean runs each).  The workload
# is the board's own crash_consistency row (32 nodes x 50 O_SYNC files into
# ONE shared directory, cross-node cold verify, 90 s budget); CC_SHARDED=N
# makes that one directory a sharded directory (rank 1 creates it with
# MXFS_IOC_DIRSHARD_MKDIR, tests/suite/crash_consistency.sh sess464 hook).
# Each variant starts from a fresh prep (the harness reuses an existing
# .crash_consistency, so a variant must not inherit another's directory).
# Read-out per run: the run.sh PASS/FAIL line with its wall; the HARD GATE is
# every run < 90 s, the sharded runs "materially better than 70-100 s", N=32
# near the private baseline (stage gate p95 <= 30 s).
# Gated on chain 97 DONE (the fleet must carry 0.64.0 with the ioctl).
# budget: prep 300 (measured 86-106 s); crash_consistency 160 per run (90 s
# budget + harness overhead, the sess436 chain-5 bound); 5 variants x (prep +
# 5 runs) ~ 5 x (100 + 5 x 110) s ~ 55 min.
cd /src/mxfs || exit 1
LABEL=${1:-s466c}
GATE=${GATE:-tests/evidence/sess466_chain97_dirshard_stage1_s466b.log}
LOG=tests/evidence/sess466_chain98_dirshard_pace_$LABEL.log
SSH=tools/mxfs_sshpass.sh
LAPS=${LAPS:-5}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess466 chain98 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') fleet_sv=$(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | grep -aE '^[0-9A-F]{20,}$') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P-DIRSHARD-CORRUPT')" = 0 ]; then echo "ABORT: tree mxfs.ko lacks dirshard"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for variant in baseline private sharded16 sharded32 sharded64; do
    case "$variant" in
      baseline)  ENV="" ;;
      private)   ENV="CC_PRIVATE=1" ;;
      sharded16) ENV="CC_SHARDED=16" ;;
      sharded32) ENV="CC_SHARDED=32" ;;
      sharded64) ENV="CC_SHARDED=64" ;;
    esac
    lap 300 "prep_$variant" ./run.sh 32 caw prep_cluster
    for l in $(seq 1 "$LAPS"); do
      T1=$(date +%s)
      if [ -n "$ENV" ]; then
        out=$(MXFS_TEST_ENV="$ENV" timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
      else
        out=$(timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
      fi
      echo "STAGE cc variant=$variant lap=$l rc=$rc wall=$(( $(date +%s) - T1 ))s $(echo "$out" | grep -a '^  \(PASS\|FAIL\) *crash_consistency' | tail -1 | tr -s ' ' | cut -c1-200)"
      echo "$out" | grep -a 'cc sharded\|EOPNOTSUPP\|BUDGET_EXHAUSTED\|NO_TERMINAL' | head -4 | cut -c1-200
    done
    # the sharded directory's manifest after the laps (rank-1 view)
    if [ -n "$ENV" ] && [ "${ENV#CC_SHARDED}" != "$ENV" ]; then
      echo "manifest $variant: $(timeout 30 $SSH test1 "python3 /src/mxfs/tests/dirshard_ioctl.py info /mnt/shared/.crash_consistency | head -1" 2>/dev/null | grep -a '^state=')"
      echo "dirshard dmesg $variant: $(for n in test1 test2 test17; do printf '%s=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -c "P-DIRSHARD-CORRUPT\|P-DIRSHARD-STRANGER\|P-DIRSHARD-ABANDON"' 2>/dev/null | tr -d '\r\n ')"; done)"
    fi
  done
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
