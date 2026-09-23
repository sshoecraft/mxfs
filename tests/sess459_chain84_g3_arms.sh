#!/bin/bash
# sess459 chain 84: the review-#5 condition-1 deterministic G3 accounting arms
# on the 0.61.5 production build that chain 83 (tests/sess459_chain83_
# untokened_gate.sh) built, prepped and baselined.  Gated on chain 83 DONE;
# no rebuild here (RULE: never rebuild under a run; the build is chain 83's).
#   1  abort unless mxfs.ko carries P-DBG-DEPART-INJECT
#   2  prep_cluster @ 32/caw
#   3  tests/settle_token_arms.sh: postteardown, orphantoken, orphanrejected,
#      overflow, underflow (one victim each, distinct slots)
#   4  prep_cluster again (leave the fleet clean)
# budget: per-arm budget 160 (harness header); prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s459d}
GATE=${GATE:-tests/evidence/sess459_chain83_untokened_gate_s459c.log}
LOG=tests/evidence/sess459_chain84_g3_arms_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess459 chain84 START $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) inject_string=$(strings -a mxfs.ko | grep -c 'P-DBG-DEPART-INJECT') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P-DBG-DEPART-INJECT')" = 0 ]; then echo "ABORT: mxfs.ko has no departure injector"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 160 "settle arm=postteardown victim=test5"    tests/settle_token_arms.sh 32 test5  test1 postteardown
  lap 160 "settle arm=orphantoken victim=test7"     tests/settle_token_arms.sh 32 test7  test1 orphantoken
  lap 160 "settle arm=orphanrejected victim=test9"  tests/settle_token_arms.sh 32 test9  test1 orphanrejected
  lap 160 "settle arm=overflow victim=test11"       tests/settle_token_arms.sh 32 test11 test1 overflow
  lap 160 "settle arm=underflow victim=test13"      tests/settle_token_arms.sh 32 test13 test1 underflow
  lap 160 "settle arm=carryfreeze victim=test15"    tests/settle_token_arms.sh 32 test15 test1 carryfreeze
  lap 130 "settle arm=carrylive victim=test17"      tests/settle_token_arms.sh 32 test17 test1 carrylive
  lap 300 prep_after ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
