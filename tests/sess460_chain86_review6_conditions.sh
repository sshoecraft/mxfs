#!/bin/bash
# sess460 chain 86: the review-#5 conditions 2, 3 and 4 (ccmemory
# ccloop-c7ee71c6-sess456-GPT-ruling-review5-0611-NO-GO-untokened-failclosed-
# 6-conditions) on the 0.61.6 production build — the deterministic arms the
# next design-consult review (#6) needs.  Gated on chain 84 (tests/sess459_chain84_
# g3_arms.sh) printing DONE; rebuilds production here (0.61.6 adds only the
# injectors dbg_depart_crash_cut/_hold_ms, dbg_retire_hang_ms and
# dbg_cas_nocaw_ops, all default-off).
#   build   make modules + make tools; abort unless the .ko carries the three
#           injector strings
#   prep    prep_cluster @ 32/caw
#   cond 4  G1 admission matrix on 0.61.x: vergate noncaw_refuse,
#           fence_capability_admission (3 arms), domain_admission_matrix (R8 =
#           TCP refusal) — all on test32
#   cond 2  settle_token_arms workerhang (test5), workerhangheld (test7 +
#           SETTLE_VICTIM2=test8)
#   cond 3  depart_crash_cuts 1/2/3/5 (test9..test12), pr_unregister_fail_
#           restamp restamp (test13) + crash (test14)
#   cond 4  cas_nocaw_arms heartbeat/release/restamp/empty/settleown/guard/
#           milestone (test15..test21)
#   prep    prep_cluster again
# budget: budgets from each harness header (see there); build 600; prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s460a}
GATE=${GATE:-tests/evidence/sess459_chain84_g3_arms_s459d.log}
LOG=tests/evidence/sess460_chain86_review6_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess460 chain86 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess460_chain86_build_$LABEL.log 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess460_chain86_build_$LABEL.log 2>&1
  s1=$(strings -a mxfs.ko | grep -c 'P-DBG-DEPART-CUT'); s2=$(strings -a mxfs.ko | grep -c 'P-DBG-RETIRE-HANG'); s3=$(strings -a mxfs.ko | grep -c 'P-DBG-CAS-NOCAW')
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess460_chain86_build_$LABEL.log) strings cut=$s1 hang=$s2 nocaw=$s3"
  if [ "$brc" != 0 ] || [ "$s1" = 0 ] || [ "$s2" = 0 ] || [ "$s3" = 0 ]; then echo "ABORT: build failed or injector strings missing"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 120 "cond4 vergate noncaw_refuse test32"     tests/vergate.sh test32 noncaw_refuse
  lap 120 "cond4 fence_cap_admission test32"       tests/fence_capability_admission.sh test32
  lap 240 "cond4 domain_admission_matrix test32"   tests/domain_admission_matrix.sh $LABEL test32
  lap 200 "cond2 settle arm=workerhang victim=test5"      tests/settle_token_arms.sh 32 test5 test1 workerhang
  lap 240 "cond2 settle arm=workerhangheld victim=test7"  env SETTLE_VICTIM2=test8 tests/settle_token_arms.sh 32 test7 test1 workerhangheld
  lap 300 "cond3 crashcut 1 precas victim=test9"     tests/depart_crash_cuts.sh 32 test9  test1 1
  lap 300 "cond3 crashcut 2 postcas victim=test10"   tests/depart_crash_cuts.sh 32 test10 test1 2
  lap 300 "cond3 crashcut 3 preunreg victim=test11"  tests/depart_crash_cuts.sh 32 test11 test1 3
  lap 300 "cond3 crashcut 5 postunreg victim=test12" tests/depart_crash_cuts.sh 32 test12 test1 5
  lap 100 "cond3 pr_restamp mode=restamp victim=test13" tests/pr_unregister_fail_restamp.sh 32 test13 test1 restamp
  lap 160 "cond3 pr_restamp mode=crash victim=test14"   tests/pr_unregister_fail_restamp.sh 32 test14 test1 crash
  lap 330 "cond5 settle arm=proutsettle victim=test22" env SETTLE_VICTIM2=test23 tests/settle_token_arms.sh 32 test22 test1 proutsettle
  lap 170 "cond4 nocaw arm=heartbeat victim=test15" tests/cas_nocaw_arms.sh 32 test15 test1 heartbeat
  lap 170 "cond4 nocaw arm=release victim=test16"   tests/cas_nocaw_arms.sh 32 test16 test1 release
  lap 170 "cond4 nocaw arm=restamp victim=test17"   tests/cas_nocaw_arms.sh 32 test17 test1 restamp
  lap 140 "cond4 nocaw arm=empty victim=test18"     tests/cas_nocaw_arms.sh 32 test18 test1 empty
  lap 90  "cond4 nocaw arm=settleown victim=test19" tests/cas_nocaw_arms.sh 32 test19 test1 settleown
  lap 280 "cond4 nocaw arm=guard victim=test20"     tests/cas_nocaw_arms.sh 32 test20 test1 guard
  lap 280 "cond4 nocaw arm=milestone victim=test21" tests/cas_nocaw_arms.sh 32 test21 test1 milestone
  lap 300 prep_after ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
