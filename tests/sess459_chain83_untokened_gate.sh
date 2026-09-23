#!/bin/bash
# sess459 chain 83: build the tree (0.61.5: D-0517 buffer-LSN fix + D-0521
# probes + the review-#5 STOP-SHIP fix "untokened completions fail closed")
# as PRODUCTION once chain 82 (tests/sess459_chain82_d0517_fix_verify_lab.sh,
# the D-0517 LAB verification) prints DONE, then:
#   1  make modules + make tools (abort unless the srcversion CHANGES from the
#      chain-82 production build and the P304-IOCNT-UNTOKENED string is present)
#   2  prep_cluster @ 32/caw
#   3  tests/settle_token_arms.sh: plain, untokened (the new fail-closed arm),
#      latewait, probehang, inval, double, slowrace
#   4  the full 32/caw board (per-row budgets from the manifest; run.sh
#      enforces them, no outer timeout) — the post-D-0517-fix baseline
# derived time budgets: build measured 310-326 s in tree → 600; prep 300; settle
# arms per the harness header (plain/inval/double/latewait 120, slowrace 130,
# probehang 200, untokened 160).
cd /src/mxfs || exit 1
LABEL=${1:-s459c}
GATE=${GATE:-tests/evidence/sess459_chain82_d0517_fixverify_s459b.log}
LOG=tests/evidence/sess459_chain83_untokened_gate_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
OLD_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess459 chain83 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) old_sv=$OLD_SV ==="
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess459_chain83_build_$LABEL.log 2>&1; brc=$?
  NEW_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  GATE_STR=$(strings -a mxfs.ko | grep -c 'P304-IOCNT-UNTOKENED')
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$NEW_SV errors=$(grep -c 'error:' tests/evidence/sess459_chain83_build_$LABEL.log) modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') gate_string=$GATE_STR fix_string=$(strings -a mxfs.ko | grep -c 'OVERRIDE-APPLY')"
  if [ "$brc" != 0 ] || [ "$NEW_SV" = "$OLD_SV" ] || [ "$GATE_STR" = 0 ]; then
    echo "ABORT: build rc=$brc sv=$NEW_SV (old $OLD_SV) gate_string=$GATE_STR"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  lap 120 tools make tools
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 120 "settle arm=plain victim=test3"       tests/settle_token_arms.sh 32 test3  test1 plain
  lap 160 "settle arm=untokened victim=test4"   tests/settle_token_arms.sh 32 test4  test1 untokened
  lap 120 "settle arm=latewait victim=test29"   tests/settle_token_arms.sh 32 test29 test1 latewait
  lap 200 "settle arm=probehang victim=test28"  tests/settle_token_arms.sh 32 test28 test1 probehang
  lap 120 "settle arm=inval victim=test26"      tests/settle_token_arms.sh 32 test26 test1 inval
  lap 120 "settle arm=double victim=test27"     tests/settle_token_arms.sh 32 test27 test1 double
  lap 130 "settle arm=slowrace victim=test30"   tests/settle_token_arms.sh 32 test30 test1 slowrace
  echo "=== settle arms done $(date -u +%FT%TZ); full board 32/caw ==="
  lap 300 prep_board ./run.sh 32 caw prep_cluster
  T0=$(date +%s)
  ./run.sh 32 caw > tests/evidence/sess459_chain83_board_$LABEL.log 2>&1; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>&1 | tail -40
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
