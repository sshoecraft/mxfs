#!/bin/bash
# sess455 chain 78: build 0.61.1 IN TREE once chain 77 (0.61.0 sv 923EB92D:
# tests/sess454_chain77_0610.sh s454d, whose last stage is the 12 RETIRE_PENDING
# laps s454e) prints DONE and the rig is idle, then verify the sess455
# departure-gate rework (design-consult STOP-SHIP items 1-10, docs/pr-fencing-departure.md
# "The sess455 implementation review") together with landing group 2:
#   1  make modules + make tools (abort unless the srcversion CHANGES from
#      923EB92DAA8D9A3385402CD and the P304-RETIRE-DRAIN-STALL string is present)
#   2  prep_cluster @ 32/caw
#   3  tests/settle_token_arms.sh: plain, inval, double, slowrace, probehang,
#      latewait (the uncapped drain waits for the injected token, then clean)
#   4  the 12 RETIRE_PENDING laps (tests/sess452_chain71_retire_pending.sh
#      s455a) on 0.61.1
#   5  the full 32/caw board (./run.sh 32 caw — per-row budgets from the
#      manifest; run.sh enforces them, no outer timeout)
# derived time budgets: build measured 326 s in tree (chain 77) → 600; prep 300;
# settle arms per the harness header (plain/inval/double/latewait 120, slowrace 130,
# probehang 200); laps per chain 71's header.
cd /src/mxfs || exit 1
LABEL=${1:-s455b}
OLD_SV=${2:-923EB92DAA8D9A3385402CD}
GATE=tests/evidence/sess454_chain77_0610_s454d.log
LOG=tests/evidence/sess455_chain78_0611_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess455 chain78 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) old_sv=$OLD_SV ==="
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess455_chain78_build_$LABEL.log 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s errors=$(grep -c 'error:' tests/evidence/sess455_chain78_build_$LABEL.log) warnings=$(grep -c 'warning:' tests/evidence/sess455_chain78_build_$LABEL.log)"
  NEW_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "srcversion now $NEW_SV"
  if [ "$brc" != 0 ] || [ "$NEW_SV" = "$OLD_SV" ] || [ "$(strings -a mxfs.ko | grep -c 'P304-RETIRE-DRAIN-STALL')" = 0 ]; then
    echo "ABORT: build rc=$brc sv=$NEW_SV (old $OLD_SV) stall_string=$(strings -a mxfs.ko | grep -c 'P304-RETIRE-DRAIN-STALL')"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  lap 120 tools make tools
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 120 "settle arm=plain victim=test3"      tests/settle_token_arms.sh 32 test3  test1 plain
  lap 120 "settle arm=inval victim=test4"      tests/settle_token_arms.sh 32 test4  test1 inval
  lap 120 "settle arm=double victim=test26"    tests/settle_token_arms.sh 32 test26 test1 double
  lap 130 "settle arm=slowrace victim=test27"  tests/settle_token_arms.sh 32 test27 test1 slowrace
  lap 200 "settle arm=probehang victim=test28" tests/settle_token_arms.sh 32 test28 test1 probehang
  lap 120 "settle arm=latewait victim=test29"  tests/settle_token_arms.sh 32 test29 test1 latewait
  echo "=== settle arms done $(date -u +%FT%TZ); the 12 RETIRE_PENDING laps (label s455a, sv $NEW_SV) ==="
  tests/sess452_chain71_retire_pending.sh s455a "$NEW_SV"
  echo "=== laps done $(date -u +%FT%TZ); full board 32/caw ==="
  T0=$(date +%s)
  ./run.sh 32 caw > tests/evidence/sess455_chain78_board_$LABEL.log 2>&1; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>&1 | tail -40
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
