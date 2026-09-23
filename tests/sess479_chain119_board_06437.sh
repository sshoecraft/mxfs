#!/bin/bash
# sess479 chain 119: the full 32/caw board on the 0.64.37 freeze.
#
# Why this run matters.  D-FOREIGN-REPLAY-UNGATED-IMAGES has been held open on
# criterion (2), "a board clean except the policy cell, with crash_consistency
# PASS inside the UNCHANGED 90 s budget", and that row has been the red one --
# it is the board face of D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401 and
# D-32NODE-SHARED-DIR-CREATE-PACE.  The 2026-09-02T18:43Z board
# (run 20260902T184341Z) came back 28 PASS + 1 POLICY with
# crash_consistency PASS at 22/90 s, nodes_pass=32/32, checks 205/205.  That is
# the first board on record where the criterion's own terms are satisfied.
#
# It is NOT the disposition, for two reasons, and this chain exists to close
# the first of them:
#   - it ran on an older build, and the criterion is written against the FINAL
#     candidate; 0.64.37 is newer, so the evidence has to be retaken here;
#   - the pace failure is a FIRST-LAP, cold-directory effect (the 0.64.7 matrix
#     had baseline lap 1 exhaust the budget on all 32 nodes and laps 2-3 pass),
#     so a single green board is a sample, not a streak.  Repeat this chain
#     before anyone cites it, and read lap 1 specifically, never an average.
#
# derived time budget: the 29-row board summed 960 s of measured walls on the
# 2026-09-02 run (node_death_replay alone is 333 s).  With the harness's own
# per-test overhead -- 12 s x 29 tests of ssh fan-out, coord-broker sweep and
# criteria.json record, plus 15 s startup -- the wrapper is
# 960 + 348 + 15 = 1323 s.  BOARD_BUDGET is that, not a round number; a board
# that overruns it is a budget failure to diagnose, never a timeout to widen.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s479a}
GATE=${GATE:-tests/evidence/sess475_chain116_d0133_s479k.log}
LOG=tests/evidence/sess479_chain119_board_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
BOARD_BUDGET=${BOARD_BUDGET:-1323}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
install_ko() {
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do
    [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t
  done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$2"; [ "$sv" = "$2" ]
}
{
  echo "=== sess479 chain119 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) budget=${BOARD_BUDGET}s ==="
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  # Freshness gate.  showstat.sh renders whatever .last_run.json points at, so
  # it happily prints a board from a previous DAY when this run never executed
  # -- exactly what happened on the s480a attempt: run.sh exited 3 on the run
  # lock (a live peer run.sh held it) and the conditions table underneath still
  # showed 28 PASS / 1 POLICY from run 20260902T184341Z.  That is fabricated
  # evidence for criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES, and it is
  # the whole reason this chain exists.  Pin the run id before the board and
  # require it to have MOVED afterwards; a board that did not run prints no
  # conditions at all.
  pre_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board pre_run_id=$pre_id"
  T0=$(date +%s)
  timeout "$BOARD_BUDGET" ./run.sh 32 caw; rc=$?
  wall=$(( $(date +%s) - T0 ))
  echo "STAGE board rc=$rc wall=${wall}s budget=${BOARD_BUDGET}s"
  if [ "$rc" = 124 ]; then
    echo "FAIL: the board exceeded its ${BOARD_BUDGET}s budget (wall=${wall}s).  A timeout IS a failure: the slowness is the defect, and this run must not be re-run with a larger number."
  fi
  post_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board post_run_id=$post_id"
  if [ "$post_id" = "$pre_id" ] || [ "$post_id" = none ]; then
    echo "FAIL: the board did NOT run (run_id unchanged at $pre_id, run.sh rc=$rc).  Refusing to print the conditions table: showstat would render the PREVIOUS run's verdict and it would read as this build's evidence.  Nothing here may be cited for criterion (2)."
    echo "DONE $(date -u +%FT%TZ)"
    exit 1
  fi
  echo "--- conditions (run_id=$post_id) ---"
  timeout 120 ./showstat.sh 32 caw 2>&1 | grep -av '^\s*$'
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
