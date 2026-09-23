#!/bin/bash
# sess480 chain 123: the SECOND board on the 0.64.37 freeze.
#
# Criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES is not satisfied by one green
# board, and the record says so in its own terms: the crash_consistency pace
# failure is a FIRST-LAP, cold-directory effect -- the 0.64.7 matrix had baseline
# lap 1 exhaust the budget on all 32 nodes while laps 2-3 passed at 21-22 s -- so
# a single green board is a sample, and any citation must read lap 1 specifically
# rather than an average.  This chain is the repeat.
#
# It waits for the rig rather than racing for it (see tests/rig_wait_free.sh):
# gating on a predecessor's DONE line is what let four chains collide earlier in
# this session, one of them relinking the module a live board's preps were
# shipping to 32 nodes.
#
# budget: board budget 1470 s, RE-DERIVED from the 0.64.37 board this repeats.
# The first attempt used 1323 s, taken from an older board's 960 s of summed
# walls -- but that board's crash_consistency row ran 22 s and 0.64.37's runs
# 91 s, so the 28 rows that completed here sum to 711 s on their own and
# node_death_replay (row 29, measured 333-392 s) was guaranteed to be cut off.
# It was: the board came back with row 29 ABORTED purely because the WRAPPER
# was too small, wasting the row that carries criterion (3).
#   711 + 392 (largest measured NDR wall) + 12 s x 29 harness overhead + 15 s
#   startup = 1466 -> 1470.
# This is a correction to a mis-derivation, NOT a pad: the per-row budgets are
# untouched, crash_consistency still has its unchanged 90 s and still FAILS at
# 91 s, and summing measured walls rather than budget ceilings is the required
# derivation.  A wrapper below the sum of the walls truncates the board whatever
# the filesystem does.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480g}
GATE=${GATE:-tests/evidence/sess480_chain122_sequencer_s480f.log}
LOG=tests/evidence/sess480_chain123_board_repeat_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
BOARD_BUDGET=${BOARD_BUDGET:-1470}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain123 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) budget=${BOARD_BUDGET}s ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$PROD_KO" ] || { echo "ABORT: missing $PROD_KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$PROD_KO" mxfs.ko || { echo "ABORT: install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$PROD_SV"
  [ "$sv" = "$PROD_SV" ] || { echo "ABORT: srcversion mismatch"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # Same freshness gate as chain 119: showstat renders whatever .last_run.json
  # points at, so a board that did not run would otherwise print the PREVIOUS
  # one's verdict and read as this build's evidence.
  pre_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board pre_run_id=$pre_id"
  T0=$(date +%s)
  timeout "$BOARD_BUDGET" ./run.sh 32 caw; rc=$?
  wall=$(( $(date +%s) - T0 ))
  echo "STAGE board rc=$rc wall=${wall}s budget=${BOARD_BUDGET}s"
  [ "$rc" = 124 ] && echo "FAIL: the board exceeded its ${BOARD_BUDGET}s budget (wall=${wall}s).  The slowness is the defect."
  post_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board post_run_id=$post_id"
  if [ "$post_id" = "$pre_id" ] || [ "$post_id" = none ]; then
    echo "FAIL: the board did NOT run (run_id unchanged at $pre_id, rc=$rc).  Refusing to print the conditions table; nothing here may be cited for criterion (2)."
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  echo "--- conditions (run_id=$post_id) ---"
  # harness-lint: ok - unreachable unless post_run_id != pre_run_id proved above that THIS run recorded a board
  timeout 120 ./showstat.sh 32 caw 2>&1 | grep -av '^\s*$'
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
