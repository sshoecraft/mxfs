#!/bin/bash
# sess495 chain 140: the full 32/caw board on the 0.70.13 freeze.
#
# Why this run matters.  0.70.x carries the departure/unmount/durability fixes
# landed since the last full board (0.64.37, run 20260904T000831Z):
# D-0483 unmount-publish hoist, D-0486, D-0487 SB-summary-lock convoy strip,
# D-0490 untokened-departure double-retire, D-0491 BTREE-dir evict-drain gap,
# D-0492 new-tenure retire of a committed-unwritten dir block, D-0493 terminal
# guard classification, plus the always-on create-cost probes.  None of that
# has been measured on the whole board yet, and two records are waiting on it:
#   - D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-PIN-0487 / the SB-summary convoy
#     record close on "no regression in the unmount rows" of a board on the
#     build that carries the fix;
#   - D-FOREIGN-REPLAY-UNGATED-IMAGES criterion (2) is a board clean except the
#     policy cell with crash_consistency inside its unchanged 90 s budget, on the
#     FINAL candidate.  0.70.13 is not final (the lookup and per-modify-flush
#     work for the pace record is still open), so this board is the pace row's
#     current position, not that criterion's evidence.
#
# derived time budget: the last complete board (0.64.37, sess480 chain 123) took
# 1320 s wall for 29 rows with nothing aborted, under a wrapper re-derived at
# 1470 s = 1107 s of summed measured walls + 12 s x 29 tests of harness
# overhead + 15 s startup.  node_death_replay alone ranges 333-380 s.  Keep
# 1470 s: a board that overruns it is a budget failure to diagnose, never a
# timeout to widen.
#
# Usage: GATE=<log> setsid nohup bash tests/sess495_chain140_board_07013.sh s495a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s495a}
GATE=${GATE:-tests/evidence/sess494_lkp_attrib_s494h.log}
LOG=tests/evidence/sess495_chain140_board_$LABEL.log
PROD_KO=${PROD_KO:-tests/evidence/sess494_frozen_07013/mxfs.ko}
PROD_SV=${PROD_SV:-6CF6DDD1255241B3FBA1551}
BOARD_BUDGET=${BOARD_BUDGET:-1470}
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
  echo "=== sess495 chain140 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) budget=${BOARD_BUDGET}s gate=$GATE ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  # The DONE line is not the rig being free: a gate log can print DONE while
  # its own last run.sh still holds the run lock.  Wait on the lock itself.
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  # Freshness gate (sess479): showstat.sh renders whatever .last_run.json points
  # at, so a board that never ran would still print a previous run's table.
  # Pin the run id before the board and require it to have moved afterwards.
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
    echo "FAIL: the board did NOT run (run_id unchanged at $pre_id, run.sh rc=$rc).  Refusing to print the conditions table: showstat would render the PREVIOUS run's verdict and it would read as this build's evidence."
    echo "DONE $(date -u +%FT%TZ)"
    exit 1
  fi
  echo "--- conditions (run_id=$post_id) ---"
  timeout 120 ./showstat.sh 32 caw 2>&1 | grep -av '^\s*$'
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
