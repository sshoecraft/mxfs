#!/bin/bash
# sess498: THE 32/caw BOARD WITH THE LEAF-HASH-HOLE HEAL SWITCHED OFF
# (D-DIR-LEAF-HASH-INDEX-LOSES-ENTRIES-MASKED-BY-DATASCAN-HEAL-0496,
#  D-32NODE-SHARED-DIR-CREATE-PACE).
#
# Every leaf-hash hole the heal repaired on 2026-09-04 (101 P22-DATASCAN-HIT
# across 46 run directories) belongs to the new-tenure retire of an undestaged
# log item that 0.70.11 removed (D-0492): runs 083456Z..085524Z on 0.70.3/0.70.4
# and the deliberate 0.70.9 control lap whose boot journal spans 111915Z..112955Z.
# Every run on 0.70.11 or later shows zero.  The heal is the O(dir) cold data
# walk on every negative lookup, the largest single term of the shared-directory
# create (p90 20 reads, ~4.85 ms per create lookup).
#
# This chain installs the frozen 0.70.18 (adds mxfs.dir_datascan_heal), preps
# the fleet with the heal OFF, reads the knob back on all 32 nodes, runs the
# whole board, then sweeps every node's kernel log since the prep.  Two
# questions, answered separately:
#   1. does any directory-coherency row fail once the index is authoritative?
#      (a hole producer other than D-0492 survives -> its face reappears here)
#   2. does crash_consistency fit its unchanged 90 s budget without the scan?
# The sweep proves the knob was honoured (dscan=0 means the scan never ran) and
# counts the negative lookups that would have scanned (P26-LKERR).
#
# This is the experiment the design-consult ruling (ccmemory
# docs/rulings/retire-datascan-heal-conditions.md) calls
# valid; it is NOT by itself the bar for flipping the default.
#
# derived time budgets, derived: prep 300 (measured 107-146 s); board 1411 =
# 1048 s of measured row walls (showstat 32/caw, 2026-09-04T13:04Z) + 12 s x 29
# rows of harness overhead + 15 s startup; sweep 90 s per node in parallel.
#
# Usage:  setsid nohup bash tests/sess498_heal_off_board.sh s498a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s498a}
KO=${KO:-tests/evidence/sess498_frozen_07018/mxfs.ko}
WANT_SV=${WANT_SV:-0E42A339B7701D7E8622AAA}
MODARGS=${MODARGS:-dir_datascan_heal=0}
BOARD_BUDGET=${BOARD_BUDGET:-1411}
LOG=tests/evidence/sess498_heal_off_board_$LABEL.log
O=tests/evidence/sess498_heal_off_board_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }
done_exit() { echo "DONE $(date -u +%FT%TZ)"; exit "${1:-0}"; }

{
  echo "=== sess498 heal_off_board START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO MODARGS='$MODARGS' board_budget=${BOARD_BUDGET}s ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; done_exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; done_exit 1; }
  cp "$KO" mxfs.ko
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do
    [ -f "$(dirname "$KO")/tools/$t" ] && cp "$(dirname "$KO")/tools/$t" tools/$t
  done
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_ko sv=$sv want=$WANT_SV knob=$(modinfo mxfs.ko | grep -c dir_datascan_heal)"
  [ "$sv" = "$WANT_SV" ] || { echo "ABORT: wrong module"; done_exit 1; }

  SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
  MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS="$MODARGS" timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s"
  [ "$rc" = 0 ] || { echo "NOT RUN: prep rc=$rc"; done_exit 1; }
  for n in $(nodes); do
    ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion /sys/module/mxfs/parameters/dir_datascan_heal 2>/dev/null | tr '\n' ' '" 2>/dev/null > "$O/readback_$n.out" ) &
  done
  wait
  want="$WANT_SV 0 "
  ok=0; for n in $(nodes); do [ "$(cat "$O/readback_$n.out" 2>/dev/null)" = "$want" ] && ok=$((ok + 1)); done
  echo "READBACK sv+heal0: $ok/32"
  [ "$ok" = 32 ] || { echo "ABORT: the knob is not 0 on every node; the board would not measure the heal-off condition"; done_exit 1; }

  pre_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board pre_run_id=$pre_id"
  T0=$(date +%s)
  MXFS_EXTRA_MODARGS="$MODARGS" timeout "$BOARD_BUDGET" ./run.sh 32 caw > "$O/board.out" 2>&1; rc=$?
  wall=$(( $(date +%s) - T0 ))
  echo "STAGE board rc=$rc wall=${wall}s budget=${BOARD_BUDGET}s"
  [ "$rc" = 124 ] && echo "FAIL: the board exceeded its ${BOARD_BUDGET}s budget (wall=${wall}s); a timeout is a failure to diagnose, never a number to widen"
  post_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE board post_run_id=$post_id"
  if [ "$post_id" = "$pre_id" ] || [ "$post_id" = none ]; then
    echo "FAIL: the board did NOT run (run_id unchanged at $pre_id, run.sh rc=$rc); no conditions table, nothing here may be cited"
    done_exit 1
  fi
  echo "--- conditions (run_id=$post_id) ---"
  timeout 120 ./showstat.sh 32 caw 2>&1 | grep -av '^\s*$'

  for n in $(nodes); do
    ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P22-DATASCAN-HIT|P26-DSCAN|P26-LKERR|P21H-LEAFHOLE|P33-DSCAN-ONDISK|mxfs-cc-FAIL|lookup_fail|P285-F4-BLI-FREED-OPEN|P492-KEEP-UNDEST|P3R-RELAND|P3F-UNLANDED|P123-DIRFENCE-SKIP|P287-F4|shut down|Corruption|EUCLEAN|ESTALE'" 2>/dev/null | gzip > "$O/ctx_$n.gz" ) &
  done
  wait
  cnt() { zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac "$1"; }
  for n in $(nodes); do
    echo "$n lkerr=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P26-LKERR') dscan=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P26-DSCAN') heal_hit=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P22-DATASCAN-HIT') leafhole=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P21H-LEAFHOLE') cc_fail=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'mxfs-cc-FAIL') shutdown=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'shut down')" >> "$O/per_node.txt"
  done
  rows_fail=$(grep -aE '^[0-9]+ +\|' "$LOG" | grep -ac 'FAIL')
  echo "VERDICT board_rc=$rc board_wall=${wall}s rows_fail=$rows_fail dscan=$(cnt 'P26-DSCAN ') dscan_miss=$(cnt 'P26-DSCAN-MISS') heal_hit=$(cnt 'P22-DATASCAN-HIT') lkerr=$(cnt 'P26-LKERR') leafhole=$(cnt 'P21H-LEAFHOLE') cc_fail=$(cnt 'mxfs-cc-FAIL') lookup_fail=$(cnt 'lookup_fail') bli_freed_open=$(cnt 'P285-F4-BLI-FREED-OPEN') keep_undest=$(cnt 'P492-KEEP-UNDEST') reland=$(cnt 'P3R-RELAND') unlanded_lost=$(cnt 'P3F-UNLANDED-LOST') fence_skip=$(cnt 'P123-DIRFENCE-SKIP') shutdown=$(cnt 'shut down') corruption=$(cnt 'Corruption')"
  echo "  the knob is honoured iff dscan=0 and heal_hit=0 (the scan never ran); every negative lookup then trusted the index (lkerr counts them)"
  sort -t= -k5 -rn "$O/per_node.txt" | head -5 | sed 's/^/    /'
  grep -aE 'crash_consistency|dir_reuse_coherency|cache_coherency|zero_silent_loss|dirent_durability|dirent_publish_integrity|rsync_paired' "$LOG" | grep -aE '^[0-9]+ +\|' | sed 's/^/    ROW: /' | cut -c1-200
  done_exit 0
} >> "$LOG" 2>&1
