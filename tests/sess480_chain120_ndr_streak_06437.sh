#!/bin/bash
# sess480 chain 120: criterion (3) of D-FOREIGN-REPLAY-UNGATED-IMAGES on the
# FINAL candidate build -- node_death_replay x10 consecutive PASS under
# production defaults on 0.64.37 (sv EAD72FC7EC56BA505829901).
#
# Why 10, and why again.  The sess463 design-consult ruling is explicit that the streak
# counts only on the final fixed build: chain 87's 6 laps on 0.61.7 count as
# laps 1-6 "only if no relevant build change follows", and 0.64.x carries a
# great deal of relevant change (dir sharding, the SB-counter seal, the intents
# census fix in 0.64.37 itself).  So the streak restarts here at zero.  Any FAIL
# resets it to zero -- it is a CONSECUTIVE streak, not a tally of passes.
#
# Anti-fabrication gates, learned the expensive way.  Chain 87's harvest loop
# did `ls -dt tests/evidence/board_*_node_death_replay | head -1` and read the
# VERDICT out of whatever that returned.  If the row does not actually run --
# run.sh refused on the run lock, prep failed, the timeout fired -- that glob
# returns the PREVIOUS lap's directory and its stale `VERDICT PASS` is scored
# as this lap's result.  The streak would climb on laps that never happened.
# So: the evidence directory is pinned before each row and must have MOVED
# afterwards, the row's own rc must be 0, and a lap that cannot prove it ran is
# a FAIL that resets the streak rather than a lap that is quietly skipped.
#
# derived time budgets, from measured walls rather than round numbers: prep 300 s
# (measured 88-112 s on this fleet), the death row 500 s (measured 333-392 s;
# the manifest's own budget is 470 s and run.sh enforces it), the closing board
# 1323 s (960 s of measured walls + 12 s x 29 tests of harness overhead + 15 s
# startup).  A timeout is a FAILURE to diagnose, never a number to widen.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480c}; N_NDR=${2:-10}
GATE=${GATE:-tests/evidence/sess479_chain119_board_s480b.log}
LOG=tests/evidence/sess480_chain120_ndr_streak_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain120 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) want_sv=$PROD_SV N_NDR=$N_NDR ==="
  if [ ! -f "$PROD_KO" ]; then echo "ABORT: missing $PROD_KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  cp "$PROD_KO" mxfs.ko || { echo "ABORT: install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$PROD_SV"
  [ "$sv" = "$PROD_SV" ] || { echo "ABORT: srcversion mismatch — this is not the final candidate"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  # The false-SKIP half of this record's fix must be present in the binary
  # under test, or the streak proves nothing about it.
  ovr=$(strings -a mxfs.ko | grep -c 'OVERRIDE-APPLY')
  echo "STAGE buflsn_bypass_present=$ovr"
  [ "$ovr" != 0 ] || { echo "ABORT: mxfs.ko lacks the buffer-LSN class-gated bypass (false-SKIP arm)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # Attempt-bounded rather than index-bounded.  A lap that could not run (the
  # run lock was held throughout) must not consume one of the ten, or the
  # criterion becomes unreachable for a reason that has nothing to do with the
  # filesystem.  The cap stops it looping for ever when the rig is genuinely
  # unavailable, and the verdict below still requires a real consecutive streak.
  streak=0; best=0; laps_run=0; lap=0; attempts=0
  MAX_ATTEMPTS=$(( N_NDR * 2 ))
  while [ "$streak" -lt "$N_NDR" ] && [ "$attempts" -lt "$MAX_ATTEMPTS" ]; do
    attempts=$((attempts+1)); lap=$((lap+1))
    # run.sh exits 3 when ANOTHER run.sh holds the run lock.  That is an
    # infrastructure refusal, not a result about this filesystem, and scoring it
    # as a lap failure is the same defect this file's header criticises -- an
    # unprepped fleet recorded as an outcome.  It has already cost one full
    # launch: a peer chain held the lock for the whole window and all ten laps
    # came back "prep rc=3", giving laps_run=0 of 10 and a streak of zero that
    # says nothing about the build.  So a lock refusal WAITS and retries the
    # same lap rather than consuming it.  A prep that fails for any other reason
    # is a real failure and still resets the streak.
    prc=1; tries=0
    while [ $tries -lt 6 ]; do
      timeout 300 ./run.sh 32 caw prep_cluster; prc=$?
      [ "$prc" != 3 ] && break
      tries=$((tries+1))
      echo "STAGE prep_lap$lap rc=3 (run lock held by a peer run.sh — NOT a lap result); waiting, retry $tries/6"
      bash tests/rig_wait_free.sh 3600 || { echo "STAGE prep_lap$lap: rig never freed"; break; }
    done
    echo "STAGE prep_lap$lap rc=$prc retries=$tries"
    if [ "$prc" -ne 0 ]; then
      if [ "$prc" = 3 ]; then
        echo "LAP$lap NOT RUN: the run lock was held for every attempt.  This lap measured nothing and is NOT scored either way; the streak is left at $streak."
        continue
      fi
      echo "LAP$lap FAIL: prep rc=$prc — streak resets ($streak -> 0)"
      streak=0; continue
    fi
    pre_dir=$(ls -dt tests/evidence/board_*_node_death_replay 2>/dev/null | head -1)
    T0=$(date +%s)
    timeout 500 ./run.sh 32 caw node_death_replay; rrc=$?
    wall=$(( $(date +%s) - T0 ))
    echo "STAGE node_death_replay$lap rc=$rrc wall=${wall}s budget=500s"
    post_dir=$(ls -dt tests/evidence/board_*_node_death_replay 2>/dev/null | head -1)
    laps_run=$((laps_run+1))
    if [ "$post_dir" = "$pre_dir" ] || [ -z "$post_dir" ]; then
      echo "LAP$lap FAIL: the death row produced NO new evidence directory (still '$pre_dir', rc=$rrc).  The row did not run; the previous lap's VERDICT must not be scored as this one's.  Streak resets ($streak -> 0)"
      streak=0; continue
    fi
    if [ "$rrc" -ne 0 ]; then
      echo "LAP$lap FAIL: node_death_replay rc=$rrc (wall=${wall}s) — streak resets ($streak -> 0)"
      streak=0; echo "EVIDENCE $post_dir"; continue
    fi
    echo "EVIDENCE $post_dir"
    ok=1
    for l in shared single; do
      v=$(grep -a '^VERDICT' "$post_dir/$l.log" 2>/dev/null | head -1 | cut -c1-160)
      if [ -z "$v" ]; then echo "LAP$lap $l: (no VERDICT line — arm did not report)"; ok=0
      else echo "LAP$lap $l: $v"; echo "$v" | grep -q 'VERDICT PASS' || ok=0; fi
    done
    echo "LAP$lap f4truth: $(cat "$post_dir"/*/recov_test*.txt 2>/dev/null | grep -ao 'truth=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
    echo "LAP$lap buflsn: $(cat "$post_dir"/*/recov_test*.txt 2>/dev/null | grep -ao 'buflsn_skips=[0-9]* buflsn_overrides=[0-9]*' | sort | uniq -c | tr '\n' ' ') verdicts: $(cat "$post_dir"/*/recov_test*.txt 2>/dev/null | grep -a 'P-FR-BUF-LSN' | grep -ao 'verdict=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
    if [ $ok = 1 ]; then
      streak=$((streak+1)); [ $streak -gt $best ] && best=$streak
      echo "LAP$lap PASS — consecutive streak=$streak"
    else
      echo "LAP$lap FAIL: an arm did not report VERDICT PASS — streak resets ($streak -> 0)"
      streak=0
    fi
  done
  echo "NDR_STREAK final_consecutive=$streak longest_consecutive=$best laps_run=$laps_run attempts=$attempts of max $MAX_ATTEMPTS (need $N_NDR consecutive)"
  if [ "$streak" -ge 10 ]; then
    echo "NDR_STREAK: criterion (3) MET on $PROD_SV — 10 consecutive node_death_replay PASS under production defaults"
  else
    echo "NDR_STREAK: criterion (3) NOT MET (need 10 consecutive, longest was $best)"
  fi
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
