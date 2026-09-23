#!/bin/bash
# sess480 chain 126: does the SHARED DIRECTORY cause the crash_consistency
# barrier stall, or is the barrier failing for its own reasons?
#
# THE OBSERVATION THIS TESTS.  Two boards on 0.64.37 both failed the row with
# nodes_pass=0/32 and BUDGET_EXHAUSTED on every node, but at different depths.
# The second one, run 20260904T000831Z, reported
#   steps[cc barrier written=29, cc barrier ready=3]
# and run.sh builds that histogram from each node's failure reason (run.sh:1326
# takes step= out of the reason field), so it names WHERE EACH NODE WAS PARKED,
# not what it completed.  Per-node extraction of the same field identifies the
# three: test23, test27 and test30 never cleared the FIRST barrier (cc_ready)
# while the other 29 sat waiting at the second (cc_written).  Twenty-nine nodes
# had done their work and failed because three had not arrived.
#
# THE HYPOTHESIS.  Everything a node does before `ck "cc barrier ready"`
# (tests/suite/crash_consistency.sh:69) touches the ONE shared directory: a
# stat of $D at :47 and, in the default non-private shape, `mkdir -p $D` at :65
# via ccdir().  That is exactly the inode whose contention
# D-32NODE-SHARED-DIR-CREATE-PACE measures at p50 = 10 ms with a multi-second
# tail and 74.5% of blocked time in the CAW inode-grant wait.  With 32 nodes
# each touching it before the barrier, the row becomes a 32-sample draw from
# that tail, and a fleet-wide barrier makes ONE unlucky draw fatal for all 32.
# If that is right it explains both failure shapes and the 4x run-to-run
# variance, without the barrier itself being defective.
#
# THE FALSIFIABLE PREDICTION.  CC_PRIVATE=1 gives each node its own
# subdirectory, so the shared directory lock does not rotate
# (crash_consistency.sh:53-60, added for the sess436 ruling).  If the shared
# directory is the cause, the private leg should converge through both barriers
# while the shared leg stalls, ON THE SAME BUILD MINUTES APART.  If the private
# leg ALSO strands nodes at cc_ready, the shared directory is NOT the whole
# story and the barrier needs its own investigation -- which would be a new
# finding, not a null result.
#
# This is a MEASUREMENT, never a route to a green board: the source comment at
# :58 is explicit that CC_PRIVATE "is never a board condition; the board row
# stays the shared-directory workload", and nothing here changes the row.
#
# budget: prep 300 s (measured 88-117 s); the cc row keeps its UNCHANGED 90 s
# budget, which run.sh enforces itself, plus ~37 s of measured startup -> 160 s
# per leg.  Both legs are run twice, alternating, because a single pair could be
# one draw from a tail rather than a difference.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480l}
GATE=${GATE:-tests/evidence/sess480_chain125_iclus_anchored_s480k.log}
LOG=tests/evidence/sess480_chain126_cc_private_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain126 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$PROD_KO" mxfs.ko || { echo "ABORT: install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$PROD_SV"
  [ "$sv" = "$PROD_SV" ] || { echo "ABORT: srcversion mismatch"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for lap in 1 2; do
  for leg in shared private; do
    echo "--- lap $lap leg=$leg ---"
    timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; prc=$?
    echo "STAGE prep_${leg}_$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then
      echo "LEG $leg lap $lap NOT RUN: prep rc=$prc — an unprepped fleet is not a result and is not scored."
      continue
    fi
    # harness-lint: ok - pinned BEFORE the row and compared with $post below; a row that produced no new directory is refused, not scored
    pre=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    O=tests/evidence/sess480_cc_private_$LABEL; mkdir -p "$O"
    if [ "$leg" = private ]; then
      MXFS_TEST_ENV="CC_PRIVATE=1" timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_${leg}_$lap.out" 2>&1
    else
      timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_${leg}_$lap.out" 2>&1
    fi
    rc=$?
    # harness-lint: ok - compared against the $pre pinned above, which is the freshness check
    post=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    echo "STAGE cc_${leg}_$lap rc=$rc"
    #
    # sess483 FIX — THIS GATE USED TO REFUSE TO SCORE A PASS, AND IT THREW AWAY
    # THIS EXPERIMENT'S ANSWER.  It keyed "did the row run?" on a NEW
    # tests/evidence/run_crash_consistency_* directory.  That directory is
    # written when the row FAILS; a passing row writes none.  So both private
    # legs -- the outcome this chain exists to detect -- were reported as
    # "NOT SCORED: the row produced no new evidence directory" while the leg
    # outputs sitting right there said PASS 32/32, 204/204 checks, 18s and 19s
    # of a 90s budget.  The gate's instinct was right (never read a stale
    # directory as this leg's result); its key was a failure artefact.
    #
    # The correct proof of execution is the run_id run.sh prints into THIS
    # leg's own captured output.  It is unique per invocation and exists on
    # pass and fail alike.  The evidence directory is still used, but only for
    # the per-node parked/straggler detail, which genuinely does not exist when
    # nothing parked.
    rid=$(grep -ao 'run_id=[0-9A-Za-z]*' "$O/cc_${leg}_$lap.out" | tail -1)
    row=$(grep -aE 'crash_consistency' "$O/cc_${leg}_$lap.out" | grep -a 'nodes_pass' | tail -1)
    if [ -z "$rid" ] || [ "$rid" = "${last_rid:-}" ] || [ -z "$row" ]; then
      echo "LEG $leg lap $lap NOT SCORED: no fresh run_id (got '${rid:-none}', previous '${last_rid:-none}') or no verdict row in the leg output; the previous leg's result must not be read as this one's."
      continue
    fi
    last_rid=$rid
    # The row line carries nodes_pass and the steps[] histogram -- the two
    # numbers this experiment turns on.
    echo "$row" | cut -c1-300 | sed "s/^/  $leg lap$lap ROW: /"
    echo "  $leg lap$lap $rid"
    if [ "$post" = "$pre" ] || [ -z "$post" ]; then
      echo "  $leg lap$lap PARKED: none — no evidence directory was written, which for this row means nothing parked and nothing failed. The ROW line above is the result."
      continue
    fi
    # Per-node parked step, which the histogram summarises and which names the
    # stragglers when there are any.
    echo -n "  $leg lap$lap PARKED: "
    for f in "$post"/test*[0-9]; do
      [ -f "$f" ] || continue
      grep -ao 'step=cc barrier [a-z]*' "$f" 2>/dev/null | tail -1
    done 2>/dev/null | sort | uniq -c | tr '\n' ' '
    echo
    echo -n "  $leg lap$lap STRAGGLERS(cc_ready): "
    for f in "$post"/test*[0-9]; do
      [ -f "$f" ] || continue
      grep -aq 'step=cc barrier ready' "$f" 2>/dev/null && printf '%s ' "$(basename "$f")"
    done 2>/dev/null
    echo
    echo "  $leg lap$lap EVIDENCE $post"
  done
  done
  echo "--- reading ---"
  echo "  If the private legs pass or converge through both barriers while the shared legs strand"
  echo "  nodes at cc_ready, the shared-directory inode is the cause and D-32NODE-SHARED-DIR-CREATE-PACE"
  echo "  owns the crash_consistency row outright.  If BOTH shapes strand nodes, the fleet-wide barrier"
  echo "  has a problem of its own and D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401 needs a"
  echo "  separate root, which is a finding and not a null result."
  timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
