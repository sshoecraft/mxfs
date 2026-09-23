#!/bin/bash
# sess482 chain 130: MEASURE THE AFFINE FAST PATH'S BLESSINGS FOR THE FIRST TIME.
#
# THE DEFECT (D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED).  The dentry
# revalidation affine fast path returns VALID for a cached (parent, name) ->
# inode binding with NO coordinated lookup and NO check of the parent's hold
# epoch, whenever the CHILD inode lives in this node's own allocation group.
# Its premise is about the child ("under node-affine allocation we own it");
# the claim it needs is about the PARENT ("this name still resolves here").
# Those are different properties.  A peer unlinking the name must take dp EX,
# which drops this node to NL and bumps its epoch -- so the epoch fast path
# correctly declines, and the affine exit blesses the destroyed binding anyway.
# The named consequence is silent data loss: open(O_CREAT) truncating the
# current occupant of a recycled inode.
#
# WHY NO PRIOR RUN MEASURED IT.  Two probes tested dentry->d_time against the
# parent epoch.  d_time has exactly one writer in the tree and this exit returns
# before reaching it, so an affine regular-file dentry -- the whole of the
# vector -- holds d_time == 0 for its entire life.  The first probe therefore
# fired on everything (229,444 lines in one row, 100% with d_time=0); the
# second, narrowed to d_time != 0, is silent on precisely the files at risk.
# A zero from either says nothing.  0.66.0 replaces them with a direct test.
#
# WHAT THIS CHAIN RUNS.  mxfs.affine_audit_pct diverts a sampled fraction of
# blessings into the coordinated validation the exit skips -- which already
# computes the wanted verdict -- and compares.  node_death_replay is the right
# row: it is the one currently passing with real headroom (measured 368-380 s
# against a 470 s budget, ten consecutive laps in chain 120), and it manufactures
# the vector's precondition, a DEAD PARENT INCARNATION, on every lap.
#
# THE VERDICT RULE, fixed here in advance so the result cannot be read
# favourably afterwards:
#   n            = audits taken.  This is the denominator; a miss count without
#                  it is unreadable, and a zero without it is worthless.
#   gone/rebind/incarn = CONFIRMED wrong blessings.  ANY nonzero is a real
#                  defect on the one positive-dentry exit that ignores the
#                  parent hold epoch: severity becomes critical and the fix is
#                  to narrow or remove the exit.
#   operr        = NOT a miss.  The coordinated path maps every errno to
#                  INVALID because that is safe for the VFS, but only -ENOENT
#                  means the name is gone.  Counting transport noise here would
#                  manufacture a defect that is not there.
#   zero misses  = bounds the miss rate among AUDITED encounters at about 3/n
#                  (95%).  A BOUND, not a proof, and it is quoted with n.
# The audit is an INTERLOCK, not an observer: a sampled bad blessing is also
# refused.  So a miss count is what was CAUGHT, and is a lower bound on what
# would have been served with the knob off.
#
# WHY 5 PERCENT.  The affine exit fired ~7,170 times per node per row (229,444
# over 32 nodes).  At 5% that is ~360 audits/node, ~11,500 fleet-wide, giving a
# 3/n bound near 0.03% fleet-wide -- while adding one coordinated directory
# lookup per 20 blessings.  100% is NOT used on purpose: that fast path exists
# because the coordinated lookup made a solo rsync 127 s against ~5 s, so
# auditing every blessing would blow the row's budget and turn a correctness
# measurement into a budget failure that says nothing about correctness.
#
# ANTI-VACUITY GATES, because a PASS from a step that never ran is this
# project's most common evidence failure:
#   - the built module must actually EXPOSE affine_audit_pct (modinfo), else the
#     lap would run with no instrument and report a clean zero;
#   - the knob must READ BACK as 5 on all 32 nodes before the armed lap;
#   - the CONTROL lap must produce ZERO audit lines (proves the knob gates);
#   - the ARMED lap must produce a NONZERO n (proves the knob armed).
#   Any of these failing is an ABORT, never a quietly-skipped step.
#
# derived time budgets, derived: prep 300 s (measured 88-112 s); each node_death_replay
# 500 s (measured 368-380 s, and run.sh enforces the manifest's own 470 s); knob
# set/readback 60 s (fleet_set_params bounds each ssh at 40 s and runs parallel);
# log sweep 120 s (fleet_probe_sweep bounds each node at 25 s).  Total ~1900 s.
# The armed lap keeps the SAME 470 s budget as the control -- the audit cost is
# not an excuse to widen it, and a timeout there is a real the budget rule finding about
# what the coordinated lookup costs.
#
# Usage:  setsid nohup bash tests/sess482_chain130_affine_audit.sh s482b &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s482b}
GATE=${GATE:-tests/evidence/sess482_chain129_ladderF_s482a.log}
LOG=tests/evidence/sess482_chain130_affine_audit_$LABEL.log
EV=tests/evidence/sess482_affine_audit_$LABEL
PCT=${PCT:-5}
mkdir -p "$EV"

gate_dl=$(( $(date +%s) + 21600 ))
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$gate_dl" ]; then
        echo "=== sess482 chain130 ABORT: gate $GATE never reached DONE within 6 h ===" >> "$LOG"
        echo "DONE $(date -u +%FT%TZ)" >> "$LOG"
        exit 1
    fi
    sleep 30
done

{
  echo "=== sess482 chain130 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  echo "STAGE gate cleared: $GATE"

  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # GATE 1: the instrument must exist in the module that is about to be shipped.
  if ! modinfo mxfs.ko 2>/dev/null | grep -q 'affine_audit_pct'; then
      echo "ABORT: mxfs.ko does not expose affine_audit_pct — the laps below would"
      echo "       run with no instrument and report a clean zero that means nothing."
      echo "       Build the tree (0.66.0 or later) before running this chain."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE instrument_present sv=$sv"

  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # ---- CONTROL LAP: knob off (its default). Establishes the baseline wall and
  # ---- proves the instrument is genuinely gated rather than always-on.
  T0=$(date +%s); SINCE0=$(date -u +'%Y-%m-%d %H:%M:%S')
  timeout 500 ./run.sh 32 caw node_death_replay; c_rc=$?
  echo "STAGE control_lap rc=$c_rc wall=$(( $(date +%s) - T0 ))s budget=470s (run.sh enforces)"

  timeout 120 bash tests/fleet_probe_sweep.sh "$EV/sweep_control" "$SINCE0" 32 \
      'P165-AFFINE-AUDIT' 'P165-AFFINE-AUDIT-MISS' > "$EV/sweep_control.txt" 2>&1
  ctl=$(grep -a '^SUM P165-AFFINE-AUDIT=' "$EV/sweep_control.txt" | sed 's/.*=//' | tr -dc '0-9')
  ctl=${ctl:-0}
  echo "STAGE control_audit_lines=$ctl (MUST be 0 — the knob defaults to off)"
  [ "$ctl" = 0 ] || echo "WARNING: audit output with the knob OFF — the gate is not gating; every number below is suspect"

  # ---- WAIT FOR THE FLEET TO COME BACK before arming.
  # sess483: this chain aborted twice in a row on "armed on only 30 of 32",
  # both times with test6 and test7 returning ssh rc=255 and the fleet reading
  # mounted 0/32.  Neither node was faulty — a sweep minutes later found all 32
  # reachable.  The control lap is node_death_replay, which destroys and
  # reboots nodes; the arm step was simply running while two of them were still
  # coming back up.  The chain was refusing to spend a lap on a partially armed
  # fleet, which is right, but it was creating the partial fleet itself.
  #
  # This is a readiness GATE, not a performance budget: 240 s is derived from
  # guest boot (~60-90 s measured) plus the mount and rejoin behind it, doubled,
  # and it exits the moment all 32 answer.  A chain that waits 90 s costs 90 s;
  # a chain that arms early costs the whole lap.
  ready_dl=$(( $(date +%s) + 240 ))
  while :; do
      up=0
      for i in $(seq 1 32); do
          ( r=$(timeout 15 tools/mxfs_sshpass.sh "test$i" \
                  "mountpoint -q /mnt/shared && echo RDY" 2>/dev/null | tr -dc 'A-Z')
            echo "${r:-DOWN}" > "$EV/.rdy.test$i" ) &
      done
      wait
      up=$(cat "$EV"/.rdy.test* 2>/dev/null | grep -c '^RDY$')
      [ "$up" -eq 32 ] && { echo "STAGE fleet_ready 32/32 mounted"; break; }
      if [ "$(date +%s)" -ge "$ready_dl" ]; then
          echo "STAGE fleet_ready TIMEOUT: only $up/32 nodes reachable and mounted after 240 s"
          echo "  Not arming — a partially present fleet gives a denominator that cannot be"
          echo "  attributed, and the missing nodes are a rig fault to fix, not a number to lower."
          echo "DONE $(date -u +%FT%TZ)"; exit 1
      fi
      sleep 10
  done

  # ---- ARM the knob and PROVE it armed on all 32 before spending a lap.
  timeout 60 bash tests/fleet_set_params.sh "affine_audit_pct=$PCT" 32 "$EV/knobs_on.txt" \
      > "$EV/knobs_on.log" 2>&1; krc=$?
  armed=$(grep -ac "affine_audit_pct=$PCT" "$EV/knobs_on.txt" 2>/dev/null)
  armed=${armed:-0}
  echo "STAGE arm rc=$krc readback_ok=$armed/32"
  if [ "$armed" -ne 32 ]; then
      echo "ABORT: knob armed on only $armed of 32 nodes — a partially-armed fleet"
      echo "       produces a denominator that cannot be attributed. Not spending a lap on it."
      echo "       $(tail -3 "$EV/knobs_on.log" | tr '\n' ' ')"
      timeout 60 bash tests/fleet_set_params.sh "affine_audit_pct=0" 32 "$EV/knobs_off.txt" >/dev/null 2>&1
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  # ---- ARMED LAP: same row, same budget. The audit cost is not an excuse to widen it.
  T1=$(date +%s); SINCE1=$(date -u +'%Y-%m-%d %H:%M:%S')
  timeout 500 ./run.sh 32 caw node_death_replay; a_rc=$?
  a_wall=$(( $(date +%s) - T1 ))
  echo "STAGE armed_lap rc=$a_rc wall=${a_wall}s budget=470s pct=$PCT"

  timeout 120 bash tests/fleet_probe_sweep.sh "$EV/sweep_armed" "$SINCE1" 32 \
      'P165-AFFINE-AUDIT' 'P165-AFFINE-AUDIT-MISS' 'kind=GONE' 'kind=REBIND' 'kind=INCARN' \
      > "$EV/sweep_armed.txt" 2>&1

  # ---- DISARM and prove it, so the fleet is left on production defaults.
  timeout 60 bash tests/fleet_set_params.sh "affine_audit_pct=0" 32 "$EV/knobs_off.txt" \
      > "$EV/knobs_off.log" 2>&1
  off=$(grep -ac 'affine_audit_pct=0' "$EV/knobs_off.txt" 2>/dev/null); off=${off:-0}
  echo "STAGE disarm readback_ok=$off/32"
  [ "$off" -eq 32 ] || echo "WARNING: fleet NOT uniformly back on the default — do not run a production criterion until it is"

  # ---- VERDICT, against the rule stated at the top of this file.
  echo "--- VERDICT ---"
  sum=$(grep -a '^SUM P165-AFFINE-AUDIT=' "$EV/sweep_armed.txt" | sed 's/.*=//' | tr -dc '0-9')
  mis=$(grep -a '^SUM P165-AFFINE-AUDIT-MISS=' "$EV/sweep_armed.txt" | sed 's/.*=//' | tr -dc '0-9')
  sum=${sum:-0}; mis=${mis:-0}
  echo "  audit summary lines fleet-wide = $sum   (one is emitted per 10,000 audits per node)"
  echo "  MISS lines fleet-wide          = $mis"
  for k in GONE REBIND INCARN; do
    v=$(grep -a "^SUM kind=$k=" "$EV/sweep_armed.txt" | sed 's/.*=//' | tr -dc '0-9')
    echo "  kind=$k = ${v:-0}"
  done
  echo "  verbatim audit/miss lines (first hits per node are in $EV/sweep_armed/):"
  grep -a '^HIT ' "$EV/sweep_armed.txt" | head -20

  if [ "$sum" = 0 ]; then
      echo "  READING: NO audit summary line appeared. Either the row generated fewer than"
      echo "  10,000 audits per node, or the knob did not take effect despite reading back."
      echo "  The MISS count alone is then NOT a measurement — n is unknown, so a zero here"
      echo "  bounds nothing. Re-run with a higher pct or a longer row before citing it."
  elif [ "$mis" = 0 ]; then
      echo "  READING: zero confirmed wrong blessings across the audited sample. This BOUNDS"
      echo "  the miss rate among audited encounters; it does not prove absence. Quote the"
      echo "  bound with n taken from the last P165-AFFINE-AUDIT line on each node."
  else
      echo "  READING: CONFIRMED wrong blessing(s) on the exit that ignores the parent hold"
      echo "  epoch. Check the kind= split above: any GONE/REBIND/INCARN is real (operr is"
      echo "  not). D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED becomes critical and the"
      echo "  fix is to narrow or remove the affine exit, not to tune the probe."
  fi

  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
