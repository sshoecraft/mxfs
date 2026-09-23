#!/bin/bash
# sess480 chain 124: the UNCENSORED create-pace lap for
# D-32NODE-SHARED-DIR-CREATE-PACE, which the 0.64.37 board just proved is the
# blocker on criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES.
#
# Why not another board.  The board's crash_consistency row fails at 91/90 s
# with every node reporting checks=11 passed=11 failed=0 -- a pure wall-time
# failure whose latency distribution is RIGHT-CENSORED at the 90 s deadline.
# Censored data cannot show the shape of the tail, and the tail is the whole
# question: p50 is 10 ms and flat in N while the mean is 255 ms, so each node
# pays roughly one multi-second stall per 8 creates rather than being uniformly
# slower.  A 100x+ outlier against a 10 ms median smells like a timer, not
# contention, and "EX rotation among 32 contenders" locates where requests
# queue without explaining why individual transitions cost seconds.
# tests/create_scale_curve.sh takes no run.sh flock and has no deadline, so it
# can measure what the board can only truncate.
#
# What the two laps discriminate.  Lap 1 runs on a freshly prepped fleet; lap 2
# runs immediately after on the SAME warm mount with FRESH directories.  If the
# stalls persist into lap 2, the cold state is DIRECTORY-specific (block
# allocation/split, first log reservation, first mastering of that inode's DLM
# resource).  If they vanish, it was mount/transport/cluster warm-up.  That is
# the cheapest available separation of the two stories behind the first-lap
# effect (baseline lap 1 exhausting the budget on all 32 nodes while laps 2-3
# pass at 21-22 s), and it needs no kernel change -- which matters, because
# changing kernel source right now would invalidate the 0.64.37 candidate that
# criteria (2) and (3) are being measured against.
#
# The harness now also prints, per arm, the tail's MODES (slow samples bucketed:
# a queue spreads them, a lease/quantum or timeout-retry piles them at a fixed
# value) and STALLS BY OP INDEX (clustered at op 1 = a one-time cold cost
# amplified into a cluster-wide convoy; spread evenly = steady-state
# contention).
#
# the budget rule.  The 1800 s guard below is a HANG BACKSTOP, not a performance budget,
# and it is deliberately not derived from expected walls: the measurement's
# entire purpose is to let slow operations run to completion and be recorded, so
# a budget tight enough to be a performance assertion would censor exactly the
# samples being collected.  The per-operation latencies this produces ARE the
# performance assertion, and they are judged against the 2x-native ceiling
# afterwards.  prep keeps its ordinary derived 300 s (measured 88-112 s).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480j}
GATE=${GATE:-tests/evidence/sess480_chain120_ndr_streak_s480i.log}
LOG=tests/evidence/sess480_chain124_pace_$LABEL.log
EV=tests/evidence/sess480_pace_$LABEL
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain124 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$PROD_KO" ] || { echo "ABORT: missing $PROD_KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$PROD_KO" mxfs.ko || { echo "ABORT: install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$PROD_SV"
  [ "$sv" = "$PROD_SV" ] || { echo "ABORT: srcversion mismatch"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc — no fleet, so nothing below would measure anything"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for lap in 1 2; do
    echo "--- lap $lap ($([ $lap = 1 ] && echo 'COLD: freshly prepped fleet' || echo 'WARM MOUNT, FRESH DIRECTORIES')) ---"
    T0=$(date +%s)
    CSC_OUT=$EV/lap$lap timeout 1800 bash tests/create_scale_curve.sh 8 caw
    echo "STAGE lap$lap rc=$? wall=$(( $(date +%s) - T0 ))s (1800 s guard is a hang backstop, not a budget)"
    echo "  raw per-op samples kept in $EV/lap$lap"
  done

  echo "--- sample counts kept (proof the laps produced data rather than reporting on none) ---"
  for lap in 1 2; do
    n=$(cat "$EV/lap$lap"/*/n*.txt 2>/dev/null | grep -ac '^OP ')
    echo "  lap$lap OP samples=$n"
    [ "${n:-0}" -gt 0 ] || echo "  lap$lap WARNING: zero samples — this lap measured nothing and must not be cited"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
