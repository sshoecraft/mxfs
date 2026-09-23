#!/bin/bash
# sess482 chain 129: IS THE op1 CONCENTRATION A PROPERTY OF THE FILESYSTEM, OR
# OF THE HARNESS THAT MEASURED IT?
#
# THE FINDING THIS TEST EXISTS TO FALSIFY.  Chain 124 ran the create-scale curve
# twice at F=8 files/node.  Decomposing its 2016 raw per-op samples by op index
# gives, for the SHARED-directory arm, the share of ALL create milliseconds that
# op index 1 alone accounts for (a uniform cost over 8 ops would give 12.5%):
#
#     P=4   68.9% / 50.2%      (lap1 / lap2)
#     P=8   75.0% / 66.1%
#     P=16  84.0% / 87.8%
#     P=32  93.9% / 90.6%
#
# and at P=32 the remaining ops are cheap: op1 p50 = 1454 ms, ops 2-8 p50 = 8-10
# ms -- BELOW the private arm's steady state (p50 27-32 ms).  Read naively that
# says the shared directory is not a per-create bottleneck at all, and that its
# whole cost is a one-time admission per node.
#
# WHY THAT READING IS NOT YET SAFE.  The clients are CLOSED-LOOP and start
# together: a node cannot issue op2 until op1 has been admitted.  So every bit
# of the initial 32-way queue drain is charged to op1 BY CONSTRUCTION, and cold
# first-touch costs (lock-resource setup, cache and journal warmup) land there
# too.  A synchronised burst measured this way produces a >90% op1 share whether
# or not any reusable "one-time admission" state exists.  With only 8 ops per
# node the run may simply END before the holder's quantum expires.
#
# THE DISCRIMINATOR, and it is a clean one.  Hold P at 32 and vary F.
#
#   ONE-TIME ADMISSION: op1 stays expensive, every later op stays ~10 ms, and
#     op1's share of total falls steadily as F grows (it is one fixed cost
#     divided by more ops).  Per-node wall grows as 1486 + (F-1)*14 ms.
#
#   BATCHING QUANTUM: a SECOND expensive op appears at some index K, and then a
#     third near 2K.  The spikes are periodic.  op1's share collapses toward
#     1/(number of rotations).  This is the outcome that would explain the
#     failing crash_consistency row, whose own trace reports EIGHT waits per
#     node for ~100 creates -- i.e. ~12.5 creates per grant episode.
#
# The two predictions differ in the RAW per-op-index series, not in any summary
# statistic, which is why every sample is kept.
#
# WHAT THIS CHAIN DOES NOT CLAIM.  It measures the create-scale harness, not the
# failing row.  Whatever it finds, the decisive evidence for crash_consistency is
# a grant-epoch trace of THAT workload (creates completed per directory-EX
# ownership epoch).  This chain is the cheap prior that says whether that trace
# is worth building, and it can refute the op1 story without any rig time spent
# on the harder instrument.
#
# derived time budgets, derived rather than rounded.  Chain 124 measured the full
# 6-point ladder x 2 arms at F=8 in 34 s, i.e. ~2.8 s per point, of which most
# is ssh fan-out to 32 nodes.  Here each F value is 2 points (P=32 only).
# Fixed cost per F: ~12 s fan-out x 2 arms + ~1.5 s admission x 2 = ~27 s.
# Variable cost: F creates at a measured 8-14 ms.  The PATHOLOGICAL ceiling the
# test is looking for is a full grant rotation (~1.5 s at P=32) per create, so
# the guard allows 1.6 s per file rather than the measured 0.014 s -- that is
# deliberately the cost of the outcome being hunted, not padding:
#     guard(F) = 60 + F*1.6   ->  73, 86, 111, 162, 265 s for F = 8..128
# prep keeps its measured 300 s (88-112 s observed).  Total ~1000 s.
# A timeout here is a RESULT (it means rotation-per-create), not a number to
# widen: the chain records it as such and moves to the next F.
#
# Usage:  setsid nohup bash tests/sess482_chain129_create_ladder_F.sh s482a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s482a}
GATE=${GATE:-tests/evidence/sess481_chain128_create_cost_s481a.log}
LOG=tests/evidence/sess482_chain129_ladderF_$LABEL.log
EV=tests/evidence/sess482_ladderF_$LABEL
FLIST=${FLIST:-8 16 32 64 128}
mkdir -p "$EV"

# Bounded: a gate chain that dies without writing DONE must not leave this
# one waiting forever with the rig idle.
gate_dl=$(( $(date +%s) + 21600 ))
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$gate_dl" ]; then
        echo "=== sess482 chain129 ABORT: gate $GATE never reached DONE within 6 h ===" >> "$LOG"
        echo "DONE $(date -u +%FT%TZ)" >> "$LOG"
        exit 1
    fi
    sleep 30
done

{
  echo "=== sess482 chain129 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  echo "STAGE gate cleared: $GATE"

  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc — with no fleet nothing below measures anything"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  sv=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
  echo "STAGE build_identity sv=$sv"

  for F in $FLIST; do
    guard=$(( 60 + F * 16 / 10 ))
    echo "--- F=$F files/node, P=32 only, guard=${guard}s (1.6 s/file allows one full grant rotation per create — the outcome being hunted) ---"
    T0=$(date +%s)
    CSC_OUT=$EV/F$F LADDER=32 timeout "$guard" bash tests/create_scale_curve.sh "$F" caw
    rc=$?
    wall=$(( $(date +%s) - T0 ))
    if [ "$rc" = 124 ]; then
      echo "STAGE F$F TIMEOUT at ${wall}s — this is a RESULT: per-node cost exceeded 1.6 s/file, which is rotation-per-create territory"
    else
      echo "STAGE F$F rc=$rc wall=${wall}s"
    fi
  done

  echo "--- sample accounting (proof each F produced data rather than reporting on none) ---"
  for F in $FLIST; do
    want=$(( 32 * F ))
    for arm in private shared; do
      got=$(cat "$EV/F$F/${arm}_P32"/n*.txt 2>/dev/null | grep -ac '^OP ')
      got=${got:-0}
      if [ "$got" -eq 0 ]; then
        echo "  F=$F $arm samples=0 of $want — THIS ARM MEASURED NOTHING AND MUST NOT BE CITED"
      elif [ "$got" -ne "$want" ]; then
        echo "  F=$F $arm samples=$got of $want expected (SHORT — the arm was cut off; cite only with this caveat)"
      else
        echo "  F=$F $arm samples=$got of $want"
      fi
    done
  done

  echo "--- op-index decomposition, SHARED arm, P=32 (the discriminator) ---"
  echo "    reading: op1 share FALLING smoothly with F and no second spike => one-time admission."
  echo "             a spike recurring at some index K => batching quantum, and K is the batch size."
  python3 - "$EV" $FLIST <<'PY'
import os, sys
ev = sys.argv[1]
for F in sys.argv[2:]:
    d = os.path.join(ev, "F%s" % F, "shared_P32")
    if not os.path.isdir(d):
        print("  F=%-4s no directory %s" % (F, d)); continue
    per = {}
    for fn in sorted(os.listdir(d)):
        if not fn.startswith("n") or not fn.endswith(".txt"):
            continue
        for line in open(os.path.join(d, fn)):
            if line.startswith("OP "):
                p = line.split()
                if len(p) >= 3:
                    try:
                        per.setdefault(int(p[1]), []).append(float(p[2]))
                    except ValueError:
                        pass
    if not per:
        print("  F=%-4s zero samples — measured nothing" % F); continue
    tot = sum(sum(v) for v in per.values())
    idx = sorted(per)
    # every op index whose mean is >= 10x the median-of-means is a spike
    means = {i: sum(per[i]) / len(per[i]) for i in idx}
    ordered = sorted(means.values())
    med = ordered[len(ordered) // 2]
    spikes = [i for i in idx if med > 0 and means[i] >= 10 * med]
    op1 = sum(per[idx[0]]) if idx else 0.0
    print("  F=%-4s total_ms=%-10.0f op1_share=%5.1f%%  spike_indices(mean>=10x median)=%s"
          % (F, tot, 100.0 * op1 / tot if tot else 0.0, spikes if spikes else "none"))
    print("       per-index mean_ms: %s"
          % " ".join("%d:%.0f" % (i, means[i]) for i in idx[:24]))
    if len(idx) > 24:
        print("       (%d indices total, first 24 shown)" % len(idx))
PY

  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
