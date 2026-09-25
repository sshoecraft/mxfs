#!/bin/bash
# sess483 chain 132: IS THE SHARED-DIRECTORY CREATE COST DRIVEN BY F AT ALL,
# AND IF SO IS THE MECHANISM A COLLAPSING DIRECTORY TENURE?
#
# BACKGROUND.  D-32NODE-SHARED-DIR-CREATE-PACE now owns the crash_consistency
# board row outright (sess483: private directories PASS 32/32 in 18-19 s of a
# 90 s budget, one shared directory FAILS 0/32 at 90 s, four legs alternating
# on one build).  Chain 129 measured, at P=32 into one shared directory:
#
#   mean ms per create:  193  169  550  1558  2151   for F = 8 16 32 64 128
#
# and killed both standing readings -- a one-time admission cost must FALL when
# divided by more operations, and the per-index series has no periodicity, so
# it is not a batching quantum either.
#
# TWO THINGS A GPT REVIEW OF THAT LADDER ESTABLISHED, BOTH OF WHICH THIS CHAIN
# EXISTS TO HANDLE.
#
# (1) THE LADDER IS CONFOUNDED WITH ELAPSED TIME.  The clients are CLOSED-LOOP,
#     so at most 32 creates are ever outstanding whatever F is; raising F
#     raises the DURATION of sustained contention, not the queue depth.  Chain
#     129 also ran its points in one fixed order, 8 -> 128, on a filesystem
#     that was never re-prepped between them.  So "cost rises with F" and "cost
#     rises with how long the test has been running" fit the same data.
#     THE FIX, and it is cheap: run the ladder FORWARD and then immediately
#     REVERSE on the same un-re-prepped filesystem.
#       - F drives it   => the F -> cost mapping REPEATS in the reverse pass
#                          (F=128 expensive, F=8 cheap, both times).
#       - time drives it => the mapping INVERTS: the reverse pass is most
#                          expensive at its FIRST point (F=128) only because it
#                          is late, and F=8 comes out expensive at the end.
#     Either way this is a result.  Note each create_scale_curve invocation
#     makes its own fresh stamped directory, so the DIRECTORY is not reused
#     across points -- only the filesystem and the DLM's accumulated state are,
#     which is exactly what the reverse pass tests.
#
# (2) COUNTING CREATES PER TENURE IS NOT ENOUGH ON ITS OWN.  i_dlm_epoch moves
#     on every grant loss, including one this same node immediately reverses,
#     so a tenure of 1 can mean either "the directory went right round the
#     fleet between these two creates" or "the grant churned and never left".
#     0.69.2 therefore reports gap_ms beside the count: the wait between the
#     last create of the old tenure and the first of the new.  Near a full
#     rotation (~1.5 s at 32 nodes) means a real rotation; a millisecond or two
#     means the cost is not queueing at all and the search moves to the holder
#     drain / handoff path.
#
# THE HYPOTHESIS AND ITS FALSIFIERS, written before the run.
#   H1 TENURE COLLAPSE: creates-per-tenure K falls toward 1 as F grows, gap_ms
#      is of rotation size, and ms/create ~ rotation / K.
#   FALSIFIER A: K flat while cost rises  => handovers are getting SLOWER, not
#      more frequent.  H1 is dead, not refined; the endsrc histogram below
#      names which release path ended the tenures and that is where to look.
#   FALSIFIER B: K small but gap_ms tiny  => the epoch is churning under
#      retained control.  The wait is not for the directory, and dlk_ms is
#      being spent inside the holder rather than in the queue.
#   FALSIFIER C: no tenure lines at an F  => one tenure covered that whole
#      point, K = F, H1 refuted there outright.
#   FALSIFIER D: the reverse pass inverts the mapping => F is not the driver
#      and the whole ladder, including chain 129's, measures elapsed time.
#
# WHY MEDIANS AND n, NOT MEANS.  The acquire-wait distribution is bimodal --
# dlk_ms p50 = 1 ms against p90 = 2133 ms over 3144 samples -- so a mean is a
# mixture and moves for two entirely different reasons.  Every figure below is
# reported with its sample count and its p50/p90.
#
# derived time budgets, derived.  build 338 s measured (chain 128) -> 600.  prep
# 88-112 s measured -> 300.  Per F point, chain 129's derivation: 60 s fixed
# (ssh fan-out x 2 arms + admission) + 1.6 s per file, that per-file figure
# being the cost of the PATHOLOGICAL outcome being hunted (one full rotation
# per create) rather than padding -> 73, 111, 265 s for F = 8, 32, 128; two
# passes = 898 s.  Sweeps 6 x ~40 s -> 240.  Total ~2050 s.  A timeout at a
# point is a RESULT -- rotation-per-create -- recorded and never widened.
#
# Usage:  setsid nohup bash tests/sess483_chain132_dirtenure.sh s483c &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s483c}
GATE=${GATE:-tests/evidence/sess482_chain130_affine_audit_s483b.log}
LOG=tests/evidence/sess483_chain132_dirtenure_$LABEL.log
EV=tests/evidence/sess483_dirtenure_$LABEL
NNODES=${NNODES:-32}
FWD=${FWD:-8 32 128}
REV=${REV:-128 32 8}
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"

gate_dl=$(( $(date +%s) + 21600 ))
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$gate_dl" ]; then
        echo "=== sess483 chain132 ABORT: gate $GATE never reached DONE within 6 h ===" >> "$LOG"
        echo "DONE $(date -u +%FT%TZ)" >> "$LOG"
        exit 1
    fi
    sleep 30
done

# One F point: run the ladder arm, account for its samples, sweep the tenure
# lines, analyse them.  $1 = pass name (fwd|rev), $2 = F.
point() {
    local PASS=$1 F=$2 guard rc wall arm want got SINCE T0
    guard=$(( 60 + F * 16 / 10 ))
    echo "--- pass=$PASS F=$F files/node, P=32, guard=${guard}s ---"
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
    T0=$(date +%s)
    CSC_OUT=$EV/${PASS}_F$F LADDER=32 timeout "$guard" \
        bash tests/create_scale_curve.sh "$F" caw > "$EV/csc_${PASS}_F$F.out" 2>&1
    rc=$?
    wall=$(( $(date +%s) - T0 ))
    if [ "$rc" = 124 ]; then
        echo "  STAGE $PASS F$F TIMEOUT at ${wall}s — a RESULT: per-node cost exceeded 1.6 s/file, i.e. rotation-per-create territory. Samples below are CENSORED and the slowest are the ones missing, so any mean from them is biased LOW."
    else
        echo "  STAGE $PASS F$F rc=$rc wall=${wall}s"
    fi

    for arm in private shared; do
        want=$(( NNODES * F ))
        got=$(cat "$EV/${PASS}_F$F/${arm}_P32"/n*.txt 2>/dev/null | grep -ac '^OP ')
        got=${got:-0}
        if [ "$got" -eq 0 ]; then
            echo "  $PASS F=$F $arm samples=0 of $want — THIS ARM MEASURED NOTHING AND MUST NOT BE CITED"
        elif [ "$got" -ne "$want" ]; then
            echo "  $PASS F=$F $arm samples=$got of $want (CENSORED — the missing ones are the slowest still in flight; quote any figure as a lower bound)"
        else
            echo "  $PASS F=$F $arm samples=$got of $want"
        fi
    done

    # Per-op cost, shared arm, as p50/p90 with n — never a bare mean.
    python3 - "$EV/${PASS}_F$F/shared_P32" "$PASS" "$F" <<'PY' | tee -a "$EV/summary.txt"
import glob, os, sys
d, PASS, F = sys.argv[1], sys.argv[2], sys.argv[3]
ops = []
# The sample line is "OP <op index> <duration ms>" — THREE fields, and the
# duration is the THIRD.  This parse is copied verbatim from the producer,
# tests/create_scale_curve.sh, deliberately: an earlier version here took the
# first numeric field after OP and silently reported the op INDEX as the
# duration.  It was caught only because p50=5/max=8 at F=8 is exactly the index
# range, which is luck, not a check.  Never write a second parser for someone
# else's format when the first one is three lines away.
for p in glob.glob(os.path.join(d, "n*.txt")):
    for ln in open(p, errors="replace"):
        f = ln.split()
        if len(f) == 3 and f[0] == "OP":
            try:
                ops.append(float(f[2]))
            except ValueError:
                pass
if not ops:
    print("  %s F=%s shared: no parsable OP samples" % (PASS, F)); sys.exit(0)
ops.sort()
n = len(ops)
def q(f):
    return ops[min(n - 1, int(n * f))]
print("  %s F=%-4s shared per-create ms: n=%d p50=%.0f p90=%.0f p99=%.0f max=%.0f mean=%.0f"
      % (PASS, F, n, q(.5), q(.9), q(.99), ops[-1], sum(ops) / n))
print("        under 30 ms (a retained grant): %.1f%%   over 1000 ms (a rotation or worse): %.1f%%"
      % (100.0 * sum(1 for o in ops if o < 30) / n,
         100.0 * sum(1 for o in ops if o > 1000) / n))
PY

    # The tenure lines for this point.
    local D="$EV/tenure_${PASS}_F$F" i
    mkdir -p "$D"
    for i in $(seq 1 "$NNODES"); do
        ( timeout 90 "$SSH" "test$i" \
            "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -a 'P483-DIRTENURE'" \
            > "$D/test$i.txt" 2>/dev/null ) &
    done
    wait
    local nlines nrep
    nlines=$(cat "$D"/test*.txt 2>/dev/null | grep -ac 'P483-DIRTENURE'); nlines=${nlines:-0}
    nrep=$(grep -alc 'P483-DIRTENURE' "$D"/test*.txt 2>/dev/null | wc -l)
    echo "  $PASS F=$F tenure lines=$nlines from $nrep/$NNODES node(s)"
    if [ "$nlines" -eq 0 ]; then
        echo "  $PASS F=$F READING: no tenure ENDED at this point. The probe is in the"
        echo "        shipped module (gate 1) on the frozen build (gate 2), so this means"
        echo "        the grant epoch never moved: one tenure covered the whole point,"
        echo "        K = F = $F. FALSIFIER C — H1 is refuted at this F."
        return 0
    fi
    cat "$D"/test*.txt 2>/dev/null | grep -a 'P483-DIRTENURE' > "$EV/tenure_${PASS}_F$F.all"
    python3 - "$EV/tenure_${PASS}_F$F.all" "$PASS" "$F" <<'PY' | tee -a "$EV/summary.txt"
import re, sys
path, PASS, F = sys.argv[1], sys.argv[2], sys.argv[3]
cre, gap, wall, per = [], [], [], {}
for ln in open(path, errors="replace"):
    m = re.search(r"creates=(\d+) wall_ms=(\d+) mean_ms=(\d+) gap_ms=(\d+).*?endsrc=(\d+:\d+)", ln)
    if not m:
        continue
    cre.append(int(m.group(1))); wall.append(int(m.group(2)))
    gap.append(int(m.group(4)))
    per.setdefault(m.group(5), []).append(int(m.group(1)))
if not cre:
    print("  %s F=%s tenure lines present but none parsed — the probe format changed; fix the parser before reading anything" % (PASS, F))
    sys.exit(0)
n = len(cre)
def qs(v, f):
    w = sorted(v); return w[min(len(w) - 1, int(len(w) * f))]
print("  %s F=%-4s tenures n=%d  creates/tenure p50=%d p90=%d max=%d  K=1: %.0f%%"
      % (PASS, F, n, qs(cre, .5), qs(cre, .9), max(cre),
         100.0 * cre.count(1) / n))
print("        gap_ms between tenures p50=%d p90=%d max=%d   under 30 ms (grant churn, never left): %.0f%%   over 1000 ms (a real rotation): %.0f%%"
      % (qs(gap, .5), qs(gap, .9), max(gap),
         100.0 * sum(1 for g in gap if g < 30) / n,
         100.0 * sum(1 for g in gap if g > 1000) / n))
print("        creates covered=%d  ms inside tenures=%d" % (sum(cre), sum(wall)))
top = sorted(per.items(), key=lambda kv: -len(kv[1]))[:4]
print("        tenures ended by (i_dlm_epoch_src __LINE__ -> count, median creates): "
      + "  ".join("%s->%d/%d" % (s, len(v), sorted(v)[len(v) // 2]) for s, v in top))
PY
    return 0
}

{
  echo "=== sess483 chain132 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  echo "STAGE gate cleared: $GATE"
  # This run's numbers only.  The LOG is appended to across relaunches (the
  # gate downstream keys on its DONE line, so the filename cannot change), and
  # a verdict that grepped the LOG would mix this run's figures with an earlier
  # one's -- which already happened once this session, with a buggy parser's
  # output still in the file.
  : > "$EV/summary.txt"

  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  t0=$(date +%s)
  timeout 600 make modules > "$EV/build.log" 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - t0 ))s"
  [ "$brc" = 0 ] || { echo "ABORT: build rc=$brc — $(grep -a -i 'error' "$EV/build.log" | head -5 | tr '\n' ' ')"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # GATE 1: probe present, and gap_ms present — an older build would parse as
  # "no gap field" and every gap statistic below would silently read zero.
  np=$(strings mxfs.ko 2>/dev/null | grep -ac 'P483-DIRTENURE')
  ng=$(strings mxfs.ko 2>/dev/null | grep -ac 'gap_ms=')
  echo "STAGE instrument_present dirtenure=$np gap_field=$ng"
  if [ "${np:-0}" -lt 1 ] || [ "${ng:-0}" -lt 1 ]; then
      echo "ABORT: mxfs.ko lacks P483-DIRTENURE or its gap_ms field. Build 0.69.2 or later."
      echo "       Without the probe, 'no tenure lines' would mean absence rather than"
      echo "       'the epoch never moved' — opposite conclusions. Without gap_ms, a"
      echo "       tenure of 1 cannot be told from grant churn under retained control."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  FREEZE=tests/evidence/sess483_chain132_frozen_$(tr -d '.\n' < VERSION)
  mkdir -p "$FREEZE" && cp mxfs.ko "$FREEZE/mxfs.ko"
  echo "STAGE identity sv=$SV freeze=$FREEZE"

  timeout 300 ./run.sh "$NNODES" caw prep_cluster; prc=$?
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # GATE 2: whole fleet on the frozen build, or the counts mix builds.
  : > "$EV/fleet_sv.txt"
  for i in $(seq 1 "$NNODES"); do
      ( s=$(timeout 30 "$SSH" "test$i" "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null | tr -dc 'A-F0-9')
        echo "test$i ${s:-NONE}" > "$EV/.sv.test$i" ) &
  done
  wait
  for i in $(seq 1 "$NNODES"); do cat "$EV/.sv.test$i" >> "$EV/fleet_sv.txt" 2>/dev/null; done
  match=$(grep -c " $SV\$" "$EV/fleet_sv.txt")
  echo "STAGE fleet_identity match=$match/$NNODES sv=$SV"
  if [ "$match" -ne "$NNODES" ]; then
      echo "ABORT: only $match of $NNODES nodes run the frozen build:"
      grep -v " $SV\$" "$EV/fleet_sv.txt" | head -8 | sed 's/^/    /'
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  echo "===== PASS 1 (forward: $FWD) $(date -u +%FT%TZ) ====="
  for F in $FWD; do point fwd "$F"; done
  echo "===== PASS 2 (reverse: $REV) — SAME filesystem, deliberately NOT re-prepped:"
  echo "      the point is to keep every bit of accumulated state so that if cost"
  echo "      tracks elapsed time rather than F, this pass inverts the mapping."
  echo "      $(date -u +%FT%TZ) ====="
  for F in $REV; do point rev "$F"; done

  echo "--- VERDICT ---"
  echo "  FIRST, the confound. Compare the shared p50 at each F between the two passes:"
  grep -a 'shared per-create ms' "$EV/summary.txt" 2>/dev/null | sed 's/^/    /'
  echo "    same F -> same cost in both passes  => F IS the driver; chain 129's ladder stands."
  echo "    mapping inverted (cost tracks position in the run, not F) => FALSIFIER D:"
  echo "      the ladder measures ELAPSED TIME and chain 129's headline numbers, and the"
  echo "      'rises with F' claim in D-32NODE-SHARED-DIR-CREATE-PACE, must be withdrawn."
  echo "  SECOND, the mechanism, read only if F survived the first test:"
  grep -a 'tenures n=' "$EV/summary.txt" 2>/dev/null | sed 's/^/    /'
  grep -a 'gap_ms between tenures' "$EV/summary.txt" 2>/dev/null | sed 's/^/    /'
  echo "    K falling toward 1 AND gap_ms of rotation size => H1 CONFIRMED (tenure collapse)."
  echo "    K flat while cost rises                        => FALSIFIER A: handovers slower,"
  echo "      not more frequent; the endsrc histogram names the releasing path."
  echo "    K small but gap_ms tiny                        => FALSIFIER B: grant churn under"
  echo "      retained control; the wait is inside the holder, not in the queue."
  echo "  THIRD, the standing discrepancy to settle: crash_consistency's own trace implies"
  echo "  K about 12.5 for ~100 creates per node. If K here is near 1 at comparable F, the"
  echo "  two workloads are not measuring the same thing and neither may be cited for the"
  echo "  other until that is explained."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
