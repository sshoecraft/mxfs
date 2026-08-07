#!/bin/bash
# sustained_load — the filesystem still meets its time budget AFTER the rest of
# the suite has run on the same mount.  It must not degrade with use.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess21)
#   Measured three times, on two builds: a workload that completes comfortably
#   on a FRESH prep cannot finish inside its budget once the same mount has
#   been used by the preceding tests.
#
#     condition          test                fresh prep    after prior work
#     32/caw @0.11.163   rsync_paired        PASS 14 s     0/32, hung at 60 s
#     32/caw @0.11.163   crash_consistency   PASS 32/32    31/32
#     32/caw @0.11.167   crash_consistency   PASS 57 s     0/32, hung at 90 s
#
#   Running the IDENTICAL 13-test sequence on a fresh prep passes every time,
#   so this is NOT test ordering — it is accumulated mount state.  Every other
#   criterion runs early enough, or re-preps often enough, to miss it, which is
#   exactly why the board stayed green through all three occurrences.
#
#   Under RULE 0 this is disqualifying on its own: a clustered filesystem that
#   must be remounted to stay inside its performance budget is not shippable.
#   Suspects (untested): DLM lock-table growth, AG grant-cache churn, inode
#   cache / AIL growth, CAW slot-table pressure, per-AG counters that never
#   reset.
#
# HOW IT JUDGES
#   It runs LAST (group P8), so "after prior work" is literally true, and it
#   deliberately does NOT re-prep.  The workload is fixed and metadata-heavy
#   (metadata is what degrades — DLM/AG/inode-cache state), and small enough
#   that a healthy cluster finishes it in a few seconds.  The runner's own RULE
#   0 budget mechanism is the threshold: elapsed > budget_s flips PASS to FAIL
#   even with zero errors.  So a degraded mount fails by taking too long, which
#   is precisely the symptom observed.
SUITE_TEST_NAME=sustained_load
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
# N-INVARIANT total work, same treatment as dlm_fairness/tcp_dlm_scaling: the
# semantic is "is the mount still responsive", which does not need more ops at
# more nodes.  ~640 create/stat/remove triples split across nodes, floor 20.
OPS=$(( 640 / T ))
[ "$OPS" -lt 20 ] && OPS=20
[ "$OPS" -gt 60 ] && OPS=60

BASE="$MNT/.sustained_load"

# ccloop c7ee71c6 sess28 — PHASE TIMERS.  This criterion used to time ONLY the
# op loop, and that hid where its budget actually goes: measured 32/caw on an
# aged mount, it reported wall=3978ms per_op=198ms and still consumed the full
# 180 s budget with 4 of 32 nodes never producing a terminal record.  20 ops at
# ~198 ms is ~4 s of operations against a 180 s wall, so ~97% of the elapsed
# time was outside the only thing being measured — and the number the cell
# printed made the mount look nearly healthy while it was timing out.
#
# Time every phase, and report the phase sum as `twall`, so a future reader can
# see WHICH phase degrades rather than inferring it.  Pure instrumentation: no
# change to the workload or the verdict.
p0=$(( $(date +%s%3N) ))
pa=$p0; pb=$p0
if [ "$R" = 1 ]; then
    rm -rf "$BASE" 2>/dev/null
    pa=$(( $(date +%s%3N) ))
    mkdir -p "$BASE" 2>/dev/null
    pb=$(( $(date +%s%3N) ))
    sync
fi
p1=$(( $(date +%s%3N) ))
ck "sl base ready" coord_barrier "sl_base"
p2=$(( $(date +%s%3N) ))

D="$BASE/n$R"
mkdir -p "$D" 2>/dev/null
p3=$(( $(date +%s%3N) ))

setup_ms=$(( p1 - p0 ))     # rank-1 teardown+recreate of the shared base (0 elsewhere)
rmrf_ms=$(( pa - p0 ))      # ...of which: removing the PREVIOUS run's tree
mkb_ms=$(( pb - pa ))       # ...of which: re-creating the shared base dir
syn_ms=$(( p1 - pb ))       # ...of which: the sync
bar1_ms=$(( p2 - p1 ))      # waiting for the slowest node to reach sl_base
mkd_ms=$(( p3 - p2 ))       # this node's own per-node dir create

# ccloop c7ee71c6 sess28 — PER-OP PROGRESS TO /dev/kmsg.
#
# A node that blows the budget produces NO terminal record at all
# (states:NO_TERMINAL_RECORD), so everything it was doing is invisible: the
# aggregate line comes only from the nodes that finished, and it therefore
# describes the healthy majority.  That is how this criterion reported
# per_op=198ms while 4 of 32 nodes were stuck.
#
# Emit each slow op to the kernel ring AS IT HAPPENS, so a node that never
# returns still leaves an attributable trail.  Threshold-gated so a healthy run
# writes ~nothing (measured healthy per-op is 4-6 ms), plus one heartbeat every
# 5 ops so a stall is bounded even if the slow call never completes.
SL_SLOW_MS=200
sl_mark() { echo "MXFS_SL r=$R $*" > /dev/kmsg 2>/dev/null; }
sl_op() {   # <phase> <k> <cmd...>
    local ph="$1" k="$2"; shift 2
    local a b d
    a=$(date +%s%3N)
    "$@" 2>/dev/null || errs=$((errs + 1))
    b=$(date +%s%3N); d=$((b - a))
    [ "$d" -ge "$SL_SLOW_MS" ] && sl_mark "SLOW phase=$ph k=$k ms=$d"
    return 0
}

start_ms=$(( $(date +%s%3N) ))
errs=0
sl_mark "BEGIN ops=$OPS"
for k in $(seq 1 "$OPS"); do
    sl_op mkdir "$k" mkdir "$D/d$k"
    a=$(date +%s%3N); echo x > "$D/d$k/f" 2>/dev/null || errs=$((errs + 1))
    b=$(date +%s%3N); [ $((b - a)) -ge "$SL_SLOW_MS" ] && sl_mark "SLOW phase=write k=$k ms=$((b - a))"
    [ -s "$D/d$k/f" ]                 || errs=$((errs + 1))
    [ $((k % 5)) -eq 0 ] && sl_mark "HB create k=$k elapsed=$(( $(date +%s%3N) - start_ms ))"
done
sl_mark "CREATED elapsed=$(( $(date +%s%3N) - start_ms ))"
sl_op readdir 0 ls "$D"
sl_mark "READDIR elapsed=$(( $(date +%s%3N) - start_ms ))"
for k in $(seq 1 "$OPS"); do
    rm -f "$D/d$k/f" 2>/dev/null
    sl_op rmdir "$k" rmdir "$D/d$k"
    [ $((k % 5)) -eq 0 ] && sl_mark "HB remove k=$k elapsed=$(( $(date +%s%3N) - start_ms ))"
done
sl_mark "REMOVED elapsed=$(( $(date +%s%3N) - start_ms ))"
a=$(date +%s%3N); sync; b=$(date +%s%3N)
[ $((b - a)) -ge "$SL_SLOW_MS" ] && sl_mark "SLOW phase=sync ms=$((b - a))"
sl_mark "SYNCED elapsed=$(( $(date +%s%3N) - start_ms ))"
end_ms=$(( $(date +%s%3N) ))
wall_ms=$(( end_ms - start_ms ))

p4=$(( $(date +%s%3N) ))
ck "sl done" coord_barrier "sl_done"
p5=$(( $(date +%s%3N) ))
bar2_ms=$(( p5 - p4 ))      # waiting for the slowest node to finish its ops
twall_ms=$(( p5 - p0 ))     # everything this criterion actually spends

# Per-op cost is the degradation-independent figure: it lets a human compare
# a used mount against a fresh one directly, even across node counts.
per_op_ms=$(( wall_ms / (OPS > 0 ? OPS : 1) ))

st=PASS; reason=""
[ "$errs" -gt 0 ] && { st=FAIL; reason="$errs metadata op failures on a used mount"; }
echo "RESULT: $st | test=sustained_load | nodes=$T | measured=ops=$OPS wall=${wall_ms}ms per_op=${per_op_ms}ms setup=${setup_ms}ms rmrf=${rmrf_ms}ms mkb=${mkb_ms}ms syn=${syn_ms}ms bar1=${bar1_ms}ms mkd=${mkd_ms}ms bar2=${bar2_ms}ms twall=${twall_ms}ms errs=$errs | reason=$reason"
[ "$st" = PASS ]
