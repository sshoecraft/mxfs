#!/bin/bash
# scaling_curve — aggregate FS write throughput across N nodes.
#
# Each node writes an independent data file (its own AG via node affinity) with
# O_DIRECT for a fixed payload, measures its own MiB/s, and publishes it.  The
# aggregate cluster bandwidth (sum of per-node rates) is the scaling number.
# PASS iff every node completes its write within the time budget AND sustains a
# per-node floor (no node starved / collapsed) AND the aggregate exceeds the
# fastest single node (positive scaling: 2 independent writers must beat 1).
#
# RULE 0: budget derived — PAYLOAD at a conservative floor rate must finish well
# inside WINDOW; a node that can't is a scaling FAIL, not a widen.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.scaling_curve"
mkdir -p "$D" 2>/dev/null

PAYLOAD_MB="${SCALING_PAYLOAD_MB:-256}"
WINDOW="${SCALING_WINDOW:-60}"
FLOOR_MBPS="${SCALING_FLOOR_MBPS:-5}"   # per-node minimum (very conservative)

ck "sccurve barrier ready" coord_barrier "sc_ready"

f="$D/node${R}.dat"
t0=$(date +%s.%N)
dd if=/dev/zero of="$f" bs=1M count="$PAYLOAD_MB" oflag=direct conv=fsync 2>/dev/null
rc=$?
t1=$(date +%s.%N)
elapsed=$(awk "BEGIN{e=$t1-$t0; print (e>0)?e:0.001}")
rate=$(awk "BEGIN{printf \"%d\", $PAYLOAD_MB/$elapsed}")

ckeq "sccurve node${R} write ok" 0 "$rc"
ck   "sccurve node${R} within window" awk "BEGIN{exit !($elapsed <= $WINDOW)}"
ck   "sccurve node${R} rate>=floor" awk "BEGIN{exit !($rate >= $FLOOR_MBPS)}"

coord_put "rate_${R}" "$rate"
ck "sccurve barrier wrote" coord_barrier "sc_wrote"

# Rank 1 aggregates: sum rates, assert positive scaling (aggregate > max single).
if [ "$R" = 1 ]; then
    agg=0; maxr=0
    for n in $(seq 1 "$T"); do
        r=$(coord_get "rate_${n}" 30 2>/dev/null); r=${r:-0}
        agg=$((agg + r)); [ "$r" -gt "$maxr" ] && maxr="$r"
    done
    echo "SCALING: nodes=$T aggregate_MBps=$agg max_single=$maxr" >&2
    # "positive scaling" (aggregate beats the fastest single node) is only a
    # meaningful claim with 2+ writers -- at T=1 aggregate==max_single by
    # construction (one node vs itself), so the check is mathematically
    # always-false, not a real signal. Skip it there, same as
    # strong_consistency's existing T==1 special case.
    [ "$T" -gt 1 ] && ck "sccurve aggregate > max single" test "$agg" -gt "$maxr"
    ck "sccurve aggregate>=N*floor"     test "$agg" -ge "$((T * FLOOR_MBPS))"
fi

ck "sccurve barrier done" coord_barrier "sc_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
