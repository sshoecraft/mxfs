#!/bin/bash
# ds_probe.sh — per-phase latency breakdown for the dlm_scaling create/stat/unlink
# op, to locate where the ~22ms/op at 32 nodes goes (RULE 4 instrumentation).
#
# Runs the SAME primitive as tests/suite/dlm_scaling.sh (`: > f; stat f; rm -f f`)
# in a FRESH private subdir, but times each phase separately and reports averages.
# Run on ONE node (idle cluster) to get the uncontended per-op floor, or launch on
# all N (via a for-loop over nodes) to measure per-op cost under concurrent load.
#
# Usage: ds_probe.sh <mnt> <ops> [tag]
set -u
MNT="${1:-/mnt/shared}"
OPS="${2:-500}"
TAG="${3:-probe}"
D="$MNT/.ds_probe/${TAG}_$$"
rm -rf "$D" 2>/dev/null
mkdir -p "$D" || { echo "PROBE-FAIL: mkdir $D"; exit 1; }

# Warm: one op so the parent dir block + AG meta are cached (matches steady state).
: > "$D/warm"; rm -f "$D/warm"

cre=0; sta=0; unl=0
t0=$(date +%s.%N)
for i in $(seq 1 "$OPS"); do
    f="$D/f$i"
    a=$(date +%s.%N); : > "$f";                b=$(date +%s.%N)
    stat "$f" >/dev/null 2>&1;                 c=$(date +%s.%N)
    rm -f "$f";                                d=$(date +%s.%N)
    cre=$(awk "BEGIN{print $cre+($b-$a)}")
    sta=$(awk "BEGIN{print $sta+($c-$b)}")
    unl=$(awk "BEGIN{print $unl+($d-$c)}")
done
t1=$(date +%s.%N)
rm -rf "$D" 2>/dev/null

awk -v ops="$OPS" -v tot="$(awk "BEGIN{print $t1-$t0}")" -v cre="$cre" -v sta="$sta" -v unl="$unl" -v tag="$TAG" \
 'BEGIN{
    printf "PROBE tag=%s ops=%d wall=%.2fs rate=%.1f/s op_avg=%.2fms  create=%.2fms stat=%.2fms unlink=%.2fms\n",
      tag, ops, tot, ops/tot, 1000*tot/ops, 1000*cre/ops, 1000*sta/ops, 1000*unl/ops;
 }'
