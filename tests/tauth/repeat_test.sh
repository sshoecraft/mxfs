#!/bin/bash
# repeat_test.sh — run one tests/tauth binary N times in a row and count its
# failures, so an intermittent result has a rate instead of an anecdote.
#
# The binaries are timing-sensitive simulations (formation_test forms a
# 12-node cluster on a 40 ms ramp); one pass or one failure says little, and
# two binaries built from different sources can only be compared by rate.
# Runs are sequential: two at once would compete for the CPU and change the
# timing being measured.
#
# Usage: tests/tauth/repeat_test.sh <binary> [N] [label]
#        N defaults to 20; each run is bounded at RUN_S seconds (default 120)
# Output: one line per failed run (its rc and the first lines naming fails=),
#         then "<label>: F of N failed in S s".  Each run's whole output is
#         kept in OUT_DIR (default: a fresh mktemp -d), named in the last line.
set -u
bin=${1:?usage: repeat_test.sh <binary> [N] [label]}
n=${2:-20}
label=${3:-$(basename "$bin")}
RUN_S=${RUN_S:-120}
OUT_DIR=${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/repeat_test.XXXXXX")}
cd "$(dirname -- "${BASH_SOURCE[0]}")" || exit 2
[ -x "$bin" ] || { echo "repeat_test: $bin is not an executable here"; exit 2; }
t0=$(date +%s)
f=0
for i in $(seq 1 "$n"); do
    out="$OUT_DIR/run$i.out"
    timeout "$RUN_S" "./$(basename "$bin")" > "$out" 2>&1
    rc=$?
    if [ "$rc" != 0 ]; then
        f=$((f + 1))
        echo "run $i rc=$rc $(grep -a 'fails=[1-9]' "$out" | head -n 2 | cut -c1-160 | tr '\n' ' ')"
    fi
done
echo "$label: $f of $n failed in $(( $(date +%s) - t0 ))s (outputs in $OUT_DIR)"
