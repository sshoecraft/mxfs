#!/bin/bash
# strong_consistency — agnostic multi-node sequential-consistency test.
#
# Writers (odd ranks) perform N ordered writes to a per-node counter file + a
# final value; readers (even ranks) verify the final value and last counter
# each writer committed are visible in order.  Ported from the months-old
# tests/cluster/test_sequential_consistency.sh into the agnostic + coord_barrier
# (MQTT, off-FS) suite format.  Runs on every node; run.sh aggregates (PASS iff
# all nodes pass).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.strong_consistency"
mkdir -p "$D" 2>/dev/null

ITER=20

# Role: single node does both; else odd=writer, even=reader.
if [ "$T" -eq 1 ]; then role=both
elif [ $((R % 2)) -eq 1 ]; then role=writer
else role=reader
fi

ck "sc barrier ready" coord_barrier "sc_ready"

if [ "$role" = writer ] || [ "$role" = both ]; then
    for i in $(seq 1 "$ITER"); do
        echo "node${R}_seq${i}" > "$D/node${R}_counter"
        sync
    done
    echo "$ITER" > "$D/node${R}_final"
    sync
fi

ck "sc barrier write-done" coord_barrier "sc_write_done"

if [ "$role" = reader ] || [ "$role" = both ]; then
    for w in $(seq 1 "$T"); do
        if [ $((w % 2)) -eq 1 ] || [ "$T" -eq 1 ]; then
            ck   "sc node${w}_final exists"  test -f "$D/node${w}_final"
            ckeq "sc node${w} final value"   "$ITER" "$(cat "$D/node${w}_final" 2>/dev/null)"
            ck   "sc node${w}_counter exists" test -f "$D/node${w}_counter"
            ckeq "sc node${w} last counter"  "node${w}_seq${ITER}" "$(cat "$D/node${w}_counter" 2>/dev/null)"
        fi
    done
fi

ck "sc barrier verify" coord_barrier "sc_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
