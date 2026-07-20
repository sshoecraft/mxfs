#!/bin/bash
# coord_bar_watch.sh — timestamp every MQTT coordination message during a
# coordinated suite test (run.sh run_coord).  Non-invasive per-phase timing:
# each node publishes a retained marker at every coord_barrier, so recording
# live arrivals gives per-rank per-phase wall clocks without touching the
# test script or the FS under test.
#
# Usage:  coord_bar_watch.sh <outfile> [topic_filter]
#   outfile       where to append "epoch.ms topic payload" lines
#   topic_filter  default 'mxfs/coord/#' (all runs/tests)
#
# -R suppresses stale retained messages (prior runs); only live arrivals are
# recorded, so line time == the moment that rank reached that barrier.
# Analyze with: awk of bar/<tag>/r/<rank> lines — per-tag min/max arrival =
# phase skew; consecutive-tag deltas per rank = that node's phase wall.
BROKER="${MXFS_COORD_BROKER:-192.168.1.149}"
OUT="${1:?usage: coord_bar_watch.sh <outfile> [topic_filter]}"
FILTER="${2:-mxfs/coord/#}"
mosquitto_sub -h "$BROKER" -t "$FILTER" -v -q 1 -R 2>/dev/null | \
while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%s.%3N)" "$line"
done >> "$OUT"
