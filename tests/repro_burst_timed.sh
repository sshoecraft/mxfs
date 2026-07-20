#!/bin/bash
# repro_burst_timed.sh — run ON a node.  Concurrent same-dir create burst with
# PER-CREATE latency logging; any create taking > THRESH ms is logged with the
# clock so a peer-side stack sampler can correlate.  Also dumps own /proc/self
# isn't useful (we ARE the creator) so we fork the create and watch it.
# Simpler: just time each create inline and print slow ones + a running max.
set -u
source "$(dirname -- "${BASH_SOURCE[0]}")/suite/coord.sh"
R="${MXFS_RANK:?}"; T="${MXFS_NODES:?}"; MNT="${1:-/mnt/shared}"
D="$MNT/.burst"; FPN="${FPN:-100}"; THRESH_MS="${THRESH_MS:-500}"
[ "$R" = 1 ] && { rm -rf "$D"; mkdir -p "$D"; sync; }
coord_barrier "ready" || exit 1
maxms=0; slown=0; t0=$(date +%s.%N)
for i in $(seq 1 "$FPN"); do
  a=$(date +%s.%N)
  : > "$D/n${R}_$i"
  b=$(date +%s.%N)
  ms=$(echo "($b-$a)*1000/1"|bc)
  [ "$ms" -gt "$maxms" ] && maxms=$ms
  if [ "$ms" -gt "$THRESH_MS" ]; then
    slown=$((slown+1))
    echo "R$R SLOW create #$i = ${ms}ms at $(date +%T.%3N)"
  fi
done
tot=$(echo "($(date +%s.%N)-$t0)*1000/1"|bc)
echo "R$R BURST done: total=${tot}ms maxcreate=${maxms}ms slow(>${THRESH_MS}ms)=$slown"
coord_barrier "done"
