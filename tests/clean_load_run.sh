#!/bin/bash
# tests/clean_load_run.sh — run criteria only inside a genuinely clean host-load
# window (sess46: the dev host's external game-server bursts cycle load
# 17→88 every 20-40 min; a single pre-run load check races the next burst and
# poisons pace-sensitive rows into NO_TERMINAL/rounds-short FAILs that read
# like fs defects).
#
# Loops: wait for 1-min load < GATE, run the criteria, then read back the
# hostload= stamp run.sh recorded for each row.  A run whose EVERY stamp is
# < CLEAN counts as the verdict (PASS or FAIL — a clean-window FAIL is REAL
# and must be investigated, never retried away).  A run with any stamp >=
# CLEAN was burst-contaminated: ignored, retried.  Bounded attempts.
#
# usage: clean_load_run.sh <nodes> <transport> <test...>
#   env: GATE (default 16) CLEAN (default 22) TRIES (default 8)
set -u
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
N="$1"; TR="$2"; shift 2
GATE="${GATE:-16}"; CLEAN="${CLEAN:-22}"; TRIES="${TRIES:-8}"

for try in $(seq 1 "$TRIES"); do
    while :; do
        L=$(cut -d' ' -f1 /proc/loadavg | cut -d. -f1)
        [ "$L" -lt "$GATE" ] && break
        sleep 20
    done
    echo "== attempt $try (load $(cut -d' ' -f1-3 /proc/loadavg)) =="
    OUT=$(timeout 300 ./run.sh "$N" "$TR" "$@" 2>&1 | grep -E "  PASS|  FAIL")
    echo "$OUT"
    # every row's hostload stamp must be < CLEAN for the run to count
    STAMPS=$(echo "$OUT" | grep -oE 'hostload=[0-9]+' | cut -d= -f2)
    DIRTY=0
    for s in $STAMPS; do [ "$s" -ge "$CLEAN" ] && DIRTY=1; done
    [ -z "$STAMPS" ] && DIRTY=1
    if [ "$DIRTY" -eq 0 ]; then
        echo "== CLEAN-WINDOW VERDICT (attempt $try) =="
        echo "$OUT" | grep -q "  FAIL" && exit 1 || exit 0
    fi
    echo "   (burst-contaminated — retrying)"
done
echo "== NO CLEAN WINDOW in $TRIES attempts =="
exit 2
