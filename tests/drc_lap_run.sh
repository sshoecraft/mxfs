#!/bin/bash
# drc_lap_run.sh — one instrumented fresh->plateau dir_reuse lap (sess39).
# Runs 3 consecutive dir_reuse_coherency tests at 32/caw with
# drc_lap_probe.sh snapshots around each, so per-run /proc/fs/mxfs/stat
# deltas (log + push_ail lines), grant-head bytes, LSNs, PSI and steal can
# be diffed between the fresh run and the plateau runs.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
LOG="$REPO/tests/logs/sess39_lap/lap_results.txt"
mkdir -p "$REPO/tests/logs/sess39_lap"
snap() { "$REPO/tests/drc_lap_probe.sh" "$1" >/dev/null; echo "$(date +%s) snap $1" >> "$LOG"; }
run1() {
    local tag="$1"
    echo "$(date +%s) start $tag" >> "$LOG"
    timeout 165 ./run.sh 32 caw dir_reuse_coherency 2>&1 | grep -E "^  (PASS|FAIL)" | tail -1 | tee -a "$LOG"
    echo "$(date +%s) end $tag" >> "$LOG"
}
snap fresh_pre
run1 fresh
snap fresh_post
run1 p1
snap p1_post
run1 p2
snap p2_post
echo done
