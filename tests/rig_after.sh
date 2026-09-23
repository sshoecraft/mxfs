#!/bin/bash
# rig_after.sh — run one rig command AFTER another relay-proof chain has
# written its 'DONE' line, so rig sequences can be queued from a session
# without polling and without two runs ever overlapping on the fleet.
#
#   setsid nohup tests/rig_after.sh <wait-log> <label> <max-wait-s> -- <cmd...>
#
# Appends to tests/evidence/rig_after_<label>.log; the command's stdout /
# stderr go there too.  budget: <max-wait-s> is the CALLER's derived bound
# on the upstream chain; the command itself must carry its own timeout.
WAIT=${1:?wait log}; LABEL=${2:?label}; MAXW=${3:?max wait s}
shift 3; [ "${1:-}" = "--" ] && shift
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/rig_after_${LABEL}.log
{
  echo "=== rig_after $LABEL start $(date -u +%FT%TZ) waiting on $WAIT (max ${MAXW}s): $* ==="
  w=0
  while ! grep -aq '^DONE ' "$WAIT" 2>/dev/null; do
    sleep 30; w=$((w+30))
    if [ "$w" -ge "$MAXW" ]; then echo "ABORT: $WAIT not DONE after ${w}s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  done
  echo "upstream DONE seen after ${w}s $(date -u +%FT%TZ)"
  "$@"
  echo "STAGE cmd rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
