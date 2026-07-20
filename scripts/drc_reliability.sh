#!/bin/bash
# drc_reliability.sh — run dir_reuse_coherency at a given node count N times,
# resetting between each, reporting PASS/FAIL + which shutdown face (if any).
# Usage: scripts/drc_reliability.sh <N> <RUNS> [modargs]
#   modargs: extra MXFS_EXTRA_MODARGS (default: none = bare defaults)
set -u
cd /src/mxfs
N="${1:?usage: drc_reliability.sh <N> <RUNS> [modargs]}"
RUNS="${2:?}"
MODARGS="${3:-}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
pass=0; fail=0
for i in $(seq 1 "$RUNS"); do
  timeout 260 scripts/ccloop_reset.sh "$N" >/dev/null 2>&1
  if [ -n "$MODARGS" ]; then
    r=$(MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh "$N" tcp dir_reuse_coherency 2>&1 | grep -E "  (PASS|FAIL)  dir")
  else
    r=$(./run.sh "$N" tcp dir_reuse_coherency 2>&1 | grep -E "  (PASS|FAIL)  dir")
  fi
  # collect shutdown faces per node
  faces=""
  for k in $(seq 1 "$N"); do
    n="test$k"
    line=$(timeout 15 "$SSH" "$n" "$PF" 'dmesg 2>/dev/null | grep -E "Shutting down|P-DIFREE-DBL|P-DIFREE-CORRUPT|xfs_ifree returned|dir_create_child err|imap_to_bp failed" | tail -3' 2>&1 | grep -vE "^Warning|^Unauth|^If you")
    [ -n "$line" ] && faces="$faces [$n: $(echo "$line" | tr '\n' ';' | cut -c1-260)]"
  done
  echo "RUN $i: ${r:-NO_RESULT}${faces:+ FACES:$faces}"
  echo "$r" | grep -q PASS && pass=$((pass+1)) || fail=$((fail+1))
done
echo "TOTAL N=$N pass=$pass fail=$fail modargs='${MODARGS:-<defaults>}'"
echo "DRCDONE"
