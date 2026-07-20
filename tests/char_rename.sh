#!/bin/bash
# Characterize concurrent-rename failure modes over R rounds without
# resetting between rounds (recreates the test dir each round).  After
# each round, checks every node for a forced shutdown / DLM timeout and
# reports: round result (dirent miss / empty / shutdown).
# Usage: tests/char_rename.sh [rounds] [N]
set -u
cd "$(dirname "$0")/.."
R=${1:-5}; N=${2:-20}
NODES="test1 test2 test3 test4"
PASS=/tmp/.mxfs_pass
SSH=tools/mxfs_sshpass.sh

for n in $NODES; do timeout 8 $SSH $n $PASS 'dmesg -C >/dev/null 2>&1' 2>/dev/null & done; wait

for r in $(seq 1 $R); do
  out=$(timeout 200 bash tests/repro_rename_concurrent.sh "$NODES" "$N" 2>&1 | grep -E 'sees writer|TOTAL_FAILS')
  fails=$(echo "$out" | grep -oE 'TOTAL_FAILS=[0-9]+' | grep -oE '[0-9]+' | sort -rn | head -1)
  empty=$(echo "$out" | grep -oE 'empty=[0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')
  miss=$(echo "$out" | grep -oE 'miss=[0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')
  sd=""
  for n in $NODES; do
    if timeout 8 $SSH $n $PASS 'dmesg | grep -qiE "Shutting down filesystem|lock unrecoverable|rc=-110"' 2>/dev/null; then sd="$sd $n"; fi
  done
  echo "round $r: max_fails=${fails:-?} empty=$empty miss=$miss shutdown=[${sd# }]"
  if [ -n "$sd" ]; then echo "  -> SHUTDOWN detected, stopping"; break; fi
done
