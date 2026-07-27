#!/bin/bash
# abba_stack_capture.sh — watch both nodes for the inode-DLM ABBA (P36-RETRY
# storm) and capture kernel stacks of every blocked task while it persists.
# Dumps every ~8s for as long as the storm lasts, labeled by round, so the
# PERSISTENT holder's stack (not just the waiter's) is caught.
# Usage: N1=test1 N2=test2 MXFS_PASS=/tmp/.mxfs_pass scripts/abba_stack_capture.sh <outdir> [max_wait_s]
set -u
N1=${N1:-test1}
N2=${N2:-test2}
PASS=${MXFS_PASS:-/tmp/.mxfs_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
OUT=${1:?outdir}; MAXW=${2:-240}
mkdir -p "$OUT"

probe() { # node -> count of P36-RETRY in the last 40 dmesg lines
  "$SSH" "$1" "$PASS" "dmesg | tail -40 | grep -c 'P36-RETRY'" 2>/dev/null | tr -dc 0-9
}

dump() { # node label round
  local node=$1 label=$2 rnd=$3
  "$SSH" "$node" "$PASS" '
    echo "=== D-state tasks with stacks + cmdline ==="
    for p in $(ps -eo pid,stat | awk "\$2 ~ /D/ {print \$1}"); do
      echo "--- pid=$p comm=$(cat /proc/$p/comm 2>/dev/null) cmdline=[$(tr \"\\0\" \" \" < /proc/$p/cmdline 2>/dev/null)]"
      cat /proc/$p/stack 2>/dev/null
    done
    echo "=== recent P36/P71/P70 dmesg ==="
    dmesg | grep -E "P36-RETRY|P36-STRIKE|P71-HOLD|P70-BP|LKTIMEOUT" | tail -30
  ' > "$OUT/stacks_${label}_r${rnd}.txt" 2>&1
}

end=$(( $(date +%s) + MAXW ))
rnd=0
while [ "$(date +%s)" -lt "$end" ]; do
  c1=$(probe "$N1"); c2=$(probe "$N2")
  c1=${c1:-0}; c2=${c2:-0}
  if [ "$c1" -ge 2 ] || [ "$c2" -ge 2 ]; then
    rnd=$((rnd+1))
    echo "[abba-cap] storm sample (c1=$c1 c2=$c2) — dump round $rnd"
    dump "$N1" test1 "$rnd" & d1=$!
    dump "$N2" test2 "$rnd" & d2=$!
    wait $d1 $d2
    sleep 6
  else
    sleep 3
  fi
done
echo "[abba-cap] done ($rnd dump rounds)"
[ "$rnd" -gt 0 ]
