#!/bin/bash
# drc_wedge_capture.sh — capture the exact kernel state of a dir_reuse@N/caw
# wedge (sess5 ccloop a864: the per-unlink durable-signal AIL-flush hang).
#
# Run against the rank-1 node (or any node showing a stuck rm / no round
# progress).  Dumps: the rm/unlink task stack (the durable-signal bwrite hang),
# every D-state task's stack (xfsaild, mxfs-ino-bast kworkers doing sync AIL
# push), and the recent P43-OWNERSCAN / P91-BAST-PROTECT / P-COUNTREGRESS /
# P15H probe flood.  Read-only; safe to run repeatedly.
#
# Usage: drc_wedge_capture.sh <node>   (e.g. drc_wedge_capture.sh test1)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"; PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
N="${1:?usage: drc_wedge_capture.sh <node>}"

timeout 25 "$SSH" "$N" "$PASS" '
  echo "=== $(hostname) $(date -u +%H:%M:%SZ) ==="
  echo "--- latest DRCph round/phase ---"
  dmesg 2>/dev/null | grep -oE "mxfs-DRCph r=[0-9]+ rank=[0-9]+ PHASE=[a-z-]+" | tail -1

  echo "--- ALL D-state tasks (pid stat comm wchan) ---"
  ps -eo pid,stat,comm,wchan | awk "\$2 ~ /D/ {print}" | head -40

  echo "--- stuck rm / unlink task stack ---"
  for p in $(ps -eo pid,comm | awk "\$2 ~ /^rm$|unlink/ {print \$1}"); do
    echo "  [rm pid=$p]"; cat /proc/$p/stack 2>/dev/null | head -25; echo
  done

  echo "--- xfsaild stack (AIL destage progress) ---"
  for p in $(ps -eo pid,comm | awk "\$2 ~ /xfsaild/ {print \$1}"); do
    echo "  [xfsaild pid=$p]"; cat /proc/$p/stack 2>/dev/null | head -20; echo
  done

  echo "--- mxfs bast kworker stacks (sync AIL push) ---"
  for p in $(ps -eo pid,comm | awk "\$2 ~ /kworker/ {print \$1}"); do
    st=$(cat /proc/$p/stack 2>/dev/null)
    echo "$st" | grep -qiE "ail_push|mxfs|xfs_buf|bast|drain" && { echo "  [kworker pid=$p]"; echo "$st" | head -18; echo; }
  done

  echo "--- recent durable-signal / AIL-jam probes ---"
  dmesg 2>/dev/null | grep -E "P43-OWNERSCAN|P91-BAST-PROTECT|P-COUNTREGRESS|P15H|P138|P136|P113-DRAIN|DIR-STALE-SKIP|OWNERSCAN-FLUSH-ERR" | tail -30
' 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'
