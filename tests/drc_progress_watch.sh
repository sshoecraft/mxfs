#!/bin/bash
# drc_progress_watch.sh — lightweight progress monitor for a dir_reuse@N/caw run.
# Every INTERVAL seconds, snapshots from a sample of nodes: the latest DRCph
# round/phase, count of the sess4 wall-clock strand escape (P15H-STRAND-TIMEOUT)
# firing, count of P-ACQ-STUCK (peers starving), and the latest P-ACQ-STUCK
# el_ms (longest live stall).  Writes a compact timeline to $OUT.
# Usage: drc_progress_watch.sh <OUT> [N] [INTERVAL] [MAXSECS]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"; PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
OUT="${1:?usage: drc_progress_watch.sh OUT [N] [INTERVAL] [MAXSECS]}"
N="${2:-32}"; INT="${3:-60}"; MAX="${4:-5400}"
# sample nodes spread across the set
SAMPLE="test1 test8 test16 test17 test24 test32"
: > "$OUT"
t0=$(date +%s)
while :; do
  now=$(date +%s); el=$((now - t0))
  [ "$el" -ge "$MAX" ] && { echo "[$el s] watcher MAX reached" >> "$OUT"; break; }
  line="[$el s $(date -u +%H:%M:%SZ)]"
  for n in $SAMPLE; do
    d=$(timeout 8 "$SSH" "$n" "$PASS" '
        r=$(dmesg 2>/dev/null | grep -oE "mxfs-DRCph r=[0-9]+ rank=[0-9]+ PHASE=[a-z-]+" | tail -1);
        strand=$(dmesg 2>/dev/null | grep -c "P15H-STRAND-TIMEOUT");
        stuck=$(dmesg 2>/dev/null | grep -c "P-ACQ-STUCK");
        maxel=$(dmesg 2>/dev/null | grep -oE "P-ACQ-STUCK .*el_ms=[0-9]+" | grep -oE "el_ms=[0-9]+" | sort -t= -k2 -n | tail -1);
        printf "%s strand=%s stuck=%s %s" "$r" "$strand" "$stuck" "$maxel"
    ' 2>/dev/null)
    line="$line | $n: ${d:-NO-RESP}"
  done
  echo "$line" >> "$OUT"
  # stop if run finished (lock gone AND no run.sh)
  if ! pgrep -f "run.sh $N caw" >/dev/null 2>&1; then
    echo "[$el s] run.sh gone — exiting watcher" >> "$OUT"; break
  fi
  sleep "$INT"
done
