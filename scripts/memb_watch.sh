#!/bin/bash
# memb_watch.sh — sample every node's latest MXFS-MEMBERSHIP active_count beacon
# on a clyde-synchronized clock, to prove/disprove membership FLAP (split-brain)
# during a live 16/32-node test.  If any node's active_count != N (or nodes
# disagree) DURING a coherency test, split-brain master-selection is possible
# (master = nodes[hash % active_count] differs across nodes -> two EX holders ->
# durable lost-update).  Ranked-#1 decisive experiment (ccloop 26c41354 sess1).
#
# Usage: scripts/memb_watch.sh <N> <out_log> [interval_s] [duration_s]
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
N="${1:?usage: memb_watch.sh <N> <out_log> [interval] [duration]}"
OUT="${2:?need out_log}"
INT="${3:-4}"
DUR="${4:-3600}"

NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done
: > "$OUT"
t0=$SECONDS
while [ $(( SECONDS - t0 )) -lt "$DUR" ]; do
    ts=$(date -u +%H:%M:%S)
    tmpd=$(mktemp -d)
    for n in "${NODES[@]}"; do
        ( c=$(timeout 6 "$SSH" "$n" "$PASS" \
              "dmesg | grep -oE 'MXFS-MEMBERSHIP local=[0-9]+ active_count=[0-9]+' | tail -1 | grep -oE 'active_count=[0-9]+' | cut -d= -f2" \
              2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you' | tr -d '\r\n ')
          echo "${c:-X}" > "$tmpd/$n" ) &
    done
    wait
    line="$ts"; diverge=0; seen=""
    for n in "${NODES[@]}"; do
        c=$(cat "$tmpd/$n" 2>/dev/null); c="${c:-X}"
        line="$line ${n#test}=$c"
        [ "$c" = "$N" ] || diverge=1
    done
    rm -rf "$tmpd"
    flag=""; [ "$diverge" = 1 ] && flag="  <<< DIVERGE(!=$N)"
    echo "$line$flag" >> "$OUT"
    sleep "$INT"
done
