#!/bin/bash
# bastq_snap.sh — snapshot the two things the sess128 BAST-dispatch-queue
# change is measured on, across the whole fleet, into one directory:
#
#   udp/<node>   the numeric "Udp:" row of /proc/net/snmp (RcvbufErrors is
#                field 5).  The PASS bar is a ZERO delta across a run: a
#                nonzero one means BAST hints and/or grant nudges were
#                silently dropped by the kernel before mxfs ever saw them.
#   bq/<node>    the last P265-BASTQ-STATS line from the kernel log, which
#                carries submitted/dispatched/merged/rearmed/overflow/inline.
#                dispatched << submitted IS the coalescing working.
#
# Usage:  tests/bastq_snap.sh <outdir> [nodecount]
#         tests/bastq_snap.sh --delta <predir> <postdir>
#
# RULE 3: lives in the tree, not /tmp — this gets re-run every measurement.

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

udp_field() {   # udp_field <file> <1-based field index of the numeric row>
    awk '/^Udp: [0-9]/ { print $('"$2"'+1) }' "$1" 2>/dev/null
}

if [ "${1:-}" = "--delta" ]; then
    PRE="${2:?usage: --delta <predir> <postdir>}"
    POST="${3:?usage: --delta <predir> <postdir>}"
    tot_rcv=0; tot_in=0; tot_err=0; nodes=0
    printf '%-8s %12s %12s %12s\n' node dRcvbufErr dInErrors dInDatagrams
    for f in "$PRE"/udp/*; do
        n=$(basename "$f")
        [ -f "$POST/udp/$n" ] || continue
        a=$(udp_field "$f" 5);        b=$(udp_field "$POST/udp/$n" 5)
        ai=$(udp_field "$f" 3);       bi=$(udp_field "$POST/udp/$n" 3)
        ad=$(udp_field "$f" 1);       bd=$(udp_field "$POST/udp/$n" 1)
        [ -n "$a" ] && [ -n "$b" ] || continue
        d=$((b-a)); di=$((bi-ai)); dd=$((bd-ad))
        nodes=$((nodes+1)); tot_rcv=$((tot_rcv+d)); tot_err=$((tot_err+di)); tot_in=$((tot_in+dd))
        [ "$d" -ne 0 ] && printf '%-8s %12d %12d %12d\n' "$n" "$d" "$di" "$dd"
    done
    echo "---"
    echo "nodes=$nodes  TOTAL dRcvbufErrors=$tot_rcv  dInErrors=$tot_err  dInDatagrams=$tot_in"
    echo
    echo "=== P265-BASTQ-STATS (post) ==="
    cat "$POST"/bq/* 2>/dev/null | grep -o 'node=[0-9]* .*' | sort -u | head -40
    echo
    echo "=== aggregate bq totals (post) ==="
    cat "$POST"/bq/* 2>/dev/null | awk '
        match($0, /submitted=[0-9]+/)  { s += substr($0,RSTART+10,RLENGTH-10) }
        match($0, /dispatched=[0-9]+/) { d += substr($0,RSTART+11,RLENGTH-11) }
        match($0, /merged=[0-9]+/)     { m += substr($0,RSTART+7,RLENGTH-7) }
        match($0, /rearmed=[0-9]+/)    { r += substr($0,RSTART+8,RLENGTH-8) }
        match($0, /overflow=[0-9]+/)   { o += substr($0,RSTART+9,RLENGTH-9) }
        match($0, /inline=[0-9]+/)     { i += substr($0,RSTART+7,RLENGTH-7) }
        END { printf "submitted=%d dispatched=%d merged=%d rearmed=%d overflow=%d inline=%d",s,d,m,r,o,i
              if (s>0) printf "  coalescing=%.2fx\n", s/(d?d:1); else printf "\n" }'
    exit 0
fi

OUT="${1:?usage: bastq_snap.sh <outdir> [nodecount]}"
NC="${2:-32}"
mkdir -p "$OUT/udp" "$OUT/bq"

for i in $(seq 1 "$NC"); do
    (
      timeout 40 "$SSH" "test$i" \
        "grep '^Udp: [0-9]' /proc/net/snmp" > "$OUT/udp/test$i" 2>/dev/null
      timeout 40 "$SSH" "test$i" \
        "dmesg | grep 'P265-BASTQ-STATS' | tail -1" > "$OUT/bq/test$i" 2>/dev/null
    ) &
done
wait

ok=$(grep -lc '^Udp: [0-9]' "$OUT"/udp/* 2>/dev/null | wc -l)
echo "snapshot -> $OUT  (udp rows captured: $ok/$NC)"
