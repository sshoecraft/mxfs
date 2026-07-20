#!/bin/bash
# dlm_membership — cluster membership correctness + graceful peer quiescence.
#
# Verifies the DLM forms a complete N-member cluster and keeps it coherent:
#   (a) every node publishes an "alive" marker and every node sees all N
#       (membership view is complete cluster-wide);
#   (b) on a TCP cluster, each node holds >= N-1 established DLM connections
#       (the transport mesh is fully wired);
#   (c) availability during a peer's quiescence: rank1 keeps writing while the
#       highest rank goes quiet (drops its DLM TCP traffic briefly, < lease
#       window), then the quiesced node REJOINS and must see every write rank1
#       made during the window (rejoin coherency — no stale cache).
# Soft fault only (run.sh has no host-side kill); the brief block is far under
# the 62s lease timeout so no node is fenced.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.dlm_membership"
mkdir -p "$D" 2>/dev/null

ck "mem barrier ready" coord_barrier "mem_ready"

# (a) membership completeness.
echo "$R" > "$D/alive_n${R}"; sync
ck "mem barrier alive" coord_barrier "mem_alive"
seen=0
for n in $(seq 1 "$T"); do test -f "$D/alive_n${n}" && seen=$((seen + 1)); done
ckeq "mem all N members visible" "$T" "$seen"

# (b) transport mesh (TCP only).
if [ "$T" -ge 2 ] && [ "${MXFS_DLM:-tcp}" = tcp ]; then
    conns=$(ss -tn state established '( sport = 7600 or dport = 7600 )' 2>/dev/null \
            | grep -v '^State' | grep -c ':7600')
    ck "mem tcp mesh >= N-1" test "${conns:-0}" -ge "$((T - 1))"
fi
ck "mem barrier mesh" coord_barrier "mem_mesh"

# (c) availability during peer quiescence + rejoin coherency.
NWRITE=25
if [ "$R" = 1 ]; then
    # Let the quiescing peer drop first, then write into the window.
    coord_wait "mem_quiesced" 30 || true
    for i in $(seq 1 "$NWRITE"); do echo "absent_$i" > "$D/aw_$i"; done
    sync
    coord_signal "mem_window_done"
elif [ "$R" = "$T" ]; then
    # Highest rank quiesces: briefly drop DLM TCP traffic (well under the
    # 62s lease), then restore = graceful leave+rejoin.
    have_ipt=0; command -v iptables >/dev/null 2>&1 && have_ipt=1
    if [ "$have_ipt" = 1 ]; then
        iptables -I INPUT  -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -I OUTPUT -p tcp --dport 7600 -j DROP 2>/dev/null
    fi
    coord_signal "mem_quiesced"
    sleep 2
    if [ "$have_ipt" = 1 ]; then
        iptables -D INPUT  -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -D OUTPUT -p tcp --dport 7600 -j DROP 2>/dev/null
    fi
    # Rejoin: must see ALL of rank1's window writes (coherent, no stale cache).
    coord_wait "mem_window_done" 60
    cnt=$(ls "$D"/aw_* 2>/dev/null | wc -l | tr -d ' ')
    ckeq "mem rejoined node sees peer window writes" "$NWRITE" "$cnt"
else
    coord_signal "mem_quiesced"   # middle ranks: no-op participant
fi

ck "mem barrier done" coord_barrier "mem_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
