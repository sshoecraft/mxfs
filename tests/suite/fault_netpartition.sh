#!/bin/bash
# fault_netpartition — transient DLM network partition + recovery.
#
# The highest rank briefly blocks the DLM transport port (7600) in BOTH
# directions (a partition), holds it well UNDER the 62s lease/dead-node window
# so the node is NOT fenced, then restores connectivity.  After the heal, the
# cluster must reconverge: a fresh cross-node write made by rank1 during the
# partition becomes visible to the healed node, and every node's FS stays
# mounted + writable (no split-brain corruption, no spurious eviction).
#
# Coordination uses MQTT (broker on a different host/port), so the control
# plane keeps working while the DLM port is blocked.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.fault_netpartition"
mkdir -p "$D" 2>/dev/null

BLOCK_S="${NETPART_BLOCK_S:-3}"   # << 62s lease => no fence
MARK="MXFS_NETPART_$(date +%s)_${R}"
echo "$MARK" > /dev/kmsg 2>/dev/null
FPAT='Shutting down|shutting down|SHUTDOWN|Corruption|Internal error|split.?brain'

ck "np barrier ready" coord_barrier "np_ready"

if [ "$R" = "$T" ] && [ "$T" -ge 2 ]; then
    have_ipt=0; command -v iptables >/dev/null 2>&1 && have_ipt=1
    if [ "$have_ipt" = 1 ]; then
        iptables -I INPUT  -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -I OUTPUT -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -I INPUT  -p tcp --sport 7600 -j DROP 2>/dev/null
        iptables -I OUTPUT -p tcp --sport 7600 -j DROP 2>/dev/null
    fi
    coord_signal "np_blocked"
    sleep "$BLOCK_S"
    if [ "$have_ipt" = 1 ]; then
        iptables -D INPUT  -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -D OUTPUT -p tcp --dport 7600 -j DROP 2>/dev/null
        iptables -D INPUT  -p tcp --sport 7600 -j DROP 2>/dev/null
        iptables -D OUTPUT -p tcp --sport 7600 -j DROP 2>/dev/null
    fi
    coord_signal "np_healed"
elif [ "$R" = 1 ]; then
    # During the partition, write into the FS; after heal the peer must see it.
    coord_wait "np_blocked" 30 || true
    for i in $(seq 1 15); do echo "part_$i" > "$D/part_$i"; done; sync
    coord_wait "np_healed" 60 || true
else
    coord_wait "np_healed" 60 || true
fi

# Give the mesh a moment to reconverge after heal.
ck "np barrier healed" coord_barrier "np_healed_bar"
sleep 2

# Recovery checks: FS writable everywhere; healed node sees rank1's writes.
probe="$D/.probe_n${R}"
ck "np node${R} still writable" bash -c ": > '$probe' && rm -f '$probe'"
hits=$(dmesg 2>/dev/null | awk -v m="$MARK" 'f{print} $0 ~ m{f=1}' | grep -ciE "$FPAT")
ckeq "np node${R} no shutdown/split-brain" 0 "${hits:-0}"

if [ "$R" = "$T" ]; then
    # Force a coherent re-read of the dir the peer wrote during the partition.
    sync; echo 1 > /proc/sys/vm/drop_caches 2>/dev/null
    cnt=$(ls "$D"/part_* 2>/dev/null | wc -l | tr -d ' ')
    ckeq "np healed node sees partition-window writes" 15 "$cnt"
fi

ck "np barrier done" coord_barrier "np_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
