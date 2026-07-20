#!/bin/bash
# tcp_dlm_scaling — TCP-transport DLM mesh + cross-node lock-throughput.
#
# TCP-DLM-specific (Category 4): verifies the TCP transport mesh is fully wired
# (every node holds >= N-1 established connections on the DLM port 7600) and
# that contended cross-node DLM lock handoffs sustain throughput — each node
# rapidly creates+renames+removes its own entry in a SHARED directory (forcing
# repeated cross-node dir-EX handoffs over the TCP transport) and must complete
# its quota within the budget.  PASS iff the mesh is complete AND every node
# clears its lock-op quota in time (no TCP-handoff collapse/stall).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../suite/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.tcp_dlm_scaling"
mkdir -p "$D" 2>/dev/null

# sess13 diagnostic (harmless unless mxfs.lockwr=1): pin the P-LKT ring filter to
# the shared-dir inode so its cross-node grant/release events survive the
# child-inode GRANT-LOCAL flood.  Each node sets it for the dir it churns.
DINO=$(stat -c %i "$D" 2>/dev/null)
if [ -n "$DINO" ] && [ -w /sys/module/mxfs/parameters/lkt_ino ]; then
    echo "$DINO" > /sys/module/mxfs/parameters/lkt_ino 2>/dev/null
fi

# sess9 (ccloop 72513a13): N-INVARIANT total volume, drc-precedent.  The old
# flat 150 rounds/node made TOTAL shared-dir EX ops grow linearly with N
# (450×N serialized through ONE dir's EX rotation) while WINDOW stayed 60s —
# at 16/tcp the cluster ran a HEALTHY 8.6ms/op yet 6-12 nodes landed at
# 60-64s: the bar failed scale, not the FS.  1600 total rounds (×3 ops)
# ≈ 4800 serialized ops ≈ 41s at the measured healthy rate at ANY N; the
# 60s window now means the same thing on every rung.  Floor 50 keeps the
# per-node sample statistically meaningful at N=32.
TSR_DEF=$(( 1600 / T )); [ "$TSR_DEF" -lt 50 ] && TSR_DEF=50
ROUNDS="${TCP_SCALING_ROUNDS:-$TSR_DEF}"
WINDOW="${TCP_SCALING_WINDOW:-60}"

ck "tds barrier ready" coord_barrier "tds_ready"

# (1) TCP mesh must be fully established.
if [ "$T" -ge 2 ]; then
    conns=$(ss -tn state established '( sport = 7600 or dport = 7600 )' 2>/dev/null \
            | grep -v '^State' | grep -c ':7600')
    ck "tds tcp mesh >= N-1" test "${conns:-0}" -ge "$((T - 1))"
fi

# (2) Cross-node lock-handoff throughput on a SHARED hot dir.
t0=$(date +%s.%N)
done_rounds=0
for r in $(seq 1 "$ROUNDS"); do
    f="$D/n${R}_r${r}"
    { echo "$r" > "$f" && mv "$f" "$f.done" && rm -f "$f.done"; } || break
    done_rounds=$r
done
t1=$(date +%s.%N)
elapsed=$(awk "BEGIN{e=$t1-$t0; print (e>0)?e:0.001}")
echo "mxfs-TDS rank=$R elapsed=$elapsed rounds=$done_rounds window=$WINDOW" > /dev/kmsg 2>/dev/null || true
sync

ckeq "tds node${R} completed rounds" "$ROUNDS" "$done_rounds"
ck   "tds node${R} within window" awk "BEGIN{exit !($elapsed <= $WINDOW)}"

ck "tds barrier churn" coord_barrier "tds_churn"

# (3) Shared dir fully drained (no leaked dirent under TCP-DLM churn).
if [ "$R" = 1 ]; then
    left=$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')
    # sess13 diagnostic: on a drain failure, while still mounted, log the
    # leftover dirents + dump the P-LKT ring for the dir inode (mxfs.lockwr=1).
    if [ "${left:-0}" != 0 ]; then
        echo "mxfs: TDS-LEFTOVER ino=$DINO names=[$(ls "$D" 2>/dev/null | tr '\n' ' ')]" > /dev/kmsg 2>/dev/null
        [ -w /sys/module/mxfs/parameters/lktdump ] && \
            echo "${DINO:-0}" > /sys/module/mxfs/parameters/lktdump 2>/dev/null
    fi
    ckeq "tds shared dir drained" 0 "$left"
fi

ck "tds barrier done" coord_barrier "tds_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
