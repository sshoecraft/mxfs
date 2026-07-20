#!/bin/bash
# live_marker_harvest.sh — start/stop/collect per-node journalctl -f collectors
# so short-rotation journals (dirwr=1 floods rotate ~85s) can't eat the
# evidence window.  (ccloop 46efd8b6 sess2: rv-dir SF-era create trail needed
# across all 32 nodes; post-run pulls kept missing it.)
#
# Complex commands are NEVER passed through mxfs_sshpass.sh inline (its
# CMD="$*" flattening mangles quotes — see memory
# infra-sshpass-wrapper-flattens-args-no-complex-scripts).  A remote runner
# script is scp'd to each node and invoked by plain path.
#
# Usage:
#   live_marker_harvest.sh start N     — start collectors on test1..testN
#   live_marker_harvest.sh stop N      — stop collectors
#   live_marker_harvest.sh collect N D — scp each node's capture to D/testN.cap
set -u
CMD="${1:?start|stop|collect}"; N="${2:-32}"; OUT="${3:-}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass

case "$CMD" in
start)
    RS=$(mktemp)
    cat > "$RS" <<'EOF'
#!/bin/bash
pkill -f mxfs_live_harvest 2>/dev/null
rm -f /tmp/mxfs_harvest.cap
MARK='P-CRNAME|P-SFDIR|P-SFREL|P56-RELOAD-MERGE|P56-DIRWRITE|P29-DATAWRITE|P-LEAFWRITE|P-LEAFDROP|P26-DSCAN|P21H-LEAFHOLE|P3L-DIRLOG-BIRTH|P63-HANDOFF|P65-EPOCH-ADOPT|P-RELOAD-IDENTICAL|P62-RELOAD-FORK-SHRINK|P106-EXGRANT|P106-EXREL|P106-STALE|P141-UNLK|P127-DIRMISS|P-DIRFLUSH|P136-DIRINO-WRDONE|P-GENCREATE|P105-CREATE-PARENT|P-DE-BLK|P34F-RELOAD|P-DIRREFRESH-EVICT|P-TDS-RMW|Kernel panic|BUG:|Oops'
nohup bash -c "exec -a mxfs_live_harvest journalctl -k -f -o short-precise | grep -E --line-buffered '$MARK' > /tmp/mxfs_harvest.cap 2>/dev/null" >/dev/null 2>&1 &
echo STARTED
EOF
    for i in $(seq 1 "$N"); do
        ( sshpass -f "$PF" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$RS" "root@test$i:/tmp/mxfs_harvest_start.sh" >/dev/null 2>&1 && \
          "$SSH" "test$i" "$PF" "bash /tmp/mxfs_harvest_start.sh" 2>/dev/null | grep -q STARTED && echo "test$i started" ) &
    done
    wait; rm -f "$RS"; echo "collectors started on $N nodes"
    ;;
stop)
    for i in $(seq 1 "$N"); do
        ( "$SSH" "test$i" "$PF" "pkill -f mxfs_live_harvest; true" >/dev/null 2>&1 ) &
    done
    wait; echo "collectors stopped"
    ;;
collect)
    [ -n "$OUT" ] || { echo "collect needs an output dir"; exit 1; }
    mkdir -p "$OUT"
    for i in $(seq 1 "$N"); do
        ( sshpass -f "$PF" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@test$i:/tmp/mxfs_harvest.cap" "$OUT/test$i.cap" >/dev/null 2>&1 ) &
    done
    wait; wc -l "$OUT"/test*.cap 2>/dev/null | tail -1
    ;;
esac
