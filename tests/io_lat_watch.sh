#!/bin/bash
# io_lat_watch.sh — start/stop the bpftrace witness (tests/io_lat_watch.bt) on
# each named node and harvest what it saw.  It answers, for any lap that shows
# a DLM request-deadline expiry or a whole-node pause, whether the shared LUN
# or the TCP link froze underneath mxfs during that second: SLOWIO lines are
# block completions >= 100 ms, TCPRETX lines are retransmitted segments, both
# stamped with the node's monotonic clock (dmesg's time base).
#
# The s543i lap (2026-09-08 21:01Z) had test1 log nothing for 2.3 s in the
# middle of a create burst while test2's SB-summary request sat unanswered
# past the 1 s deadline; every message in both directions resumed at the same
# instant.  Nothing in that lap's evidence could say whether the LUN or the
# link paused.  This is the witness that lap lacked.
#
# Usage: tests/io_lat_watch.sh start <label> <node>...
#        tests/io_lat_watch.sh stop  <label> <node>...   -> tests/evidence/<ts>_iolat_<label>/<node>.txt
# The stop action prints per-node counts: slow completions, max latency,
# retransmits by destination port (3260 = iSCSI to the LUN).
set -u
ACTION=${1:?start|stop}
LABEL=${2:?label}
shift 2
[ $# -ge 1 ] || { echo "usage: $0 start|stop <label> <node>..." >&2; exit 2; }
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
RLOG=/tmp/io_lat_watch_$LABEL.log
RPID=/tmp/io_lat_watch_$LABEL.pid
RBT=/tmp/io_lat_watch.bt

case "$ACTION" in
start)
    for n in "$@"; do
        timeout 20 $SSH "$n" SCP tests/io_lat_watch.bt "$RBT" >/dev/null 2>&1 || { echo "  FAIL $n: could not copy the bpftrace program"; exit 3; }
        # -B line: a line per event as it happens, not at exit; -q: no attach banner.
        got=$(timeout 20 $SSH "$n" "nohup bpftrace -q -B line $RBT > $RLOG 2>&1 & echo \$! > $RPID; sleep 1; if kill -0 \$(cat $RPID) 2>/dev/null; then echo STARTED pid=\$(cat $RPID); else echo DEAD; cat $RLOG; fi" 2>/dev/null | filt | tr '\n' ' ')
        echo "  INFO io_lat_watch $n: $got"
        case "$got" in *STARTED*) ;; *) exit 3 ;; esac
    done
    ;;
stop)
    OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_iolat_$LABEL
    mkdir -p "$OUT"
    for n in "$@"; do
        # SIGTERM ends the trace and prints the maps (histogram, counts) at the tail of the log.
        timeout 30 $SSH "$n" "p=\$(cat $RPID 2>/dev/null); [ -n \"\$p\" ] && kill \$p 2>/dev/null; for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 \$p 2>/dev/null || break; sleep 0.5; done; cat $RLOG" 2>/dev/null | filt > "$OUT/$n.txt"
        slow=$(grep -ac '^SLOWIO' "$OUT/$n.txt")
        maxms=$(grep -ao 'lat_ms=[0-9]*' "$OUT/$n.txt" | cut -d= -f2 | sort -n | tail -1)
        retx=$(grep -ac '^TCPRETX' "$OUT/$n.txt")
        retx_iscsi=$(grep -ac '^TCPRETX.*dport=3260$' "$OUT/$n.txt")
        issued=$(grep -ao '^@issued: [0-9]*' "$OUT/$n.txt" | cut -d' ' -f2)
        echo "  IOLAT-MEASURE label=$LABEL node=$n issued=${issued:-?} slow_ge_100ms=$slow max_ms=${maxms:-0} tcp_retx=$retx tcp_retx_iscsi=$retx_iscsi tcp_retx_other=$(( retx - retx_iscsi )) out=$OUT/$n.txt"
    done
    ;;
*)
    echo "usage: $0 start|stop <label> <node>..." >&2; exit 2 ;;
esac
