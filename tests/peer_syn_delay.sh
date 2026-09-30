#!/bin/bash
#
# peer_syn_delay.sh — hold every TCP connection setup of the peer mesh open on
# the rig's nodes, by delaying the SYN and the SYN-ACK of the peer port and
# nothing else, or take that delay away again.
#
# WHY.  Two nodes that sight each other together both connect: the lower node
# id connects, and the higher one force-connects when it holds no connection
# at its sighting.  On the rig a connection is set up in about a millisecond,
# so the higher node's sighting falls inside the lower one's setup about once
# in ten cluster formations, and a lap that wants both directions to meet
# waits for that.  A delay inside the module (peer_recv_start_delay_ms) holds
# the window AFTER a socket's install open, which is not the window the
# sightings race in.  Delaying the SYN and the SYN-ACK makes every setup of
# the mesh take two delays, with the module as a release carries it and with
# every message of an established connection as fast as it was.
#
# WHAT IT DOES, per node and in parallel:
#   apply <ms>  root qdisc prio with a fourth band nothing maps to, netem
#               delay <ms> on that band, and two filters that send to it the
#               TCP packets with SYN set whose destination or source port is
#               the peer port (the SYN, and the SYN-ACK that answers it)
#   clear       removes the root qdisc; the kernel puts its default back
#   show        prints the qdiscs and the filters
# Each node answers one line: <node> rc=<rc> netem=<0|1> filters=<n>.
# apply ends 0 only when every node reads netem=1 filters=2, clear only when
# every node reads netem=0.
#
# A node that reboots loses the delay; a lap that kills nodes is not run
# under it.  The delay must be cleared before any other lap or board runs.
#
# Budget (derived): per node one ssh of four tc commands, measured under 2 s;
# bound 20 s per node, run in parallel, so the caller's bound is 30 s.
#
# Usage: tests/peer_syn_delay.sh <nodes> apply <ms> | clear | show
#        [PEER_PORT=7600] [DEV=eth0]
#
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
SSH="$HERE/tools/mxfs_sshpass.sh"
N="${1:?usage: peer_syn_delay.sh <nodes> apply <ms> | clear | show}"
OP="${2:?usage: peer_syn_delay.sh <nodes> apply <ms> | clear | show}"
MS="${3:-0}"
PORT="${PEER_PORT:-7600}"
DEV="${DEV:-eth0}"
case "$N$MS$PORT" in *[!0-9]*) echo "nodes, ms and PEER_PORT are numbers" >&2; exit 2 ;; esac
case $OP in
    apply) [ "$MS" -gt 0 ] || { echo "apply needs a delay above 0 ms" >&2; exit 2; } ;;
    clear|show) ;;
    *) echo "unknown operation [$OP]" >&2; exit 2 ;;
esac
OUT=$(mktemp -d)
READ="echo NETEM=\$(tc qdisc show dev $DEV | grep -c netem) FILTERS=\$(tc filter show dev $DEV parent 1: 2>/dev/null | grep -c 'flowid 1:4')"
case $OP in
    apply) CMD="tc qdisc del dev $DEV root 2>/dev/null
        tc qdisc add dev $DEV root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1 &&
        tc qdisc add dev $DEV parent 1:4 handle 40: netem delay ${MS}ms limit 1000 &&
        tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff match ip dport $PORT 0xffff match u8 0x02 0x02 at 33 flowid 1:4 &&
        tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff match ip sport $PORT 0xffff match u8 0x02 0x02 at 33 flowid 1:4
        echo RC=\$?; $READ" ;;
    clear) CMD="tc qdisc del dev $DEV root 2>/dev/null; echo RC=0; $READ" ;;
    show)  CMD="tc qdisc show dev $DEV; tc filter show dev $DEV parent 1: 2>/dev/null; echo RC=0; $READ" ;;
esac
pids=()
for i in $(seq 1 "$N"); do
    ( timeout 20 "$SSH" "test$i" "$CMD" </dev/null > "$OUT/test$i.txt" 2>/dev/null; echo "SSH_RC=$?" >> "$OUT/test$i.txt" ) &
    pids+=($!)
done
wait "${pids[@]}"
bad=0
for i in $(seq 1 "$N"); do
    f="$OUT/test$i.txt"
    rc=$(sed -n 's/^RC=//p' "$f" | tail -n 1)
    sshrc=$(sed -n 's/^SSH_RC=//p' "$f" | tail -n 1)
    netem=$(sed -n 's/^NETEM=\([0-9]*\) .*/\1/p' "$f" | tail -n 1)
    filters=$(sed -n 's/.* FILTERS=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
    [ "$OP" = show ] && grep -a -E '^(qdisc|filter| *match)' "$f" | sed -e "s/^/test$i: /" | cut -c1-200
    echo "test$i rc=${rc:-none} ssh_rc=${sshrc:-none} netem=${netem:-?} filters=${filters:-?}"
    case $OP in
        apply) [ "${rc:-1}" = 0 ] && [ "${netem:-0}" = 1 ] && [ "${filters:-0}" = 2 ] || bad=$(( bad + 1 )) ;;
        clear) [ "${netem:-1}" = 0 ] || bad=$(( bad + 1 )) ;;
        show)  [ "${sshrc:-1}" = 0 ] || bad=$(( bad + 1 )) ;;
    esac
done
v=PASS; [ $bad = 0 ] || v=FAIL
echo "RESULT $v peer_syn_delay $OP nodes=$N ms=$MS port=$PORT dev=$DEV not_as_asked=$bad"
[ $bad = 0 ]
