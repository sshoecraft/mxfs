#!/bin/bash
# klog_tail.sh — live kernel-log collectors that survive VM destroy.
#
# Problem this solves (sess4 ccloop 186320ae): test1 wedged mid-run, the
# harness virsh-destroyed it, and its runtime-only journald lost the entire
# wedge-era kernel log — the primary evidence for a RULE-4 diagnosis.
# journald persistence alone is not enough: its async flush loses the last
# seconds before a hard destroy.  A clyde-side `dmesg -w` over ssh captures
# every line up to the instant of death, stored on clyde.
#
# Usage:
#   scripts/klog_tail.sh start N      # spawn collectors for test1..testN
#   scripts/klog_tail.sh stop         # kill all collectors
#   scripts/klog_tail.sh status       # show collector pids + log sizes
#
# Logs: /tmp/klog_<node>.log on clyde (append; one file per node, restarted
# collectors keep appending so reboots leave a seam, grep for "=== klog").
# The spawner loop re-establishes the ssh after a node reboot.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$SCRIPT_DIR")
PASS_FILE=${MXFS_PASS:-/tmp/.mxfs_pass}
PIDDIR=/tmp/klog_tail.pids

case "${1:-}" in
start)
    N=${2:?usage: klog_tail.sh start N}
    mkdir -p "$PIDDIR"
    for i in $(seq 1 "$N"); do
        node="test$i"
        [ -e "$PIDDIR/$node.pid" ] && kill "$(cat "$PIDDIR/$node.pid")" 2>/dev/null
        (
            while :; do
                echo "=== klog collector (re)attach $node $(date -u +%FT%TZ) ===" >> "/tmp/klog_$node.log"
                timeout 86400 "$REPO/tools/mxfs_sshpass.sh" "$node" "$PASS_FILE" \
                    "dmesg -TW" >> "/tmp/klog_$node.log" 2>/dev/null
                sleep 5
            done
        ) &
        echo $! > "$PIDDIR/$node.pid"
    done
    echo "collectors started for test1..test$N (logs /tmp/klog_testN.log)"
    ;;
stop)
    if [ -d "$PIDDIR" ]; then
        for f in "$PIDDIR"/*.pid; do
            [ -e "$f" ] || continue
            pkill -P "$(cat "$f")" 2>/dev/null
            kill "$(cat "$f")" 2>/dev/null
            rm -f "$f"
        done
    fi
    pkill -f "dmesg -TW" 2>/dev/null
    echo "collectors stopped"
    ;;
status)
    for f in "$PIDDIR"/*.pid; do
        [ -e "$f" ] || continue
        node=$(basename "$f" .pid)
        pid=$(cat "$f")
        sz=$(stat -c%s "/tmp/klog_$node.log" 2>/dev/null || echo 0)
        printf "%s: spawner=%s alive=%s log=%s bytes\n" "$node" "$pid" \
            "$(kill -0 "$pid" 2>/dev/null && echo yes || echo no)" "$sz"
    done
    ;;
*)
    echo "usage: klog_tail.sh {start N|stop|status}" >&2; exit 2 ;;
esac
