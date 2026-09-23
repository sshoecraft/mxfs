#!/bin/bash
# netconsole_listen.sh — capture the test nodes' kernel log on clyde.
#
# WHY.  A node that panics reboots, and a rebooted node's dmesg starts at the
# new boot: the panic text is gone before anything can read it.  systemd-pstore
# recovers it only when the guest actually has a pstore backend, and a libvirt
# guest with the default machine type does not always.  So the only reliable
# record of a guest panic on this rig is the one the guest sends OUT while it
# is dying.
#
# Every test node is already configured to netconsole to clyde:
#
#     netpoll: netconsole: remote IPv4 address 192.168.120.1
#     netpoll: netconsole: remote port 6666
#
# Nothing has ever listened on that port, so every one of those datagrams has
# been discarded.  A panic that arrived while nobody was listening reads
# exactly like a node that "just rebooted" -- which is how the 2026-09-10
# mount-time reboot of test1 was first written down.
#
# This listener is deliberately dumb: it appends whatever arrives, with a
# receive timestamp, and never parses.  Kernel messages arriving mid-panic are
# the last thing that should be filtered by anything clever.
#
# Usage:
#   tools/netconsole_listen.sh start [logfile]   background, writes a pidfile
#   tools/netconsole_listen.sh stop
#   tools/netconsole_listen.sh status
#   tools/netconsole_listen.sh tail [n]
#
# The log lands in tests/evidence/netconsole.log by default and is APPENDED to,
# never truncated: an old capture is evidence too.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
PORT=${MXFS_NETCONSOLE_PORT:-6666}
LOG=${2:-$REPO/tests/evidence/netconsole.log}
PIDFILE=$REPO/tests/evidence/.netconsole.pid

have() { command -v "$1" >/dev/null 2>&1; }

start() {
    mkdir -p "$(dirname "$LOG")"
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        # /proc/<pid>/comm is safe to read on this host; /proc/<pid>/cmdline
        # is not (reading it takes that task's mmap_lock, and one task wedged
        # holding its own has hung every reader on this box before now).
        if [ -n "${pid:-}" ] && [ -r "/proc/$pid/comm" ]; then
            echo "already running pid=$pid log=$LOG"
            return 0
        fi
    fi
    if have socat; then
        nohup socat -u UDP-RECV:"$PORT",reuseaddr - >> "$LOG" 2>&1 &
    elif have ncat; then
        nohup ncat -u -l -k -p "$PORT" >> "$LOG" 2>&1 &
    elif have nc; then
        nohup nc -u -l -k -p "$PORT" >> "$LOG" 2>&1 &
    else
        echo "FAIL no socat, ncat or nc on this host — cannot listen on UDP $PORT"
        return 2
    fi
    echo $! > "$PIDFILE"
    echo "started pid=$(cat "$PIDFILE") port=$PORT log=$LOG"
    echo "-- listener started $(date -u +%FT%TZ) --" >> "$LOG"
}

stop() {
    [ -f "$PIDFILE" ] || { echo "not running (no pidfile)"; return 0; }
    pid=$(cat "$PIDFILE")
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
    rm -f "$PIDFILE"
    echo "stopped pid=$pid"
}

status() {
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        if [ -n "${pid:-}" ] && [ -r "/proc/$pid/comm" ]; then
            echo "running pid=$pid comm=$(cat "/proc/$pid/comm") port=$PORT log=$LOG"
            echo "log bytes: $(wc -c < "$LOG" 2>/dev/null || echo 0)"
            return 0
        fi
    fi
    echo "not running (port $PORT unlistened — guest panics are being discarded)"
    return 1
}

case "${1:-status}" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    tail)   tail -n "${2:-60}" "$LOG" ;;
    *)      echo "usage: $0 start|stop|status|tail"; exit 2 ;;
esac
