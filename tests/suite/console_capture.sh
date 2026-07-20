#!/bin/bash
#
# console_capture.sh — capture test-VM serial consoles to files on the host.
#
# The test VMs' <serial type='pty'> exposes each guest's serial console as a
# host pty (path in `virsh dumpxml`).  A guest kernel panic prints there and
# is otherwise LOST when the guest auto-reboots (dmesg does not survive).
# Start a background reader per node so the oops text lands in a host file.
#
# Usage:
#   console_capture.sh start <outdir> [n_nodes]   # after VMs are booted
#   console_capture.sh stop
#
# Readers die automatically when the VM restarts (pty goes away); re-run
# `start` after every VM cycle.  RULE 3: lives in the source tree.
#
set -u
CMD="${1:-}"
OUTDIR="${2:-/tmp/mxfs_consoles}"
N="${3:-8}"
PIDFILE=/tmp/.mxfs_console_capture.pids

case "$CMD" in
start)
    mkdir -p "$OUTDIR"
    : > "$PIDFILE"
    for k in $(seq 1 "$N"); do
        pty=$(virsh -c qemu:///system dumpxml "test$k" 2>/dev/null |
              sed -n "s/.*<console type='pty' tty='\([^']*\)'.*/\1/p" | head -1)
        [ -z "$pty" ] && pty=$(virsh -c qemu:///system dumpxml "test$k" 2>/dev/null |
              grep -A2 "<serial type='pty'>" | sed -n "s/.*<source path='\([^']*\)'.*/\1/p" | head -1)
        if [ -z "$pty" ]; then
            echo "test$k: no pty found" >&2
            continue
        fi
        sudo -n sh -c "cat '$pty' >> '$OUTDIR/console_test$k.log' 2>/dev/null" &
        echo $! >> "$PIDFILE"
        echo "test$k: capturing $pty -> $OUTDIR/console_test$k.log"
    done
    ;;
stop)
    if [ -f "$PIDFILE" ]; then
        while read -r p; do
            sudo -n pkill -P "$p" 2>/dev/null
            kill "$p" 2>/dev/null
        done < "$PIDFILE"
        rm -f "$PIDFILE"
    fi
    echo "console capture stopped"
    ;;
*)
    echo "usage: $0 start <outdir> [n_nodes] | stop" >&2
    exit 1
    ;;
esac
