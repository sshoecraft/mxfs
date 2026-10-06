#!/bin/bash
#
# pve_netconsole.sh — send the physical Proxmox pair's kernel log to clyde as
# it is written, so a host that resets itself leaves a record of its last
# seconds.
#
# WHY.  pve2 reset itself twice under load with nothing in its journal for the
# last ~30 s: journald's file is in the page cache until it is flushed, and a
# hard reset (the 10 s softdog that watchdog-mux arms on every PVE host, or a
# reboot) drops it.  The hosts run kernel.panic=0 and have no pstore backend, so
# nothing on the host itself survives.  Netconsole sends each line out as it is
# printed.
#
# Usage:
#   tools/pve_netconsole.sh start [evidence-dir]   listeners on clyde + targets on the hosts
#   tools/pve_netconsole.sh status
#   tools/pve_netconsole.sh stop                   disable the targets, stop the listeners
#
# Each host gets its own UDP port and log: host N of PVE_PAIR sends to port
# 6667+N-1, logged to <evidence-dir>/netconsole_<hostname>.log (appended).
# The console log level on the hosts is raised to 5, because netconsole only
# carries what the console prints and Proxmox boots with "quiet" (level 4:
# errors and worse only).  5 adds warnings; an oops or panic turns the console
# verbose by itself.  Not 7: informational lines (a stack dump a diagnostic
# asks for) would then fill the host's own screen and read as a crash there.

set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
# The port is the host's place in the whole pair (PVE_PAIR_ALL), so running
# this for one host (PVE_PAIR=<host>) keeps that host on its own port and log.
PAIR_ALL="${PVE_PAIR_ALL:-192.168.1.80 192.168.1.81}"
PAIR="${PVE_PAIR:-$PAIR_ALL}"
CLYDE_IP="${PVE_NETCONSOLE_TO:-192.168.1.166}"
CLYDE_IF="${PVE_NETCONSOLE_IF:-enp6s0}"
EVID="${2:-$REPO/tests/evidence/pve_phys_drbd_netconsole}"
PAIRSH="$REPO/tools/pve_pair.sh"
LISTEN="$REPO/tools/netconsole_listen.sh"

port_of() {  # <host>: 6667 + its index in the whole pair
    local a i=0
    for a in $PAIR_ALL; do
        [ "$a" = "$1" ] && break
        i=$((i + 1))
    done
    echo $((6667 + i))
}

host_cmd() {  # <port> <clyde-mac>
    cat <<EOF
set -e
modprobe netconsole 2>/dev/null || true
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
T=/sys/kernel/config/netconsole/clyde
if [ -d \$T ]; then echo 0 > \$T/enabled; else mkdir \$T; fi
DEV=\$(ip route get $CLYDE_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')
SRC=\$(ip route get $CLYDE_IP | sed -n 's/.* src \([^ ]*\).*/\1/p')
echo \$DEV > \$T/dev_name
echo \$SRC > \$T/local_ip
echo $CLYDE_IP > \$T/remote_ip
echo $2 > \$T/remote_mac
echo $1 > \$T/remote_port
echo 1 > \$T/enabled
dmesg -n 5
echo "<4>mxfs-netconsole: \$(hostname) -> $CLYDE_IP:$1 via \$DEV src \$SRC enabled \$(date -Is)" > /dev/kmsg
echo "netconsole \$(hostname) dev=\$DEV src=\$SRC port=$1 enabled=\$(cat \$T/enabled)"
EOF
}

case "${1:-status}" in
    start)
        mkdir -p "$EVID"
        MAC=$(cat "/sys/class/net/$CLYDE_IF/address")
        for h in $PAIR; do
            p=$(port_of "$h")
            name=$("$PAIRSH" on "$h" hostname 2>/dev/null | tail -1)
            MXFS_NETCONSOLE_PORT=$p "$LISTEN" start "$EVID/netconsole_${name:-$h}.log"
            "$PAIRSH" on "$h" "$(host_cmd "$p" "$MAC")"
            echo "$h rc=$?"
        done
        ;;
    status)
        for h in $PAIR; do
            p=$(port_of "$h")
            MXFS_NETCONSOLE_PORT=$p "$LISTEN" status | head -1
            "$PAIRSH" on "$h" 'T=/sys/kernel/config/netconsole/clyde; echo "$(hostname) enabled=$(cat $T/enabled 2>/dev/null || echo none) port=$(cat $T/remote_port 2>/dev/null) console_loglevel=$(cut -f1 /proc/sys/kernel/printk)"'
        done
        ;;
    stop)
        for h in $PAIR; do
            p=$(port_of "$h")
            "$PAIRSH" on "$h" 'T=/sys/kernel/config/netconsole/clyde; [ -d $T ] && echo 0 > $T/enabled; dmesg -n 4; echo "$(hostname) netconsole disabled"'
            MXFS_NETCONSOLE_PORT=$p "$LISTEN" stop
        done
        ;;
    *)
        echo "usage: $0 start [evidence-dir]|status|stop" >&2
        exit 2
        ;;
esac
