#!/bin/sh
# tests/mpath/pathstate.sh — the paths under a multipath map, as the node sees
# them right now.  Runs ON a node.
#
# One line per path, then a summary:
#   PATH sd=<sdX> portal=<ip> nic=<ethN|unbound> dm=<active|failed|..> chk=<ready|faulty|..> dev=<running|..> reads=<n> writes=<n>
#   PATHS map=<dm-N> total=<n> usable=<n>
# portal is the address the path's iSCSI session is connected to, which is
# what ties a path to a storage network.  nic is the interface the session is
# bound to; an unbound session follows the routing table, so it survives its
# own NIC by reconnecting through another, and is not a path that can fail.  reads/writes are the completed
# request counters of the path device (/sys/block/<sdX>/stat fields 1 and 5):
# a path whose counters move is carrying I/O, whatever multipathd calls it.
# usable counts the paths that are dm=active chk=ready.
#
# Usage: pathstate.sh [<map device>]     default: the device of the mxfs mount
#                                        at /mnt/shared, else /dev/mapper/mpatha
D=${1:-}
[ -n "$D" ] || D=$(awk '$2 == "/mnt/shared" && $3 == "mxfs" {print $1}' /proc/mounts | head -1)
[ -n "$D" ] || D=/dev/mapper/mpatha
m=$(basename "$(readlink -f "$D" 2>/dev/null)")
[ -d "/sys/block/$m/slaves" ] || { echo "PATHS map=none total=0 usable=0"; exit 0; }
total=0; usable=0
for s in /sys/block/"$m"/slaves/*; do
    [ -e "$s" ] || continue
    sd=$(basename "$s")
    sess=$(readlink -f "/sys/block/$sd/device" | grep -o 'session[0-9]*' | head -1)
    portal=$(cat /sys/class/iscsi_connection/connection"${sess#session}":0/persistent_address 2>/dev/null)
    st=$(multipathd show paths format "%d %t %T %o" 2>/dev/null | awk -v d="$sd" '$1 == d {print $2, $3, $4}')
    set -- $st
    r=$(awk '{print $1}' "/sys/block/$sd/stat" 2>/dev/null)
    w=$(awk '{print $5}' "/sys/block/$sd/stat" 2>/dev/null)
    host=$(readlink -f "/sys/block/$sd/device" | grep -o 'host[0-9]*' | head -1)
    nic=$(cat "/sys/class/iscsi_host/$host/netdev" 2>/dev/null)
    echo "PATH sd=$sd portal=${portal:-?} nic=${nic:-unbound} dm=${1:-?} chk=${2:-?} dev=${3:-?} reads=${r:-0} writes=${w:-0}"
    total=$((total + 1))
    [ "${1:-}" = active ] && [ "${2:-}" = ready ] && usable=$((usable + 1))
done
echo "PATHS map=$m total=$total usable=$usable"
