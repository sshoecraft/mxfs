#!/bin/bash
# san_net.sh — the storage networks a multipath attachment is tested on.
#
# A path is only a path if it can fail alone (docs/mpath-verification.md, T1
# and T2): every node gets one storage NIC per path, each NIC on its own
# layer-2 network and subnet, each network carrying one portal of the target,
# and none of them the network the cluster and the harness talk on.  This
# builds that on a libvirt host and is how a path is taken away and given back.
#
# The networks are named in the lab file (tools/mxfs_lab.sh), never here:
#   san a=<libvirt net>,<a.b.c> b=<libvirt net>,<a.b.c>
#       each an isolated libvirt network (no forwarding) whose bridge holds
#       <a.b.c>.1 on the host, the portal of that path, and whose DHCP hands
#       the nodes <a.b.c>.10-250 with no router and no DNS
#   storage ... mpath=<a.b.c>.1,<a.b.c>.1
#       the portals a multipath allocation logs in on (tools/lun_pool.sh)
#
# Usage:
#   scripts/san_net.sh host                 define and start the networks (idempotent)
#   scripts/san_net.sh attach <node>...     give each node a NIC on every network
#                                           (live and persistent) and have it take
#                                           an address on each; verifies it reaches
#                                           every portal over a NIC of its own
#   scripts/san_net.sh status [<node>...]   networks, and per node: NIC, link, address
#   scripts/san_net.sh link <node> <a|b> <up|down>
#                                           the cable of that node's NIC on that
#                                           network, from the hypervisor: the node
#                                           sees carrier loss and nothing else
#   scripts/san_net.sh mute <node> <a|b> <on|off>
#                                           one direction of that cable: every
#                                           frame TOWARD the node on that NIC is
#                                           dropped while the node's own frames
#                                           still arrive.  The target goes on
#                                           receiving and executing the node's
#                                           commands and the node hears none of
#                                           the answers (netem on the NIC's tap)
#   scripts/san_net.sh mac <node> <a|b>     that NIC's MAC
#
# A node's NIC on network a/b carries a MAC derived from its name, so `link`
# finds it without asking the node, which may be the thing that is broken.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
V="virsh -c qemu:///system"
die() { echo "san_net: $*" >&2; exit 1; }
ssh_n() { timeout "${3:-30}" "$SSH" "$(lab_addr "$1")" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you'; }

NETS="a b"
net_name() { local v; v=$(lab_need san "$1") || exit 2; echo "${v%%,*}"; }
net_prefix() { local v; v=$(lab_need san "$1") || exit 2; echo "${v##*,}"; }
# 52:54:00:<a1|b1>:<two bytes of the node name's checksum>: stable per node
# and per network, and outside the range the rig's first NICs use
mac_of() {  # <node> <a|b>
    local h
    h=$(printf '%s' "$1" | cksum | awk '{printf "%04x", $1 % 65536}')
    echo "52:54:00:${2}1:${h:0:2}:${h:2:2}"
}

cmd_host() {
    local k name pre xml
    for k in $NETS; do
        name=$(net_name "$k"); pre=$(net_prefix "$k")
        if ! $V net-info "$name" >/dev/null 2>&1; then
            xml=$(mktemp)
            cat > "$xml" <<EOF
<network>
  <name>$name</name>
  <bridge name='mxsan$k' stp='off' delay='0'/>
  <ip address='$pre.1' netmask='255.255.255.0'>
    <dhcp><range start='$pre.10' end='$pre.250'/></dhcp>
  </ip>
</network>
EOF
            $V net-define "$xml" >/dev/null || die "cannot define network $name"
            unlink "$xml"
        fi
        $V net-autostart "$name" >/dev/null 2>&1
        $V net-info "$name" 2>/dev/null | grep -q '^Active: *yes' || $V net-start "$name" >/dev/null || die "cannot start network $name"
        ip -4 addr show "mxsan$k" 2>/dev/null | grep -q "inet $pre.1/" || die "network $name is up but mxsan$k does not hold $pre.1"
        echo "san_net: $k = $name on mxsan$k, portal $pre.1"
    done
}

# What the node runs once its NICs exist: every NIC that is not the one the
# default route uses takes an address by DHCP, ignoring any route or DNS the
# lease carries, and is optional at boot so a node whose path is down still
# boots.  netplan where the platform has it, NetworkManager otherwise.
NODE_CONFIG='
    def=$(ip -4 route show default | sed -n "s/.* dev \([^ ]*\).*/\1/p" | head -1)
    nics=$(ls /sys/class/net | while read i; do
        [ "$i" = lo ] || [ "$i" = "$def" ] && continue
        [ -e /sys/class/net/$i/device ] || continue
        case " MACS " in *" $(cat /sys/class/net/$i/address) "*) echo $i ;; esac
    done)
    nics=$(echo $nics)
    [ "$(echo $nics | wc -w)" = NNICS ] || { echo "CONFIG_FAIL storage NICs seen: [$nics]"; exit 0; }
    if [ -d /etc/netplan ] && command -v netplan >/dev/null 2>&1; then
        f=/etc/netplan/60-mxfs-san.yaml
        { echo "network:"; echo "  version: 2"; echo "  ethernets:"
          for i in $nics; do
              echo "    $i:"; echo "      dhcp4: true"; echo "      optional: true"
              echo "      dhcp4-overrides: {use-routes: false, use-dns: false}"
          done; } > $f.new
        chmod 600 $f.new
        cmp -s $f.new $f 2>/dev/null && rm -f $f.new || { mv $f.new $f; netplan apply >/dev/null 2>&1; }
    elif command -v nmcli >/dev/null 2>&1; then
        for i in $nics; do
            nmcli -t -f NAME con show | grep -qx "mxfs-san-$i" \
                || nmcli con add type ethernet ifname $i con-name mxfs-san-$i ipv4.method auto ipv4.never-default yes ipv4.ignore-auto-dns yes ipv6.method disabled connection.autoconnect yes >/dev/null 2>&1
            nmcli con up mxfs-san-$i >/dev/null 2>&1
        done
    else
        echo "CONFIG_FAIL no netplan and no NetworkManager on this node"; exit 0
    fi
    for t in $(seq 1 20); do
        ok=0
        for p in PORTALS; do
            d=$(ip -4 route get $p 2>/dev/null | sed -n "s/.* dev \([^ ]*\).*/\1/p" | head -1)
            case " $nics " in *" $d "*) ping -c1 -W1 -I $d $p >/dev/null 2>&1 && ok=$((ok + 1)) ;; esac
        done
        [ "$ok" = NNICS ] && break
        sleep 1
    done
    echo "CONFIG_$([ "$ok" = NNICS ] && echo OK || echo FAIL) nics=[$(echo $nics)] portals_reached=$ok/NNICS default=$def"'

cmd_attach() {
    [ "$#" -ge 1 ] || die "usage: attach <node>..."
    local n k name mac macs portals snippet td bad="" nn
    nn=$(echo $NETS | wc -w)
    portals=$(for k in $NETS; do echo -n "$(net_prefix "$k").1 "; done)
    td=$(mktemp -d)
    for n in "$@"; do
        macs=""
        for k in $NETS; do
            name=$(net_name "$k"); mac=$(mac_of "$n" "$k"); macs="$macs $mac"
            if ! $V domiflist "$n" --inactive 2>/dev/null | grep -qi "$mac"; then
                $V attach-interface "$n" network "$name" --model virtio --mac "$mac" --config >/dev/null \
                    || { bad="$bad $n(persistent NIC on $name)"; continue; }
            fi
            if [ "$($V domstate "$n" 2>/dev/null)" = running ] && ! $V domiflist "$n" 2>/dev/null | grep -qi "$mac"; then
                $V attach-interface "$n" network "$name" --model virtio --mac "$mac" --live >/dev/null \
                    || bad="$bad $n(live NIC on $name)"
            fi
        done
        snippet=${NODE_CONFIG//MACS/$macs}; snippet=${snippet//NNICS/$nn}; snippet=${snippet//PORTALS/$portals}
        ( sleep 3; ssh_n "$n" "$snippet" 90 > "$td/$n" ) &
    done
    wait
    for n in "$@"; do
        line=$(grep -a '^CONFIG_' "$td/$n" 2>/dev/null | tail -1)
        echo "$n: ${line:-no answer}"
        case "$line" in CONFIG_OK*) ;; *) bad="$bad $n" ;; esac
    done
    rm -rf "$td"
    [ -z "$bad" ] || die "attach FAILED:$bad"
}

cmd_status() {
    local k n mac
    for k in $NETS; do
        echo "net $k: $(net_name "$k") $($V net-info "$(net_name "$k")" 2>/dev/null | awk '/^Active/{print "active=" $2}') host=$(ip -br -4 addr show "mxsan$k" 2>/dev/null | awk '{print $3}')"
    done
    for n in "$@"; do
        for k in $NETS; do
            mac=$(mac_of "$n" "$k")
            echo "$n $k mac=$mac link=$($V domif-getlink "$n" "$mac" 2>/dev/null | awk '{print $2}') addr=$($V net-dhcp-leases "$(net_name "$k")" 2>/dev/null | awk -v m="$mac" '$3 == m {print $5}' | tail -1)"
        done
    done
}

cmd_link() {
    local n=${1:?node} k=${2:?a|b} st=${3:?up|down}
    case "$k" in a|b) ;; *) die "network is a or b" ;; esac
    case "$st" in up|down) ;; *) die "state is up or down" ;; esac
    $V domif-setlink "$n" "$(mac_of "$n" "$k")" "$st" >/dev/null || die "cannot set $n's NIC on $k $st"
    echo "san_net: $n $k $st $(date -u +%FT%T.%3NZ)"
}

cmd_mute() {
    local n=${1:?node} k=${2:?a|b} st=${3:?on|off} tap
    case "$k" in a|b) ;; *) die "network is a or b" ;; esac
    tap=$($V domiflist "$n" 2>/dev/null | awk -v m="$(mac_of "$n" "$k")" 'tolower($5) == m {print $1}')
    [ -n "$tap" ] || die "no live NIC of $n on network $k"
    case "$st" in
        on)  sudo -n tc qdisc replace dev "$tap" root netem loss 100% || die "cannot mute $tap" ;;
        off) sudo -n tc qdisc del dev "$tap" root 2>/dev/null; sudo -n tc qdisc show dev "$tap" | grep -q netem && die "$tap is still muted" ;;
        *) die "state is on or off" ;;
    esac
    echo "san_net: $n $k mute $st ($tap) $(date -u +%FT%T.%3NZ)"
}

case "${1:-}" in
    host)   cmd_host ;;
    mute)   shift; cmd_mute "$@" ;;
    attach) shift; cmd_attach "$@" ;;
    status) shift; cmd_status "$@" ;;
    link)   shift; cmd_link "$@" ;;
    mac)    mac_of "${2:?node}" "${3:?a|b}" ;;
    *) sed -n '2,40p' "$0"; exit 2 ;;
esac
