#!/bin/bash
# mpath_up.sh — bring up / verify / tear down the 2-path dm-multipath
# presentation of the shared SCST LUN on N test nodes.
#
# This is the RUNTIME rig for the CAW-on-multipath FS matrix (the substrate
# that docs/condition4_multipath_scope.md characterised): SCST advertises the
# LUN on TWO portals (both br0 IPs, synthetic 2-path), every guest logs into
# both, and multipathd assembles /dev/mapper/mpatha (2 paths) on every node.
# The FS harness then runs with MXFS_DEV=/dev/mapper/mpatha.
#
# Usage:  scripts/mpath_up.sh {up|status|down} [N]
#   up N      — idempotent: host portals + guest logins + wait for mpatha
#               with 2 paths on test1..testN.  Escalates to a VM reboot for
#               nodes that cannot assemble in place.  Exit 0 iff all N OK.
#   status N  — one line per node (dev, path count), no changes.
#   down N    — guest logout + map flush, host 2nd-portal alias removed,
#               SCST target torn down (disk.img intact).
#
# Reboot self-heal: node records are set to node.startup=automatic, so a
# rebooted guest re-logs into both portals on boot and multipathd reassembles
# mpatha without this script.  Run `up` again anyway before a matrix run —
# it doubles as the readiness gate.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"

MODE="${1:-}"; N="${2:-2}"
case "$MODE" in up|status|down) ;; *) echo "usage: $0 {up|status|down} [N]" >&2; exit 2 ;; esac
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] && [ "$N" -le 32 ] || { echo "N out of range 1..32" >&2; exit 2; }

export MXFS_SSH_TIMEOUT=90
PORTAL1_IP="192.168.120.1"
PORTAL2_IP="192.168.120.2"
TGT="iqn.2026-05.local.mxfs:shared"
TROOT=/sys/kernel/scst_tgt/targets/iscsi
MPDEV="/dev/mapper/mpatha"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

# ---------------------------------------------------------------------------
host_up() {
    # 2nd portal IP on br0 (idempotent).
    ip addr show br0 | grep -q "inet ${PORTAL2_IP}/" \
        || $SUDO ip addr add "${PORTAL2_IP}/24" dev br0 \
        || { echo "HOST FAIL: cannot add ${PORTAL2_IP} to br0"; return 1; }

    # SCST target present, enabled, restricted to exactly our two portals?
    local want_setup=0
    if [ ! -d "$TROOT/$TGT" ]; then
        want_setup=1
    elif [ "$($SUDO cat "$TROOT/$TGT/enabled" 2>/dev/null)" != 1 ]; then
        want_setup=1
    else
        # SCST renders a multi-value attribute as allowed_portal, allowed_portal2, ...
        local portals
        portals=$($SUDO sh -c "cat $TROOT/$TGT/allowed_portal* 2>/dev/null" | tr -d ' ' | sort | tr '\n' ' ')
        echo "$portals" | grep -q "$PORTAL1_IP" && echo "$portals" | grep -q "$PORTAL2_IP" \
            || want_setup=1
    fi
    if [ "$want_setup" = 1 ]; then
        echo "--- host: (re)configuring SCST for 2 portals ---"
        "$SCRIPT_DIR/scst_wire_passthrough.sh" detach 32 >/dev/null 2>&1 || true
        "$SCRIPT_DIR/wire_vms.sh" detach 32 >/dev/null 2>&1 || true
        MXFS_SCST_PORTAL_IP="$PORTAL1_IP $PORTAL2_IP" "$SCRIPT_DIR/scst_setup.sh" setup >/dev/null \
            || { echo "HOST FAIL: scst_setup.sh setup"; return 1; }
    fi
    echo "--- host OK: portals $PORTAL1_IP + $PORTAL2_IP, target $TGT enabled ---"
}

# Node-side script: ensure 2 sessions + mpatha with >=2 paths.  Prints
# MPATH_OK <paths> on success, MPATH_FAIL <why> otherwise.
NODE_ENSURE='
set -u
MP=/dev/mapper/mpatha
mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
# The VM fleet was cloned from one image and many nodes still carry the
# image stock InitiatorName.  Two hosts sharing an initiator IQN collide
# in SCST session handling (same-IQN+ISID logins reinstate each other,
# dropping the victim'"'"'s nexus AND its PR registrations mid-run).
# Normalize to a per-host name; re-login below picks it up (nothing is
# mounted at mpath bring-up time, so the logout is safe).
WANT_IQN="iqn.2004-10.com.ubuntu:01:$(hostname)-mxfs-node"
CUR_IQN=$(sed -n "s/^InitiatorName=//p" /etc/iscsi/initiatorname.iscsi 2>/dev/null | tail -1)
if [ "$CUR_IQN" != "$WANT_IQN" ]; then
    echo "InitiatorName=$WANT_IQN" > /etc/iscsi/initiatorname.iscsi
    iscsiadm -m node -u all >/dev/null 2>&1
    systemctl restart iscsid open-iscsi >/dev/null 2>&1
    multipath -F >/dev/null 2>&1
fi
paths_ok() {
    [ -b "$MP" ] || return 1
    p=$(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")
    [ "${p:-0}" -ge 2 ]
}
if paths_ok; then
    # already assembled; make sure boot self-heal stays configured
    iscsiadm -m node -o update -n node.startup -v automatic >/dev/null 2>&1
    echo "MPATH_OK $(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")"
    exit 0
fi
mkdir -p /etc/multipath/conf.d
printf "defaults {\n    find_multipaths yes\n}\n" > /etc/multipath/conf.d/mxfs.conf
# a non-mpatha map or stale bindings would steal the mpatha name: reset the
# multipath state (safe here — nothing is mounted at bring-up time)
if [ ! -b "$MP" ]; then
    multipath -F >/dev/null 2>&1
    : > /etc/multipath/wwids 2>/dev/null
    rm -f /etc/multipath/bindings 2>/dev/null
fi
systemctl restart multipathd >/dev/null 2>&1
# enable, not just start: node.startup=automatic only self-heals a reboot if
# open-iscsi.service actually runs at boot (sess6: a power-cycled node came up
# with zero sessions because both services were disabled).
systemctl enable iscsid open-iscsi multipathd >/dev/null 2>&1
# default new discoveries to automatic too — a re-discovery otherwise resets
# records to iscsid.conf default (manual on Ubuntu), silently undoing the
# per-record update below (sess6: power-cycled node, 0 sessions, records=manual).
sed -i "s/^node.startup = manual/node.startup = automatic/" /etc/iscsi/iscsid.conf 2>/dev/null
iscsiadm -m discovery -t st -p PORTAL1:3260 >/dev/null 2>&1
iscsiadm -m discovery -t st -p PORTAL2:3260 >/dev/null 2>&1
iscsiadm -m node --login >/dev/null 2>&1
iscsiadm -m node -o update -n node.startup -v automatic >/dev/null 2>&1
iscsiadm -m session --rescan >/dev/null 2>&1
multipath >/dev/null 2>&1
for t in $(seq 1 15); do
    paths_ok && { echo "MPATH_OK $(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")"; exit 0; }
    sleep 2
    multipath >/dev/null 2>&1
done
s=$(iscsiadm -m session 2>/dev/null | grep -c "iqn.2026-05.local.mxfs")
echo "MPATH_FAIL sessions=$s dev=$( [ -b "$MP" ] && echo yes || echo no ) paths=$(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")"
exit 1
'

node_ensure() {  # node -> 0/1, prints status line
    local n="$1" out cmd
    cmd="${NODE_ENSURE//PORTAL1/$PORTAL1_IP}"
    cmd="${cmd//PORTAL2/$PORTAL2_IP}"
    out=$(ssh_node "$n" "$cmd" 2>&1 | grep -E '^MPATH_' | tail -1)
    if echo "$out" | grep -q '^MPATH_OK'; then
        echo "  $n: OK ($out)"
        return 0
    fi
    echo "  $n: RETRY-VIA-REBOOT ($out)"
    virsh -c qemu:///system destroy "$n" >/dev/null 2>&1
    sleep 2
    virsh -c qemu:///system start "$n" >/dev/null 2>&1
    local try
    for try in $(seq 1 25); do
        timeout 8 "$MXFS_SSH" "$n" "$MXFS_PASS" "true" >/dev/null 2>&1 && break
        sleep 3
    done
    out=$(ssh_node "$n" "$cmd" 2>&1 | grep -E '^MPATH_' | tail -1)
    if echo "$out" | grep -q '^MPATH_OK'; then
        echo "  $n: OK after reboot ($out)"
        return 0
    fi
    echo "  $n: FAIL ($out)"
    return 1
}

up() {
    host_up || return 1
    echo "--- guests: ensuring 2-path $MPDEV on ${NODES[*]} ---"
    local tmpd pids rc n
    tmpd=$(mktemp -d); pids=(); rc=0
    for n in "${NODES[@]}"; do
        ( node_ensure "$n" > "$tmpd/$n" 2>&1; echo $? > "$tmpd/$n.rc" ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    local ok=0
    for n in "${NODES[@]}"; do
        cat "$tmpd/$n"
        [ "$(cat "$tmpd/$n.rc" 2>/dev/null)" = 0 ] && ok=$((ok+1)) || rc=1
    done
    rm -rf "$tmpd"
    echo "=== MPATH UP: $ok/$N nodes have 2-path $MPDEV ==="
    return $rc
}

status() {
    local n
    for n in "${NODES[@]}"; do
        ssh_node "$n" '
            p=$(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")
            s=$(iscsiadm -m session 2>/dev/null | grep -c iqn.2026-05.local.mxfs)
            echo "  '"$n"': sessions=$s mpatha=$([ -b /dev/mapper/mpatha ] && echo yes || echo no) paths=${p:-0}"' \
            | grep -E '^  test' || echo "  $n: UNREACHABLE"
    done
}

down() {
    local n pids=()
    echo "--- guests: logout + flush ---"
    for n in "${NODES[@]}"; do
        ( ssh_node_quiet "$n" '
            umount /mnt/shared 2>/dev/null
            multipath -F 2>/dev/null
            iscsiadm -m node -u all 2>/dev/null
            iscsiadm -m node -o delete 2>/dev/null
            : > /etc/multipath/wwids 2>/dev/null
            rm -f /etc/multipath/bindings 2>/dev/null' ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    echo "--- host: scst teardown + drop 2nd portal ---"
    "$SCRIPT_DIR/scst_setup.sh" teardown
    ip addr show br0 | grep -q "inet ${PORTAL2_IP}/" \
        && $SUDO ip addr del "${PORTAL2_IP}/24" dev br0
    echo "=== MPATH DOWN ==="
}

case "$MODE" in
    up)     up ;;
    status) status ;;
    down)   down ;;
esac
