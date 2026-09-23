#!/bin/bash
# lio_bench_target.sh — a RESTARTABLE iSCSI target on a bench VM, for the
# laps whose subject is the target's own behaviour across a restart of its
# service or a crash of its host (tests/target_restart_pr.sh, the fence-matrix
# ruling's target-restart tranche).  The 2/tcp rig's target is never restarted
# for tests, so those laps run against this one, declared in data/rigs.json
# under its own tag.
#
# The target is LIO (targetcli-fb) on a libvirt VM on this host, exporting one
# block backstore over a whole virtio disk as one iSCSI LUN with explicit ACLs
# for the cluster's node initiators.  Everything is driven from this host over
# the lab ssh chokepoint (tools/mxfs_sshpass.sh); nothing runs on this host's
# own kernel, so the host's SCST/LIO state is untouched.
#
# WHY THE UNIT SERIAL IS FIXED: LIO derives the LUN's NAA identifier from the
# backstore's VPD unit serial, and targetcli generates a random one per create.
# data/rigs.json declares the LUN by that identifier (lun_wwid) and every
# harness refuses a device that does not carry it, so a teardown and re-setup
# must produce the SAME identifier or the declaration goes stale.  The serial
# is set on the storage object before it is exported (the kernel refuses the
# write once a LUN maps it), and it is the one thing this script insists on.
#
# WHY THE DATABASE DIRECTORIES ARE CREATED HERE: LIO honours the APTPL bit an
# initiator sets on PERSISTENT RESERVE OUT by writing the whole PR table to
# <dbroot>/pr/aptpl_<unit serial> on the target host, from which
# target.service restores it at start.  The kernel opens that file with
# O_CREAT but never creates the directory, and the dbroot targetcli-fb
# configures on this distribution (/etc/rtslib-fb-target, read from
# /sys/kernel/config/target/dbroot) ships with neither pr/ nor alua/.  With
# the directory absent every REGISTER that carries APTPL adds the registration
# and THEN fails on the metadata write ("Could not update APTPL" in the
# target's log), so the initiator sees an error, PTPL_A stays 0, the key is
# left in the table, and MXFS's next mount refuses on a predecessor key it
# never owned (measured 2026-09-22, tests/evidence/20260922T181531Z_aptpl_s160a).
# So setup creates both directories under the dbroot the target reports, and
# refuses to continue if it cannot.  tests/pr_aptpl_probe.sh measures that
# persistence is then both capable and active; this script only provides the
# target.
#
# Usage:
#   tools/lio_bench_target.sh setup             # backstore, target, ACLs, portal, service enabled
#   tools/lio_bench_target.sh status            # targetcli ls and the service state
#   tools/lio_bench_target.sh teardown          # remove the target and backstore (the disk is left)
#   tools/lio_bench_target.sh login  <node>...  # discover, log in, node.startup automatic
#   tools/lio_bench_target.sh logout <node>...  # log out and forget the node record
#   tools/lio_bench_target.sh wwid   <node>     # the LUN's identifier as that node reads it
#
# Env: MXFS_BENCH_TARGET (test32)   the VM that is the target host
#      MXFS_BENCH_DEV    (/dev/vdb) the whole disk exported, ON that VM
#      MXFS_BENCH_BSNAME (mxfsbench)
#      MXFS_BENCH_IQN    (iqn.2026-09.mxfs.bench:lun0)
#      MXFS_BENCH_SERIAL (a fixed uuid, below)
#      MXFS_BENCH_PORT   (3260)
#      MXFS_BENCH_INITIATORS  space-separated IQNs; default: read from
#                             /etc/iscsi/initiatorname.iscsi on MXFS_NODE_LIST
#                             (test1,test2)
#
# Every remote step is bounded: the target VM answers in well under a second
# when it is up, and a bound of 40 s on a whole targetcli batch is a failure of
# the VM, not slack.
set -u
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
T=${MXFS_BENCH_TARGET:-test32}
DEV=${MXFS_BENCH_DEV:-/dev/vdb}
BS=${MXFS_BENCH_BSNAME:-mxfsbench}
IQN=${MXFS_BENCH_IQN:-iqn.2026-09.mxfs.bench:lun0}
SERIAL=${MXFS_BENCH_SERIAL:-4d584653-4245-4e43-482d-4c554e303030}
PORT=${MXFS_BENCH_PORT:-3260}
NODES=${MXFS_NODE_LIST:-test1,test2}

say()  { echo "$@"; }
fail() { echo "LIO_BENCH_FAIL: $*" >&2; exit 1; }
tgt()  { timeout "$1" $SSH "$T" "$2" 2>&1; }   # <bound> <command> on the target VM

target_addr() {   # the address the nodes reach the target VM on: its first global IPv4
    tgt 15 "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1" | grep -a '^[0-9]' | head -1
}

dbroot() {   # the directory LIO writes its APTPL and ALUA metadata under, as the kernel reports it
    tgt 15 "cat /sys/kernel/config/target/dbroot" | grep -a '^/' | head -1
}

dbroot_dirs() {
    local root
    root=$(dbroot); [ -n "$root" ] || fail "no dbroot in /sys/kernel/config/target on $T (is target_core_mod loaded?)"
    tgt 20 "mkdir -p '$root/pr' '$root/alua' && test -d '$root/pr' && test -d '$root/alua' && echo DBROOT_OK" \
        | grep -aq '^DBROOT_OK' || fail "could not create $root/pr and $root/alua on $T; APTPL cannot activate without them"
    say "dbroot $root: pr/ and alua/ present"
}

initiators() {
    if [ -n "${MXFS_BENCH_INITIATORS:-}" ]; then echo "$MXFS_BENCH_INITIATORS"; return 0; fi
    local n out=""
    for n in ${NODES//,/ }; do
        local i
        i=$(timeout 15 $SSH "$n" "sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi" 2>/dev/null | grep -a '^iqn\.' | head -1)
        [ -n "$i" ] || fail "no initiator name from $n"
        out="$out $i"
    done
    echo "${out# }"
}

setup() {
    local addr inits i
    addr=$(target_addr); [ -n "$addr" ] || fail "no address on $T"
    inits=$(initiators)
    say "target host $T at $addr, disk $DEV, backstore $BS, iqn $IQN, initiators: $inits"
    tgt 20 "test -b $DEV && echo DEV_OK" | grep -aq '^DEV_OK' || fail "$DEV is not a block device on $T"
    # the persistent-reservation database directory under the kernel's dbroot,
    # which nothing else creates and without which APTPL never activates
    dbroot_dirs
    # the backstore, with the fixed serial written before anything exports it
    if ! tgt 40 "targetcli /backstores/block ls" | grep -aq "o- $BS "; then
        tgt 40 "targetcli /backstores/block create name=$BS dev=$DEV" | grep -aq 'Created block storage object' \
            || fail "backstore create failed"
        tgt 20 "echo -n '$SERIAL' > /sys/kernel/config/target/core/iblock_*/$BS/wwn/vpd_unit_serial && echo SERIAL_OK" \
            | grep -aq '^SERIAL_OK' || fail "could not set the unit serial"
        say "backstore created: block/$BS -> $DEV, unit serial $SERIAL"
    else
        say "backstore already present: block/$BS"
    fi
    local have
    have=$(tgt 20 "cat /sys/kernel/config/target/core/iblock_*/$BS/wwn/vpd_unit_serial" | grep -ao "$SERIAL" | head -1)
    [ "$have" = "$SERIAL" ] || fail "backstore $BS carries a different unit serial than the declared one ($SERIAL); tear it down and set up again"
    # the target, its TPG, the LUN, explicit ACLs, one portal
    if ! tgt 40 "targetcli /iscsi ls" | grep -aq "o- $IQN "; then
        tgt 40 "targetcli /iscsi create $IQN" | grep -aq 'Created target' || fail "target create failed"
        say "target created: $IQN"
    fi
    local tpg="/iscsi/$IQN/tpg1"
    tgt 40 "targetcli $tpg/luns ls" | grep -aq "block/$BS" \
        || { tgt 40 "targetcli $tpg/luns create /backstores/block/$BS" | grep -aq 'Created LUN' || fail "LUN mapping failed"; }
    tgt 40 "targetcli $tpg set attribute authentication=0 generate_node_acls=0 cache_dynamic_acls=0 demo_mode_write_protect=0" >/dev/null
    for i in $inits; do
        tgt 40 "targetcli $tpg/acls ls" | grep -aq "o- $i " \
            || { tgt 40 "targetcli $tpg/acls create $i" | grep -aq 'Created Node ACL' || fail "ACL for $i failed"; }
    done
    # targetcli's portal default is the wildcard address on 3260; delete it so the
    # portal is the one address the nodes reach and the service binds nothing else
    tgt 40 "targetcli $tpg/portals ls" | grep -aq "0.0.0.0:$PORT" && tgt 40 "targetcli $tpg/portals delete 0.0.0.0 $PORT" >/dev/null
    tgt 40 "targetcli $tpg/portals ls" | grep -aq "$addr:$PORT" \
        || { tgt 40 "targetcli $tpg/portals create $addr $PORT" | grep -aq 'Created network portal' || fail "portal create failed"; }
    tgt 40 "targetcli saveconfig" | grep -aq 'Configuration saved' || fail "saveconfig failed"
    tgt 40 "systemctl enable target >/dev/null 2>&1; systemctl start target; systemctl is-active target" | grep -aq '^active' \
        || fail "target.service is not active on $T"
    # The restart lap runs the target host's own commands, named in the lab
    # secrets store as restart_cmd= and reboot_cmd= under this rig's tag; that
    # store holds one token per field, so a command with arguments is a script
    # on the target host.  These are those scripts.
    tgt 30 "printf '#!/bin/sh\nexec systemctl restart target\n' > /usr/local/sbin/mxfs-target-restart
            printf '#!/bin/sh\nexec systemctl reboot\n' > /usr/local/sbin/mxfs-target-reboot
            chmod 755 /usr/local/sbin/mxfs-target-restart /usr/local/sbin/mxfs-target-reboot && echo HELPERS_OK" \
        | grep -aq '^HELPERS_OK' || fail "could not install the restart helpers on $T"
    say "LIO_BENCH_OK target=$T portal=$addr:$PORT iqn=$IQN backstore=$BS serial=$SERIAL"
}

status() {
    local root
    root=$(dbroot)
    tgt 40 "systemctl is-enabled target; systemctl is-active target; targetcli ls; echo dbroot=${root:-unknown}; ls -la '${root:-/var/target}/pr' 2>&1"
}

teardown() {
    tgt 40 "targetcli /iscsi delete $IQN" | grep -a 'Deleted' || true
    tgt 40 "targetcli /backstores/block delete $BS" | grep -a 'Deleted' || true
    tgt 40 "targetcli saveconfig" | grep -a 'saved' || true
    say "LIO_BENCH_TEARDOWN_OK ($DEV on $T left intact)"
}

login() {
    local addr n
    addr=$(target_addr); [ -n "$addr" ] || fail "no address on $T"
    for n in "$@"; do
        timeout 60 $SSH "$n" "iscsiadm -m discovery -t sendtargets -p $addr:$PORT | grep -a '$IQN' || exit 3
            iscsiadm -m node -T $IQN -p $addr:$PORT -o update -n node.startup -v automatic
            iscsiadm -m session 2>/dev/null | grep -aq ' $IQN ' || iscsiadm -m node -T $IQN -p $addr:$PORT --login
            for i in 1 2 3 4 5 6 7 8 9 10; do ls /dev/disk/by-id/ 2>/dev/null | grep -aq wwn-0x6001405 && break; sleep 1; done
            echo LOGIN_DONE sessions=\$(iscsiadm -m session 2>/dev/null | grep -ac ' $IQN ')" 2>&1 | grep -a 'LOGIN_DONE\|rror\|fail' | sed "s/^/$n: /"
    done
}

logout() {
    local addr n
    addr=$(target_addr); [ -n "$addr" ] || fail "no address on $T"
    for n in "$@"; do
        timeout 60 $SSH "$n" "iscsiadm -m node -T $IQN -p $addr:$PORT --logout; iscsiadm -m node -T $IQN -p $addr:$PORT -o delete; echo LOGOUT_DONE" 2>&1 | tail -1 | sed "s/^/$n: /"
    done
}

wwid() {
    local n=${1:?node}
    timeout 30 $SSH "$n" "for b in /sys/block/sd*; do m=\$(cat \$b/device/model 2>/dev/null | tr -d ' '); [ \"\$m\" = $BS ] || continue; echo \"\$(basename \$b) wwid=\$(cat \$b/device/wwid) vendor=\$(cat \$b/device/vendor | tr -d ' ') model=\$m rev=\$(cat \$b/device/rev | tr -d ' ') cache=\$(cat \$b/device/scsi_disk/*/cache_type 2>/dev/null)\"; done" 2>&1 | grep -a wwid=
}

case "${1:-}" in
    setup)    setup ;;
    status)   status ;;
    teardown) teardown ;;
    login)    shift; login "$@" ;;
    logout)   shift; logout "$@" ;;
    wwid)     shift; wwid "$@" ;;
    *) echo "usage: $0 {setup|status|teardown|login <node>...|logout <node>...|wwid <node>}" >&2; exit 2 ;;
esac
