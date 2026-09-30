#!/bin/bash
#
# lab_clone_node.sh — make new lab nodes by cloning a verified platform node,
# each with its own identity, without an installer, an ISO or a mirror.
#
# WHY.  A platform's verification set grows (a 4-node release needs four nodes
# where the 2-node one had two), and the nodes it grows by must run EXACTLY the
# kernels the release claims for that platform: the ones the existing pair was
# verified on.  A fresh osimager build lands on whatever the distribution
# serves that day (a newer minor, a newer kernel) and then has to be pinned
# back, and it needs the install media — which on 2026-09-28 it could not get:
# the ISO share (/iso -> an NFS export) was unmounted, the AlmaLinux 9.7 ISO
# had left its mirror, and packer stopped at the dangling symlink.  A clone of
# a verified node carries its kernel, its packages, its firewall and SELinux
# state, its iSCSI node record for the platform target and its DKMS setup, so
# the new node differs from the verified one only in what this script rewrites.
#
# WHAT IT DOES, for <source> and each <clone> <ip> pair:
#  1. stops the source (ACPI, destroy past SHUTDOWN_S): virt-clone refuses a
#     running domain, and a copy of a live qcow2 is not consistent anyway.
#     Every clone of that source is taken in the same stop; the source is
#     restarted afterwards.
#  2. virt-clone: a full copy of the boot image, a new domain UUID, and a MAC
#     derived from the clone's address (52:54:00:c1:<3rd octet>:<4th octet>).
#  3. a dnsmasq reservation mac -> ip -> name in /etc/dnsmasq.d/lab.conf.
#     Every lab guest takes DHCP from clyde on br0, so the address a clone
#     answers on is decided here, before it ever boots, and stays fixed.
#  4. the identity rewrite, on the clone's image while it is off: the image is
#     attached with qemu-nbd, the root logical volume activated and mounted,
#     and these files rewritten THROUGH THEIR EXISTING INODE.  `sed -i` makes
#     a new inode, and a file created from this host (no SELinux policy) has
#     no label at all: an enforcing clone then boots with /etc/hosts and its
#     initiator name unlabeled_t (alma9-3/4, 2026-09-28).  tee into the file
#     keeps the inode, its label and its mode.
#       /etc/hostname                the clone's name
#       /etc/hosts                   the source's name and address -> the clone's
#       /etc/machine-id              emptied: systemd mints a new id at first boot
#       /var/lib/dbus/machine-id     a symlink to /etc/machine-id, where present
#       /etc/iscsi/initiatorname.iscsi  a new unique InitiatorName: SCST keys a
#                                    session on it, and the platform target's
#                                    ini_group admits initiators by it
#     SSH host keys are kept: the harness pins none, and a clone missing them
#     would boot with no sshd on the distributions that do not regenerate them.
#  5. starts the clone, waits for ssh at its address, prints its hostname,
#     kernel and initiator.  A Proxmox clone also loses the source's node
#     directory from the cluster configuration database (/etc/pve/nodes/<src>,
#     created again for the clone's name by pve-cluster at boot).
#
# AFTERWARDS (by hand): the lab file gets `addr <clone>=<ip>` and the platform's
# `nodes` line, then scripts/scst_platform_targets.sh setup admits the new
# initiators to the platform's LUN.
#
# Budgets (derived): ACPI shutdown of an idle lab guest measured 5-10 s ->
# SHUTDOWN_S=90 then destroy; a 64 GB virtual image holding ~6 GB copies in
# well under a minute on the NVMe -> no bound on the copy beyond virt-clone's
# own; a clone boots to ssh in ~20-40 s, a RHEL one with an iSCSI record it
# cannot yet use waits for that login -> BOOT_S=240.
#
# Usage: scripts/lab_clone_node.sh <source> <clone> <ip> [<clone> <ip> ...]
#   Needs passwordless sudo on the host for qemu-nbd, LVM, mount and dnsmasq.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
SHUTDOWN_S=90
BOOT_S=240
NBD=/dev/nbd7
DNSMASQ_CONF=/etc/dnsmasq.d/lab.conf
QEMU_ROOT=$(lab_get paths qemu_root 2>/dev/null); QEMU_ROOT=${QEMU_ROOT:-/home/steve/vms/qemu}

say() { echo "[$(date +%T)] $*"; }
die() { say "FATAL: $*"; exit 1; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect|System is booting up"; return "${PIPESTATUS[0]}"; }
state() { $VIRSH domstate "$1" 2>/dev/null | head -1; }
mac_of() { local ip=$1; printf '52:54:00:c1:%02x:%02x' "$(echo "$ip" | cut -d. -f3)" "$(echo "$ip" | cut -d. -f4)"; }

stop() {  # ACPI shutdown, destroy past the budget
    local d=$1 t0
    [ "$(state "$d")" = "shut off" ] && return 0
    $VIRSH shutdown "$d" >/dev/null 2>&1
    t0=$(date +%s)
    while [ "$(state "$d")" != "shut off" ]; do
        if [ $(( $(date +%s) - t0 )) -ge $SHUTDOWN_S ]; then
            say "$d: no ACPI shutdown within ${SHUTDOWN_S} s, destroying"
            $VIRSH destroy "$d" >/dev/null 2>&1
            break
        fi
        sleep 2
    done
}

reserve() {  # dnsmasq: mac -> ip -> name, replacing any earlier line for the name or the ip
    local mac=$1 ip=$2 name=$3
    sudo -n sed -i "/^dhcp-host=.*,${ip},/d; /^dhcp-host=.*,${name}\$/d" "$DNSMASQ_CONF"
    echo "dhcp-host=${mac},${ip},${name}" | sudo -n tee -a "$DNSMASQ_CONF" >/dev/null
    sudo -n systemctl restart dnsmasq || die "dnsmasq did not restart"
}

inplace() {  # <file> <sed-expr>: rewrite a file keeping its inode (label, mode, owner)
    local f=$1 expr=$2 new
    new=$(sudo -n sed "$expr" "$f") || return 1
    printf '%s\n' "$new" | sudo -n tee "$f" >/dev/null
}

nbd_detach() {
    local vg=$1
    sync
    [ -n "${MNT:-}" ] && { sudo -n umount "$MNT" 2>/dev/null; rmdir "$MNT" 2>/dev/null; }
    [ -n "$vg" ] && sudo -n vgchange -an "$vg" >/dev/null 2>&1
    sudo -n qemu-nbd --disconnect "$NBD" >/dev/null 2>&1
    sleep 1
}

rewrite_identity() {  # <image> <source> <src-ip> <clone> <ip>
    local img=$1 src=$2 srcip=$3 clone=$4 ip=$5 pvpart vg root iqn
    sudo -n modprobe nbd max_part=16 || die "no nbd module"
    sudo -n qemu-nbd --connect="$NBD" --format=qcow2 "$img" || die "qemu-nbd could not attach $img"
    sleep 1; sudo -n partprobe "$NBD" 2>/dev/null; sleep 1
    pvpart=$(lsblk -ln -o NAME,FSTYPE "$NBD" | awk '$2 == "LVM2_member" {print "/dev/"$1; exit}')
    [ -n "$pvpart" ] || { nbd_detach ""; die "$clone: no LVM physical volume on $img (the lab's nodes are all LVM-rooted)"; }
    sudo -n pvscan --cache "$pvpart" >/dev/null 2>&1
    vg=$(sudo -n pvs --noheadings -o vg_name "$pvpart" 2>/dev/null | tr -d ' ')
    [ -n "$vg" ] || { nbd_detach ""; die "$clone: $pvpart carries no volume group"; }
    sudo -n vgchange -ay "$vg" >/dev/null 2>&1 || { nbd_detach "$vg"; die "$clone: could not activate $vg"; }
    # the root volume is named root on Proxmox, AlmaLinux and Debian and
    # ubuntu-lv on Ubuntu: it is the volume that holds /etc/hostname
    MNT=$(mktemp -d)
    root=""
    for lv in root $(sudo -n lvs --noheadings -o lv_name "$vg" 2>/dev/null | tr -d ' ' | grep -vx root); do
        [ -e "/dev/$vg/$lv" ] || continue
        sudo -n mount "/dev/$vg/$lv" "$MNT" 2>/dev/null || continue
        [ -f "$MNT/etc/hostname" ] && { root=/dev/$vg/$lv; break; }
        sudo -n umount "$MNT"
    done
    [ -n "$root" ] || { nbd_detach "$vg"; die "$clone: no logical volume of $vg holds /etc/hostname"; }
    say "$clone: image attached, root $root ($vg) mounted at $MNT"

    # hostname and hosts, in place
    echo "$clone" | sudo -n tee "$MNT/etc/hostname" >/dev/null
    inplace "$MNT/etc/hosts" "s/\\b${src}\\b/${clone}/g; s/\\b${srcip//./\\.}\\b/${ip}/g" || { nbd_detach "$vg"; die "$clone: could not rewrite /etc/hosts"; }
    # a fresh machine id at first boot
    sudo -n sh -c ": > '$MNT/etc/machine-id'"
    if [ -e "$MNT/var/lib/dbus/machine-id" ] && [ ! -L "$MNT/var/lib/dbus/machine-id" ]; then
        sudo -n ln -sf /etc/machine-id "$MNT/var/lib/dbus/machine-id"
    fi
    # a unique iSCSI initiator, in the naming style the source used (the file
    # is root-only on Debian and Proxmox, so it is read with sudo too)
    if [ -f "$MNT/etc/iscsi/initiatorname.iscsi" ]; then
        case "$(sudo -n sed -n 's/^InitiatorName=//p' "$MNT/etc/iscsi/initiatorname.iscsi")" in
            iqn.1994-05.com.redhat:*) iqn="iqn.1994-05.com.redhat:${clone}-mxfs-node" ;;
            iqn.2004-10.com.ubuntu:*) iqn="iqn.2004-10.com.ubuntu:01:${clone}-mxfs-node" ;;
            *) iqn="iqn.1993-08.org.debian:01:$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')" ;;
        esac
        inplace "$MNT/etc/iscsi/initiatorname.iscsi" "s/^InitiatorName=.*/InitiatorName=${iqn}/" \
            || { nbd_detach "$vg"; die "$clone: could not rewrite the initiator name"; }
        say "$clone: InitiatorName=$iqn"
    fi
    say "$clone: hostname=$(cat "$MNT/etc/hostname") hosts: $(grep -a "$clone" "$MNT/etc/hosts" | tr '\n' '|')"
    nbd_detach "$vg"
}

[ $# -ge 3 ] && [ $(( ($# - 1) % 2 )) -eq 0 ] || { echo "usage: $0 <source> <clone> <ip> [<clone> <ip> ...]" >&2; exit 2; }
SRC=$1; shift
[ -n "$(state "$SRC")" ] || die "no such domain: $SRC"
SRCIP=$(lab_addr "$SRC") || die "no address for $SRC in the lab file"
SRCIMG=$($VIRSH domblklist "$SRC" --details | awk '$1 == "file" && $2 == "disk" {print $4; exit}')
[ -n "$SRCIMG" ] || die "$SRC has no file-backed disk"
was=$(state "$SRC")
say "$SRC ($SRCIP, $SRCIMG, $was): cloning $(( $# / 2 )) node(s)"

stop "$SRC"
CLONES=()
while [ $# -ge 2 ]; do
    clone=$1; ip=$2; shift 2
    mac=$(mac_of "$ip")
    dir="$QEMU_ROOT/$clone"
    [ -z "$(state "$clone")" ] || die "$clone already exists as a domain"
    mkdir -p "$dir"
    say "$clone: virt-clone from $SRC (mac $mac, image $dir/$clone)"
    virt-clone --connect qemu:///system --original "$SRC" --name "$clone" --file "$dir/$clone" --mac "$mac" >/dev/null \
        || die "virt-clone failed for $clone"
    # virt-clone copies the definition, and a rig VM's definition names its
    # serial log after the domain: a clone left naming the source's log cannot
    # start while the source runs, which holds the file open ("Cannot open
    # log file ... Device or resource busy", ubuntu2404-1..8, 2026-09-29)
    if $VIRSH dumpxml --inactive "$clone" | grep -q "<log file=.*$SRC"; then
        $VIRSH dumpxml --inactive "$clone" | sed "/<log file=/s#$SRC#$clone#g" > "$dir/$clone.xml" \
            && $VIRSH define "$dir/$clone.xml" >/dev/null \
            || die "$clone: could not give it a serial log of its own"
        say "$clone: serial log renamed for the clone"
    fi
    reserve "$mac" "$ip" "$clone"
    CLONES+=("$clone=$ip")
done
[ "$was" = running ] && { $VIRSH start "$SRC" >/dev/null && say "$SRC: started again"; }

for entry in "${CLONES[@]}"; do
    clone=${entry%%=*}; ip=${entry##*=}
    rewrite_identity "$QEMU_ROOT/$clone/$clone" "$SRC" "$SRCIP" "$clone" "$ip"
done

for entry in "${CLONES[@]}"; do
    clone=${entry%%=*}; ip=${entry##*=}
    $VIRSH start "$clone" >/dev/null || die "$clone did not start"
    t0=$(date +%s); up=0
    while [ $(( $(date +%s) - t0 )) -lt $BOOT_S ]; do
        on "$ip" 10 "echo up" | grep -q up && { up=1; break; }
        sleep 5
    done
    if [ $up = 1 ]; then
        say "$clone: up at $ip after $(( $(date +%s) - t0 )) s: $(on "$ip" 20 "echo \$(hostname) \$(uname -r) \$(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null) mid=\$(cat /etc/machine-id)" | tr '\n' ' ')"
        if on "$ip" 15 "test -d /etc/pve && echo pve" | grep -q pve; then
            on "$ip" 60 "rm -rf /etc/pve/nodes/$SRC; ls /etc/pve/nodes; systemctl is-active pve-cluster pveproxy pvedaemon | tr '\n' ' '; echo; pvesm status 2>&1 | head -3" | sed "s/^/  $clone: /"
        fi
    else
        say "$clone: NOT UP at $ip within ${BOOT_S} s (check the console: virsh console $clone)"
    fi
done
say "done: $(printf '%s ' "${CLONES[@]}")"
echo "lab file: addr $(printf '%s ' "${CLONES[@]}")"
