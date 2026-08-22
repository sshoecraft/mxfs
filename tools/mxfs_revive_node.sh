#!/bin/bash
#
# mxfs_revive_node.sh — rebuild a rig VM whose libvirt domain is permanently
# wedged, WITHOUT rebooting clyde (RULE 2).
#
# WHY THIS EXISTS
# ---------------
# clyde's host kernel has been observed corrupting ext4 page-cache state (see
# ccmemory `clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377`).  When it
# oopses inside ext4_buffered_write_iter the dying task never releases the
# qcow2 file's inode rwsem, so:
#
#   - every later writer to that image wedges in uninterruptible D sleep,
#   - the qemu main thread goes zombie and is never reaped,
#   - `virsh destroy <dom>` times out (rc=124) and the domain sits forever in
#     state "in shutdown",
#   - the image file can never be written or unlinked again.
#
# The libvirt domain NAME is therefore burned.  Recovery = a NEW domain name
# (testNr) on a NEW disk file, reusing the dead node's MAC so DHCP/DNS hand the
# name testN straight back.  Node hostnames on this rig resolve through the
# network's DNS from the DHCP hostname — clyde's /etc/hosts has no testN
# entries — so the address may legitimately change and nothing cares.
#
# Two modes:
#   self   the dead node's own image is still READABLE.  Clone it; the guest
#          identity is already correct, nothing to rewrite.  (Preferred.)
#   donor  the image is unreadable/absent.  Clone a LIVE node, then rewrite
#          hostname / iSCSI IQN / machine-id / ssh host keys inside the clone.
#
# RULE 0: every step is bounded.  RULE 2b: no rm on a variable or glob path.
# RULE 2c: no `pgrep -f`, no unbounded dmsetup/umount.
#
# Usage:
#   tools/mxfs_revive_node.sh self  <deadN>
#   tools/mxfs_revive_node.sh donor <deadN> <liveDonorN>
#
#   e.g.  tools/mxfs_revive_node.sh self  test5
#         tools/mxfs_revive_node.sh donor test4 test6
#
set -u

VMROOT=/home/steve/vms/qemu
NBD=/dev/nbd0
MNT=/mnt/mxfs_revive
SSH="$(dirname "$0")/mxfs_sshpass.sh"

die()  { echo "REVIVE FAIL: $*" >&2; exit 1; }
step() { echo "--- $*"; }

MODE="${1:-}"
DEAD="${2:-}"
DONOR="${3:-}"

case "$MODE" in
    self)  [ -n "$DEAD" ] || die "usage: $0 self <deadN>" ;;
    donor) [ -n "$DEAD" ] && [ -n "$DONOR" ] || die "usage: $0 donor <deadN> <liveDonorN>" ;;
    *)     die "mode must be 'self' or 'donor'" ;;
esac

NEWDOM="${DEAD}r"
NEWDIR="$VMROOT/$NEWDOM"
NEWIMG="$NEWDIR/$NEWDOM"

sudo virsh dominfo "$NEWDOM" >/dev/null 2>&1 && \
    die "domain $NEWDOM already exists — pick it up by hand, this script will not overwrite it"

# ---------------------------------------------------------------- identity ---
# The dead domain's MAC is what gets the address back.  Read it from the stuck
# domain if libvirt still knows it, else from the on-disk XML.
MAC=$(sudo virsh dumpxml "$DEAD" 2>/dev/null | sed -n "s/.*<mac address='\([^']*\)'.*/\1/p" | head -1)
[ -n "$MAC" ] || MAC=$(sed -n "s/.*<mac address='\([^']*\)'.*/\1/p" "$VMROOT/$DEAD/$DEAD.xml" 2>/dev/null | head -1)
[ -n "$MAC" ] || die "could not determine $DEAD's MAC address"
step "$DEAD MAC = $MAC  -> new domain $NEWDOM"

# ------------------------------------------------------------------- source ---
if [ "$MODE" = self ]; then
    SRCIMG="$VMROOT/$DEAD/$DEAD"
    [ -r "$SRCIMG" ] || die "$SRCIMG is not readable — use donor mode"
else
    SRCIMG="$VMROOT/$DONOR/$DONOR"
    [ -r "$SRCIMG" ] || die "$SRCIMG is not readable"

    # The donor must be quiesced or the clone is crash-consistent garbage.
    # These guests IGNORE ACPI `virsh shutdown`; halt from inside, then destroy.
    step "quiescing donor $DONOR"
    timeout 30 "$SSH" "$DONOR" "sync; (sleep 1; systemctl poweroff -i) >/dev/null 2>&1 &" >/dev/null 2>&1
    for i in $(seq 1 40); do
        timeout 5 ping -c1 -W2 "$DONOR" >/dev/null 2>&1 || break
        sleep 3
    done
    timeout 60 sudo virsh destroy "$DONOR" >/dev/null 2>&1
    [ "$(sudo virsh domstate "$DONOR" 2>/dev/null)" = "shut off" ] || \
        die "donor $DONOR did not stop — refusing to clone a live image"
fi

# -------------------------------------------------------------------- clone ---
# O_DIRECT both ways (-T none -t none).  A buffered copy of a multi-GB image
# drives kswapd hard, and on this host that is exactly what trips the ext4
# oops this script exists to recover from.
step "cloning $SRCIMG -> $NEWIMG (O_DIRECT)"
sudo mkdir -p "$NEWDIR" || die "mkdir $NEWDIR"
timeout 900 sudo qemu-img convert -T none -t none -O qcow2 "$SRCIMG" "$NEWIMG" \
    || die "qemu-img convert failed"

if [ "$MODE" = donor ]; then
    step "restarting donor $DONOR"
    sudo virsh start "$DONOR" >/dev/null 2>&1 || echo "WARN: donor $DONOR did not restart"
fi

# ----------------------------------------------------------------- identity ---
if [ "$MODE" = donor ]; then
    step "rewriting guest identity in the clone -> $DEAD"
    sudo modprobe nbd max_part=8 || die "modprobe nbd"
    timeout 60 sudo qemu-nbd --connect="$NBD" -f qcow2 "$NEWIMG" || die "qemu-nbd connect"
    sleep 3
    sudo partx -u "$NBD" >/dev/null 2>&1

    LV=/dev/ubuntu-vg/ubuntu-lv          # these images are curtin/LVM installs
    sudo mkdir -p "$MNT"
    timeout 60 sudo mount "$LV" "$MNT" || {
        timeout 60 sudo qemu-nbd --disconnect "$NBD" >/dev/null 2>&1
        die "mount $LV failed"
    }

    echo "$DEAD" | sudo tee "$MNT/etc/hostname" >/dev/null
    echo "InitiatorName=iqn.2004-10.com.ubuntu:01:${DEAD}-mxfs-node" \
        | sudo tee "$MNT/etc/iscsi/initiatorname.iscsi" >/dev/null
    sudo truncate -s 0 "$MNT/etc/machine-id"
    sudo rm -f "$MNT/var/lib/dbus/machine-id"

    # Fresh ssh host keys.  cloud-init is DISABLED on these images
    # (/etc/cloud/cloud-init.disabled), so nothing else would regenerate them
    # and sshd refuses to start without any.
    for k in rsa ecdsa ed25519; do
        sudo rm -f "$MNT/etc/ssh/ssh_host_${k}_key" "$MNT/etc/ssh/ssh_host_${k}_key.pub"
        sudo ssh-keygen -q -t "$k" -N '' -f "$MNT/etc/ssh/ssh_host_${k}_key" \
            || die "ssh-keygen $k"
    done

    echo "    hostname   : $(sudo cat "$MNT/etc/hostname")"
    echo "    initiator  : $(sudo cat "$MNT/etc/iscsi/initiatorname.iscsi")"

    timeout 60 sudo umount "$MNT" || die "umount $MNT"
    sudo vgchange -an ubuntu-vg >/dev/null 2>&1
    timeout 60 sudo qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || echo "WARN: nbd disconnect"
fi

# ------------------------------------------------------------------- define ---
# The stock per-VM XMLs are 674-byte hand-written files with NO explicit <mac>;
# we must add one so the address comes back.
step "defining domain $NEWDOM"
sudo tee "$NEWDIR/$NEWDOM.xml" >/dev/null <<EOF
<domain type='kvm'>
  <name>$NEWDOM</name>
  <memory unit='MiB'>4096</memory>
  <vcpu placement='static'>4</vcpu>
  <cpu mode='host-passthrough'/>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$NEWIMG'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'/>
    <interface type='bridge'>
      <source bridge='br0'/>
      <mac address='$MAC'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'/>
    <console type='pty'/>
  </devices>
</domain>
EOF

sudo virsh define "$NEWDIR/$NEWDOM.xml" >/dev/null || die "virsh define"
sudo virsh start "$NEWDOM" >/dev/null || die "virsh start $NEWDOM"

# -------------------------------------------------------------------- verify ---
step "waiting for $DEAD to answer"
UP=0
for i in $(seq 1 36); do
    if timeout 5 ping -c1 -W2 "$DEAD" >/dev/null 2>&1; then UP=1; break; fi
    sleep 5
done
[ "$UP" = 1 ] || die "$DEAD did not answer ping within 180s of start"

OUT=$(timeout 30 "$SSH" "$DEAD" \
    "hostname; cat /etc/iscsi/initiatorname.iscsi; ip -4 addr show eth0 | grep -o 'inet [0-9.]*'" 2>/dev/null | tail -3)
echo "$OUT"

echo "$OUT" | grep -qx "$DEAD" || die "$DEAD came up with the wrong hostname"
echo "$OUT" | grep -q "iqn.2004-10.com.ubuntu:01:${DEAD}-mxfs-node" \
    || die "$DEAD came up with the wrong iSCSI initiator name"

echo "=== REVIVE OK: $DEAD is back as libvirt domain $NEWDOM ==="
echo "    The wedged domain '$DEAD' and its image stay on disk and stay"
echo "    unreclaimable until clyde is reset by a human (RULE 2)."
exit 0
