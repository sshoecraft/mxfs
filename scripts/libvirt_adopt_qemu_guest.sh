#!/bin/bash
#
# libvirt_adopt_qemu_guest.sh — put a guest that runs (or ran) as a bare QEMU
# process under libvirt, on the same disk, with discard enabled.
#
# alma9-1/alma9-2 were still running inside the Packer build's QEMU (the
# installer DVD and Packer's seed ISO still attached), so libvirt had never
# seen them: no virsh suspend for the freeze test, no discard for their
# images, and a host reboot would have lost them.  rhel9-1/rhel9-2 had only
# their disks left.
#
# The definition reproduces what the guest was installed on, because the
# guest names its NIC by PCI slot and its network profile is bound to that
# name: machine pc-i440fx (the distro alias of QEMU 8.2's), VGA at 00:02.0,
# the virtio NIC at 00:03.0, the virtio disk at 00:04.0 (read from a running
# guest over QMP: query-pci), bridged to br0, host-passthrough CPU (RHEL 9
# needs x86-64-v2), and the MAC it had, so it keeps its address.  The qcow2
# disk gets discard='unmap' detect_zeroes='unmap'.
#
# If the guest is running under its old QEMU (a monitor socket answers), it
# is powered off from inside first and the old process must exit before
# libvirt opens the same image.  The domain is then started and trimmed by
# scripts/vm_reclaim_disk.sh, which leaves it running.
#
# Budgets: a guest poweroff completes in ~10 s -> POWEROFF_S=90.
#
# Usage: scripts/libvirt_adopt_qemu_guest.sh <name> <mac|auto> <vcpus> <mem_mb>
#   The image is ~/vms/qemu/<name>/<name>, osimager's QEMU output layout.
#
set -u

NAME="${1:?name}"; MAC="${2:?mac or auto}"; VCPUS="${3:?vcpus}"; MEM="${4:?mem_mb}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
IMG="$HOME/vms/qemu/$NAME/$NAME"
MON="$HOME/vms/qemu/$NAME/$NAME.monitor"
POWEROFF_S=90
say() { echo "[$(date +%T)] $*"; }

[ -f "$IMG" ] || { say "$NAME: no image at $IMG"; exit 2; }
if $VIRSH domstate "$NAME" >/dev/null 2>&1; then
    say "$NAME: already a libvirt domain"; exit 0
fi

# a live monitor means the old QEMU still has the image open
mon_alive() { python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1])' "$MON" 2>/dev/null; }
WAS_RUNNING=0
if [ -S "$MON" ] && mon_alive; then
    WAS_RUNNING=1
    a=$(lab_addr "$NAME")
    say "$NAME: running under its old QEMU; powering it off from inside ($a)"
    timeout 20 "$SSH" "$a" "systemctl poweroff" >/dev/null 2>&1
    t0=$(date +%s)
    while mon_alive; do
        [ $(( $(date +%s) - t0 )) -ge $POWEROFF_S ] && { say "$NAME: old QEMU still up after ${POWEROFF_S} s; not touching its image"; exit 1; }
        sleep 2
    done
    say "$NAME: old QEMU exited after $(( $(date +%s) - t0 )) s"
fi

macxml=""; [ "$MAC" = auto ] || macxml="<mac address='$MAC'/>"
x=$(mktemp --suffix=.xml)
cat > "$x" <<EOF
<domain type='kvm'>
  <name>$NAME</name>
  <memory unit='MiB'>$MEM</memory>
  <vcpu placement='static'>$VCPUS</vcpu>
  <cpu mode='host-passthrough'/>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/></features>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' discard='unmap' detect_zeroes='unmap'/>
      <source file='$IMG'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </disk>
    <interface type='bridge'>
      $macxml
      <source bridge='br0'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <video>
      <model type='vga'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'/>
    <serial type='pty'/>
    <console type='pty'/>
    <memballoon model='none'/>
  </devices>
</domain>
EOF
$VIRSH define "$x" >/dev/null; rc=$?
rm -f "$x"
[ $rc = 0 ] || { say "$NAME: virsh define failed"; exit 1; }
say "$NAME: defined in qemu:///system (mac $($VIRSH domiflist "$NAME" | awk '/br0/ {print $5}'))"
# the reclaim returns a domain to the state it found it in (off, for a new
# definition); a guest that was running before adoption is started again
"$HERE/scripts/vm_reclaim_disk.sh" "$NAME"
if [ $WAS_RUNNING = 1 ]; then
    $VIRSH start "$NAME" >/dev/null && say "$NAME: started again under libvirt (it was running before adoption)"
fi
