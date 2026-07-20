#!/bin/bash
# MXFS test VM canonical (re)definition.
#
# Defines test VMs from ONE canonical libvirt template so all nodes are
# byte-for-byte identical in hardware config.  Only the fields that MUST differ
# per VM are substituted, and existing values are PRESERVED so identity is
# stable:
#   - name        : testN
#   - uuid        : existing domain uuid (preserved) or freshly generated
#   - MAC         : existing interface MAC (PRESERVED — tied to DHCP hostname
#                   resolution; regenerating it would break `testN` lookups)
#   - boot disk   : existing qcow2 path, else /home/steve/vms/qemu/testN/testN
#
# Hardware (4 vCPU / 4096 MB, pc-i440fx-noble, virtio-scsi, shareable
# /dev/mxfs-shared LUN at guest sda, virtio NIC on br0) comes from the template
# and is identical across every node.
#
# A running target is destroyed first (test VMs are disposable).  This only
# rewrites the libvirt definition — it never touches the qcow2 boot image or
# the shared LUN data.
#
# Usage:
#   scripts/define_vms.sh           # all of test1..test32
#   scripts/define_vms.sh 4         # test1..test4
#   scripts/define_vms.sh 2 7 18    # those specific nodes

set -u

V="virsh -c qemu:///system"
SHARED="${MXFS_SHARED_DEV:-/dev/mxfs-shared}"
MAXNODE=32
TMP=$(mktemp -d /tmp/define_vms.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "DEFINE_FAIL: $*" >&2; exit 1; }

# --- canonical template (placeholders: @@NAME@@ @@UUID@@ @@MAC@@ @@BOOT@@) ---
cat > "$TMP/template.xml" <<EOF
<domain type='kvm'>
  <name>@@NAME@@</name>
  <uuid>@@UUID@@</uuid>
  <memory unit='KiB'>4194304</memory>
  <currentMemory unit='KiB'>4194304</currentMemory>
  <vcpu placement='static'>4</vcpu>
  <resource>
    <partition>/machine</partition>
  </resource>
  <os>
    <type arch='x86_64' machine='pc-i440fx-noble'>hvm</type>
    <boot dev='hd'/>
  </os>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='@@BOOT@@'/>
      <backingStore/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </disk>
    <disk type='block' device='lun'>
      <driver name='qemu' type='raw' cache='none'/>
      <source dev='$SHARED'/>
      <target dev='sda' bus='scsi'/>
      <shareable/>
      <address type='drive' controller='0' bus='0' target='0' unit='0'/>
    </disk>
    <controller type='scsi' index='0' model='virtio-scsi'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </controller>
    <controller type='usb' index='0' model='piix3-uhci'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'/>
    <interface type='bridge'>
      <mac address='@@MAC@@'/>
      <source bridge='br0'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <audio id='1' type='none'/>
    <video>
      <model type='cirrus' vram='16384' heads='1' primary='yes'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </memballoon>
  </devices>
  <seclabel type='dynamic' model='dac' relabel='yes'/>
</domain>
EOF

parse_nodes() {
    if [ "$#" -eq 0 ]; then seq 1 "$MAXNODE"; return; fi
    if [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]]; then seq 1 "$1"; return; fi
    local a n
    for a in "$@"; do n="${a#test}"; echo "$n"; done
}

define_one() {
    local n="$1" vm="test$n" uuid mac boot
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$MAXNODE" ] || { echo "$vm: bad node"; return 1; }

    # preserve identity from the existing definition where present
    uuid=$($V domuuid "$vm" 2>/dev/null | tr -d '[:space:]')
    [ -n "$uuid" ] || uuid=$(uuidgen)
    mac=$($V dumpxml "$vm" --inactive 2>/dev/null | grep -oP "mac address='\K[^']+" | head -1)
    boot=$($V dumpxml "$vm" --inactive 2>/dev/null | grep -A3 "device='disk'" | grep -oP "source file='\K[^']+" | head -1)
    [ -n "$boot" ] || boot="/home/steve/vms/qemu/$vm/$vm"
    if [ -z "$mac" ]; then
        printf -v mac "52:54:00:%02x:%02x:%02x" $(( (n>>16)&0xff )) $(( (n>>8)&0xff )) $(( n&0xff ))
        echo "$vm: WARN no existing MAC — generated $mac"
    fi
    [ -f "$boot" ] || { echo "$vm: boot disk $boot MISSING — skipped"; return 1; }

    # destroy if running (disposable test VMs)
    [ "$($V domstate "$vm" 2>/dev/null)" = "running" ] && $V destroy "$vm" >/dev/null 2>&1

    sed -e "s|@@NAME@@|$vm|g" -e "s|@@UUID@@|$uuid|g" -e "s|@@MAC@@|$mac|g" -e "s|@@BOOT@@|$boot|g" \
        "$TMP/template.xml" > "$TMP/$vm.xml"
    $V define "$TMP/$vm.xml" >/dev/null 2>&1 || { echo "$vm: define FAILED"; return 1; }
    echo "$vm: defined (uuid=${uuid:0:8}… mac=$mac boot=$boot)"
}

rc=0
for n in $(parse_nodes "$@"); do define_one "$n" || rc=1; done
exit $rc
