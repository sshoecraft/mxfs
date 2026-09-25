#!/bin/bash
#
# selinux_svirt_mxfs.sh — can a confined QEMU (libvirt sVirt) run a disk image
# that lives on MXFS, with SELinux enforcing and no AVC denial?
#
# The use case SELinux labeling exists for on a RHEL-family host: libvirt
# starts every guest's QEMU in svirt_t with its own MCS category pair and
# relabels the guest's disk to svirt_image_t with the same pair, so one guest
# cannot open another's image.  That needs the filesystem to store a label per
# file (security.selinux xattr) and take the relabel at start.  Before the
# RPM carried a labeling rule for mxfs, every MXFS file was unlabeled_t, which
# svirt_t is denied.
#
# On NODE (which must have MXFS mounted at MNT, SELinux enforcing, /dev/kvm):
#   1. install qemu-kvm-core and libvirt's QEMU driver if absent
#   2. a 64 MiB raw image on MXFS, and a transient KVM guest with it as its
#      only disk (cache=none, so QEMU reads it O_DIRECT); the firmware reads
#      its boot sector
#   3. while it runs: the QEMU process's label, the image's label, the image
#      open in QEMU's fd table
#   4. destroy it; AVC denials counted since the start of the test
#
# Pass: guest running; QEMU in svirt_t:s0:cX,cY; the image svirt_image_t with
# the same categories; QEMU holds the image open; zero new AVC denials.
#
# Budgets: the package install pulls ~60 packages from the AlmaLinux mirrors,
# ~90 s measured for a similar set on these guests -> INSTALL_S=300 (none when
# already installed); a diskless-OS guest starts in ~2 s -> the rest 60 s.
#
# Usage: tests/selinux_svirt_mxfs.sh NODE [MNT]
#   NODE is an address tools/mxfs_sshpass.sh reaches; MNT defaults to /mnt/mxfs.
#   Evidence: tests/evidence/selinux_svirt/<stamp>/.  Exit 0 only on PASS.
#
set -u

NODE="${1:?usage: selinux_svirt_mxfs.sh NODE [MNT]}"
MNT="${2:-/mnt/mxfs}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
INSTALL_S=300
RUN_S=60
EV="$HERE/tests/evidence/selinux_svirt/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
on() { local t=$1; shift; timeout "$t" "$SSH" "$NODE" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$"; return "${PIPESTATUS[0]}"; }

say "node=$NODE mnt=$MNT evidence=$EV"
on 30 "echo kernel=\$(uname -r); echo enforce=\$(getenforce); echo module=\$(semodule -l | grep -x mxfs)
       echo mount=\$(findmnt -n -o FSTYPE $MNT); ls -l /dev/kvm" > "$EV/pre.log"
cat "$EV/pre.log"
grep -q "enforce=Enforcing" "$EV/pre.log" || { say "RESULT FAIL: SELinux is not enforcing on $NODE"; exit 1; }
grep -q "mount=mxfs" "$EV/pre.log" || { say "RESULT FAIL: $MNT on $NODE is not an MXFS mount"; exit 1; }
grep -q "/dev/kvm" "$EV/pre.log" || { say "RESULT FAIL: no /dev/kvm on $NODE"; exit 1; }

on $INSTALL_S "rpm -q qemu-kvm-core libvirt-daemon-driver-qemu libvirt-client >/dev/null 2>&1 ||
       dnf -y install qemu-kvm-core libvirt-daemon-driver-qemu libvirt-client; echo install_rc=\$?
       systemctl start virtqemud.socket virtlogd.socket; echo sockets_rc=\$?" > "$EV/install.log"
tail -2 "$EV/install.log"
grep -q "install_rc=0" "$EV/install.log" && grep -q "sockets_rc=0" "$EV/install.log" \
    || { say "RESULT FAIL: installing or starting libvirt's QEMU driver (see install.log)"; exit 1; }

# Watchdog: if the step below is still running 8 s before its budget, record
# the kernel stacks of every blocked task and of the step's own commands, so an
# overrun names what it waited on (D-SURVIVOR-CREATE-STALLS-60S-AFTER-PEER-DEATH-
# UNTIL-RESUMED-VICTIM-UNMOUNTS stalled here once with no trace).
on $RUN_S "rm -f /run/mxfs-svirt.done" >/dev/null
( on $((RUN_S + 5)) "t=0; while [ \$t -lt $((RUN_S - 8)) ]; do
        [ -e /run/mxfs-svirt.done ] && exit 0; sleep 1; t=\$((t + 1)); done
    echo stacks_at=\$(date +%s.%N)
    for p in /proc/[0-9]*; do
        st=\$(awk '{print \$3}' \$p/stat 2>/dev/null); c=\$(cat \$p/comm 2>/dev/null)
        case \"\$st:\$c\" in D:*|*:qemu-img|*:mkdir|*:rm|*:ausearch)
            echo \"== pid \${p#/proc/} comm=\$c state=\$st\"; cat \$p/stack 2>/dev/null ;;
        esac
    done" > "$EV/stacks.log" ) &
WATCH=$!

on $RUN_S "
    # --input-logs: without it ausearch reads its stdin whenever stdin is a
    # pipe, which over ssh it always is -- it counted an empty stream instead
    # of the audit log, and blocked for as long as the caller's stdin stayed open
    avc() { ausearch --input-logs -m avc,user_avc,selinux_err -ts boot </dev/null 2>/dev/null | grep -c 'type=AVC\|type=USER_AVC\|type=SELINUX_ERR'; }
    # each step stamped, so an overrun names the step that took the time
    echo t_start=\$(date +%s.%N)
    before=\$(avc)
    echo t_avc=\$(date +%s.%N)
    d=$MNT/svirt; mkdir -p \$d; echo t_mkdir=\$(date +%s.%N)
    rm -f \$d/disk.img; echo t_rm=\$(date +%s.%N)
    qemu-img create -q -f raw \$d/disk.img 64M
    echo t_create=\$(date +%s.%N)
    echo created_label=\$(stat -c %C \$d/disk.img)
    cat > /run/mxfs-svirt.xml <<X
<domain type='kvm'>
  <name>mxfs-svirt</name>
  <memory unit='MiB'>128</memory>
  <vcpu>1</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='\$d/disk.img'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <memballoon model='none'/>
  </devices>
</domain>
X
    virsh -c qemu:///system destroy mxfs-svirt >/dev/null 2>&1
    virsh -c qemu:///system create /run/mxfs-svirt.xml; echo create_rc=\$?
    sleep 3
    echo state=\$(virsh -c qemu:///system domstate mxfs-svirt)
    pid=\$(cat /run/libvirt/qemu/mxfs-svirt.pid 2>/dev/null)
    echo qemu_label=\$(cat /proc/\$pid/attr/current 2>/dev/null | tr -d '\0')
    echo image_label=\$(stat -c %C \$d/disk.img)
    echo image_open=\$(ls -l /proc/\$pid/fd 2>/dev/null | grep -c disk.img)
    virsh -c qemu:///system destroy mxfs-svirt; echo destroy_rc=\$?
    echo after_label=\$(stat -c %C \$d/disk.img)
    after=\$(avc); echo avc_new=\$((after - before))
    [ \$after -gt \$before ] && ausearch --input-logs -m avc,user_avc,selinux_err -ts boot </dev/null 2>/dev/null | tail -20
    touch /run/mxfs-svirt.done
    true" > "$EV/svirt.log"
rc=$?
wait $WATCH
[ -s "$EV/stacks.log" ] && { say "the step overran: blocked stacks in stacks.log"; head -40 "$EV/stacks.log"; }
cat "$EV/svirt.log"
[ $rc = 124 ] && { say "RESULT FAIL: over the ${RUN_S} s budget"; exit 1; }

FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
grep -q "create_rc=0" "$EV/svirt.log" || fail "the guest did not start"
grep -q "state=running" "$EV/svirt.log" || fail "the guest is not running"
ql=$(sed -n 's/^qemu_label=//p' "$EV/svirt.log"); il=$(sed -n 's/^image_label=//p' "$EV/svirt.log")
case "$ql" in *:svirt_t:s0:c*) ;; *) fail "QEMU is not in svirt_t with categories: '$ql'" ;; esac
case "$il" in *:svirt_image_t:s0:c*) ;; *) fail "the image was not relabeled svirt_image_t: '$il'" ;; esac
[ -n "$ql" ] && [ "${ql##*:s0:}" = "${il##*:s0:}" ] || fail "QEMU's categories '${ql##*:s0:}' are not the image's '${il##*:s0:}'"
grep -q "image_open=[1-9]" "$EV/svirt.log" || fail "QEMU does not hold the image open"
grep -q "avc_new=0" "$EV/svirt.log" || fail "AVC denials during the test"
[ $FAILS = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
