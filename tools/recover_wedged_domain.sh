#!/bin/bash
# tools/recover_wedged_domain.sh <domain> — recover a libvirt guest whose qemu
# process cannot be killed, WITHOUT resetting the host (RULE 2 forbids that).
#
# THE FAILURE (measured on clyde 2026-08-20, sess384, domain test4):
#   virsh destroy test4
#     error: Failed to terminate process 1188423 with SIGKILL: Device or resource busy
#   virsh domstate test4        -> hangs forever
#   virsh domstate <any other>  -> answers instantly
#   virsh list --all            -> hangs, because it touches every domain
#
# The qemu leader is a ZOMBIE with live sub-threads stuck in uninterruptible
# sleep.  On the observed instance all five were here:
#     ext4_buffered_write_iter+0x39 -> ext4_file_write_iter -> vfs_writev
#     -> __x64_sys_pwritev
# i.e. blocked writing the guest's SERIAL LOG on the host's own ext4, with
# MXFS nowhere in the path.  A D-state task cannot take a signal, so libvirtd
# retries the kill forever and deadlocks that one domain object.  Everything
# the stuck instance still holds then blocks a fresh start, in this order —
# each one only becomes visible after the previous is cleared:
#     1. libvirtd's runtime state         /run/libvirt/qemu/<d>.{pid,xml}
#     2. virtlogd's lock on the serial log /var/log/libvirt/qemu/<d>-serial.log
#     3. virtlogd's lock on the qemu log   /var/log/libvirt/qemu/<d>.log
#     4. virtlockd's lease on the DISK IMAGE  (unbreakable — the zombie's fd
#        still holds it, so the domain must be pointed at a COPY)
#     5. systemd-machined's registration   qemu-<id>-<d>
#
# Total recovery ~3 minutes, dominated by the image copy (26 GB in 75 s here).
# The old image is left untouched: if those threads ever unblock they write to
# the file nothing references any more.
#
# RULE 2: this NEVER reboots or sysrqs the host.  It restarts libvirtd/virtlogd,
# which running guests survive.
#
# Usage:  sudo tools/recover_wedged_domain.sh test4
set -u
D="${1:-}"
[ -n "$D" ] || { echo "usage: $0 <domain>"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run me under sudo"; exit 1; }

XML="/etc/libvirt/qemu/$D.xml"
[ -f "$XML" ] || { echo "no persistent XML at $XML"; exit 1; }

echo "== 1/6  is this domain actually wedged?"
if timeout 20 virsh -c qemu:///system domstate "$D" >/dev/null 2>&1; then
    echo "   virsh domstate $D answered — the domain is NOT deadlocked."
    echo "   Use the normal 'virsh destroy && virsh start' path instead."
    exit 1
fi
echo "   confirmed: virsh domstate $D does not return"

echo "== 2/6  drop libvirtd's runtime state for $D and restart it"
systemctl stop libvirtd
sleep 3
mv -f "/run/libvirt/qemu/$D.pid" "/run/libvirt/qemu/$D.pid.stale" 2>/dev/null
mv -f "/run/libvirt/qemu/$D.xml" "/run/libvirt/qemu/$D.xml.stale" 2>/dev/null
systemctl start libvirtd
sleep 8
timeout 30 virsh -c qemu:///system domstate "$D" 2>&1 || { echo "   still deadlocked — stop here and report"; exit 1; }

echo "== 3/6  move the serial log aside (virtlogd holds a lock keyed by path)"
SER="/var/log/libvirt/qemu/$D-serial.log"
mv -f "$SER" "$SER.stale" 2>/dev/null
# The path lives in the persistent XML, so repoint it as well: virtlogd's lock
# survives a rename, and only a different PATH avoids it.
cp -f "$XML" "$XML.backup"
sed -i "s#/var/log/libvirt/qemu/$D-serial.log#/var/log/libvirt/qemu/$D-serial2.log#g" "$XML"

echo "== 4/6  move the qemu log aside and restart virtlogd"
mv -f "/var/log/libvirt/qemu/$D.log" "/var/log/libvirt/qemu/$D.log.stale" 2>/dev/null
systemctl restart virtlogd
sleep 4

echo "== 5/6  point the domain at a COPY of its disk (virtlockd's lease on the"
echo "        original cannot be broken while the zombie holds the fd)"
SRC=$(sed -n "s#.*<source file='\\([^']*\\)'.*#\\1#p" "$XML" | head -1)
[ -n "$SRC" ] || { echo "   could not find <source file=...> in $XML"; exit 1; }
case "$SRC" in
    *.new) echo "   already on a copy ($SRC) — skipping" ;;
    *)  echo "   copying $SRC -> $SRC.new"
        cp --sparse=always "$SRC" "$SRC.new" || exit 1
        chmod 666 "$SRC.new"
        sed -i "s#<source file='$SRC'#<source file='$SRC.new'#" "$XML"
        ;;
esac
timeout 60 virsh -c qemu:///system define "$XML" || exit 1

echo "== 6/6  clear systemd-machined's stale registration, then start"
for m in $(machinectl list --no-legend 2>/dev/null | awk '{print $1}' | grep -- "-$D\$"); do
    echo "   terminating machine $m"
    timeout 30 machinectl terminate "$m" 2>/dev/null
done
sleep 3
timeout 90 virsh -c qemu:///system start "$D" || exit 1
echo
echo "$D started.  It has NO /src (NFS is deliberately not an fstab automount),"
echo "so mount it before the node can run anything out of the tree:"
echo "  tools/mxfs_sshpass.sh $D \"mkdir -p /src; mount -t nfs 192.168.1.4:/src /src \\"
echo "      -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp\""
echo
echo "The old image is still at $SRC and the stuck qemu still holds it."
echo "Only a host reset clears that process; until then do not delete the file."
