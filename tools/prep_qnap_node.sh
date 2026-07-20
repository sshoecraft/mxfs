#!/bin/bash
# prep_qnap_node.sh — prepare a test node to use the QNAP iSCSI LUN directly
# (no clyde SCST passthrough).  Each node is its own iSCSI initiator → its own
# I_T nexus to the QNAP target, so per-node identity / fencing is real.
#
# This is the substrate for the "direct QNAP iSCSI + TCP DLM (no CAW)"
# experiment (run 14d31183, sess71): the in-host SCST loopback target was the
# recurring source of reservation-conflict storms under the 16-node mkdir
# storm.  The QNAP TS-453 Pro is a hardware appliance target.
#
# After this runs, the shared LUN is /dev/sdb (50G QNAP iSCSI Storage) and the
# mxfs.ko on the QNAP-exported NFS /src is reachable.
set -u

NFS_SERVER="192.168.1.4:/src"
NFS_MOUNT="/src"
QNAP_PORTAL="192.168.1.4"
QNAP_TGT="iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772"

fail() { echo "PREP_QNAP_FAIL: $*"; exit 1; }

# 1. Cleanup any prior mxfs mount/module
umount /mnt/shared 2>/dev/null || true
rmmod mxfs 2>/dev/null || true

# 2. NFS /src (carries mxfs.ko + tools) — same QNAP box, NFS export.
if ! mountpoint -q "$NFS_MOUNT"; then
    mount -t nfs "$NFS_SERVER" "$NFS_MOUNT" \
        -o rw,vers=3,soft,timeo=100,retrans=5,tcp,rsize=1048576,wsize=1048576,noatime \
        || fail "NFS mount failed"
fi

# 3. Harden iSCSI BEFORE discovery (discovery snapshots iscsid.conf into the
#    per-node record).  The default noop_out_timeout=5s is too aggressive for
#    the routed VM->clyde->QNAP path: under storm I/O the keepalive falsely
#    times out and tears the session down (conn error 1020).  Raise it + TCP
#    socket buffers so transient saturation doesn't kill the session.
printf 'net.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n' >/etc/sysctl.d/99-mxfs-iscsi-tcp.conf
sysctl -p /etc/sysctl.d/99-mxfs-iscsi-tcp.conf >/dev/null 2>&1
set_iscsid() { # key value
    if grep -qE "^[# ]*$1" /etc/iscsi/iscsid.conf 2>/dev/null; then
        sed -i "s|^[# ]*$1.*|$1 = $2|" /etc/iscsi/iscsid.conf
    else
        echo "$1 = $2" >> /etc/iscsi/iscsid.conf
    fi
}
set_iscsid "node.conn\[0\].timeo.noop_out_timeout" 30
set_iscsid "node.conn\[0\].timeo.noop_out_interval" 10
set_iscsid "node.session.timeo.replacement_timeout" 120
set_iscsid "node.conn\[0\].tcp.window_size" 16777216

# 3b. iSCSI: ensure iscsid up, discover + login to the QNAP target.
systemctl start iscsid 2>/dev/null || true
iscsiadm -m discovery -t st -p "$QNAP_PORTAL" >/dev/null 2>&1 || fail "iscsi discovery failed"
# Belt-and-suspenders: also force the value onto the (just-created) node record.
iscsiadm -m node -T "$QNAP_TGT" -p "$QNAP_PORTAL" -o update -n node.conn[0].timeo.noop_out_timeout -v 30 2>/dev/null
iscsiadm -m node -T "$QNAP_TGT" -p "$QNAP_PORTAL" -o update -n node.conn[0].timeo.noop_out_interval -v 10 2>/dev/null
# node.startup automatic so a node reboot re-attaches the LUN.
iscsiadm -m node -T "$QNAP_TGT" -p "$QNAP_PORTAL" -o update -n node.startup -v automatic 2>/dev/null
iscsiadm -m node -T "$QNAP_TGT" -p "$QNAP_PORTAL" --login >/dev/null 2>&1 || true

# 4. Wait for the QNAP LUN to appear (by vendor string, not a fixed /dev name).
QDEV=""
for i in $(seq 1 15); do
    QDEV=$(lsblk -S -o NAME,VENDOR 2>/dev/null | awk '/QNAP/{print "/dev/"$1; exit}')
    [ -n "$QDEV" ] && break
    sleep 1
done
[ -n "$QDEV" ] || fail "QNAP LUN did not appear"

# 5. Module deps + mount point
modprobe libcrc32c 2>/dev/null || true
mkdir -p /mnt/shared

echo "PREP_QNAP_OK qnap_lun=$QDEV nfs=$(mountpoint -q $NFS_MOUNT && echo yes)"
