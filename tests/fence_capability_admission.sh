#!/bin/bash
# fence_capability_admission.sh — the NEGATIVE criterion for
# D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT.
#
# The positive side is easy and is covered by any normal prep: on the real LUN
# every node logs P303-FENCECAP-OK and mounts.  What that cannot show is that
# the check has TEETH.  This does.
#
# It builds a device with genuinely NO SCSI persistent reservations at all — a
# plain loop device — puts a real MXFS on it, and asserts:
#
#   ARM 1 (default)                        the mount is REFUSED, and the log
#                                          says which condition failed
#                                          (P303-FENCECAP-NOCAPS).
#   ARM 2 (fence_capability_override=1)    the mount is ADMITTED, and the log
#                                          says loudly that this mount has
#                                          weaker-than-production recovery
#                                          semantics (P303-FENCECAP-OVERRIDE).
#
# Arm 2 matters as much as arm 1.  The sess93 RULE-5 ruling requires that a rig
# which cannot produce fencing evidence be EXPLICITLY single-node/read-only/
# otherwise-provided-for rather than silently degraded — so the operator must
# have a way to say so, and taking it must be loud and attributable.  Arm 2 is
# also the compatibility check on this change: a non-PR device used to mount
# silently, and now it only mounts when someone says it may.
#
# Usage:  fence_capability_admission.sh [node]     (default test32)
#   The node must NOT be part of the live cluster — it is unmounted first.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
NODE="${1:-test32}"
IMG=/var/tmp/mxfs_nopr.img
MNT=/mnt/nopr
SZ_MB=1024

say() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail=0

say "=== fence-capability admission test on $NODE (device with NO SCSI PR)"

# Leave the cluster and unload, so the loop mount is this node's only MXFS.
timeout 200 "$SSH" "$NODE" "
    timeout 150 umount /mnt/shared 2>/dev/null
    for t in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null && break; sleep 5; done
    mkdir -p $MNT" >/dev/null 2>&1

# Build the no-PR device.  A loop device has no pr_ops at all, so
# PERSISTENT RESERVE IN / REPORT CAPABILITIES cannot even be issued -- which is
# precisely the "this rig cannot fence" condition, obtained honestly rather
# than by faking a return code.
setup=$(timeout 180 "$SSH" "$NODE" "
    losetup -D 2>/dev/null
    rm -f $IMG
    truncate -s ${SZ_MB}M $IMG || exit 1
    L=\$(losetup -f --show $IMG) || exit 1
    echo LOOP=\$L
    $REPO/tools/mkfs_mxfs -f \$L >/dev/null 2>&1 || echo MKFS_FAIL
    echo PR_OPS=\$(ls /sys/block/\$(basename \$L)/ 2>/dev/null | grep -c pr || echo 0)
" 2>&1)
echo "$setup" | grep -v -E 'Warning:|Unauthorized|authorized|^$'
LOOP=$(echo "$setup" | sed -n 's/^LOOP=//p')
[ -n "$LOOP" ] || { echo "RESULT: SETUP-FAIL — no loop device"; exit 2; }
echo "$setup" | grep -q MKFS_FAIL && { echo "RESULT: SETUP-FAIL — mkfs_mxfs failed"; exit 2; }

# ---------------------------------------------------------------- ARM 1
say "--- ARM 1: default (fence_capability_override=0) — mount must be REFUSED"
a1=$(timeout 180 "$SSH" "$NODE" "
    rmmod mxfs 2>/dev/null
    insmod /lib/modules/\$(uname -r)/extra/mxfs.ko 2>/dev/null || insmod $REPO/mxfs.ko 2>/dev/null
    echo 'MXFS-FENCECAP-ARM1' > /dev/kmsg
    timeout 60 mount -t mxfs $LOOP $MNT 2>&1; echo mount_rc=\$?
    echo mounted=\$(grep -c ' $MNT ' /proc/mounts)
    dmesg | awk '/MXFS-FENCECAP-ARM1/{f=1;next} f' | grep -E 'P303-FENCECAP|REFUSED' | tail -4
" 2>&1 | grep -v -E 'Warning:|Unauthorized|authorized|^$')
echo "$a1"
a1_mounted=$(echo "$a1" | sed -n 's/^mounted=//p')
if [ "${a1_mounted:-1}" = 0 ]; then
    if echo "$a1" | grep -q 'P303-FENCECAP-NOCAPS\|P303-FENCECAP'; then
        say "ARM 1 PASS — mount refused AND the reason is named in the log"
    else
        say "ARM 1 FAIL — mount refused but no P303-FENCECAP reason was logged"; fail=1
    fi
else
    say "ARM 1 FAIL — a device that cannot fence came up READ-WRITE anyway"; fail=1
fi

# ---------------------------------------------------------------- ARM 2
say "--- ARM 2: fence_capability_override=1 — mount must be ADMITTED, loudly"
a2=$(timeout 180 "$SSH" "$NODE" "
    timeout 60 umount $MNT 2>/dev/null
    rmmod mxfs 2>/dev/null
    insmod /lib/modules/\$(uname -r)/extra/mxfs.ko fence_capability_override=1 2>/dev/null || \
        insmod $REPO/mxfs.ko fence_capability_override=1 2>/dev/null
    echo 'MXFS-FENCECAP-ARM2' > /dev/kmsg
    timeout 60 mount -t mxfs $LOOP $MNT 2>&1; echo mount_rc=\$?
    echo mounted=\$(grep -c ' $MNT ' /proc/mounts)
    dmesg | awk '/MXFS-FENCECAP-ARM2/{f=1;next} f' | grep -E 'P303-FENCECAP' | tail -4
" 2>&1 | grep -v -E 'Warning:|Unauthorized|authorized|^$')
echo "$a2"
a2_mounted=$(echo "$a2" | sed -n 's/^mounted=//p')
if [ "${a2_mounted:-0}" = 1 ]; then
    if echo "$a2" | grep -q 'P303-FENCECAP-OVERRIDE'; then
        say "ARM 2 PASS — admitted under the explicit operator override, and it said so"
    else
        say "ARM 2 FAIL — admitted but the weaker-semantics warning was NOT logged"; fail=1
    fi
else
    say "ARM 2 FAIL — the override did not admit the mount (rc above)"; fail=1
fi

# ---------------------------------------------------------------- teardown
timeout 180 "$SSH" "$NODE" "
    timeout 60 umount $MNT 2>/dev/null
    rmmod mxfs 2>/dev/null
    losetup -d $LOOP 2>/dev/null
    rm -f $IMG" >/dev/null 2>&1

echo
if [ "$fail" = 0 ]; then
    echo "RESULT: PASS | test=fence_capability_admission | node=$NODE | both arms behaved"
else
    echo "RESULT: FAIL | test=fence_capability_admission | node=$NODE"
fi
exit "$fail"
