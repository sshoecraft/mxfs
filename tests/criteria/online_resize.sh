#!/bin/bash
# Criterion: Resize (grow).  `resize_mxfs` claims new device space
# after the backing device has been expanded; prior data is preserved.
#
# resize_mxfs is OFFLINE: it requires the FS to be unmounted.  Test
# flow:
#   1. Create a 1 GiB sparse file, loop-mount it as the "device"
#   2. mkfs.mxfs on the loop dev, mount, write known data, md5 it,
#      umount
#   3. Grow the backing file to 2 GiB (truncate -s 2G), reread the
#      loop device size (losetup -c)
#   4. Run resize_mxfs on the loop device
#   5. Remount, verify (a) df shows the new size, (b) the original
#      data still md5-matches
#
# Threshold: the grow must recover at least 90% of the ADDED space
# (post_mb - pre_mb >= 922MB of the 1024MB added) AND the pre-resize
# md5 still matches.  resize_mxfs exit code must be 0.
#
# Why delta-of-added, not %-of-total-device (sess30, run14d): MXFS
# carries a FIXED overhead that dominates a tiny 2GiB test device:
#   - 96MB envelope (4KB super + 64MB journal + 32MB disklock),
#     measured: XFS data starts at byte 100704256 on a 1GiB loop;
#   - 256MB internal XFS log = log_node_count(4) x 64MB/slice minimum
#     (mkfs_mxfs.c, sess21 run14d: 64MB/slice fixed single_node_paired
#     180%->102% and the rsync log-tail wedge; matches xfsprogs >=5.19's
#     64MB minimum.  Shrinking the log to pass this test would regress
#     RULE 0 performance criteria.)
# Measured on 1G->2G loop: pre=672MB (928MB data region - 256MB log),
# post=1696MB — the grow recovered post-pre = 1024MB = 100% of the
# added space.  The old ">=1800MB of total" gate measured mkfs overhead,
# not resize; it passed only while the log minimum was 32MB/slice.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "online_resize"
set_script_timeout 120

parse_common_args "$@"
NODE="${NODES[0]}"

# Use a loopback file on the test node — avoids needing to actually
# grow the LIO LUN.  resize_mxfs only cares about the block device
# size; it doesn't care how that size came to be.
teardown_all "$NODE"

out=$(ssh_node "$NODE" "
    # Idempotent cleanup of any leftover state from a prior aborted run:
    # a stale /mnt/resize_mount or loop device pins the module and would
    # make the insmod below fail (module busy / already loaded).
    umount /mnt/resize_mount 2>/dev/null || true
    for l in \$(losetup -j /tmp/resize_test/img.raw 2>/dev/null | cut -d: -f1); do
        losetup -d \"\$l\" 2>/dev/null || true
    done
    set -e
    $MXFS_PREP >/tmp/prep.log 2>&1
    modprobe libcrc32c
    # Load only if not already loaded — set -e must not trip on an
    # already-present module.
    lsmod | grep -q '^mxfs ' || insmod $MXFS_MODULE
    mkdir -p /tmp/resize_test
    cd /tmp/resize_test
    rm -f img.raw
    truncate -s 1G img.raw
    LOOP=\$(losetup -f --show img.raw)
    echo LOOP=\$LOOP

    # mkfs and initial mount
    echo y | $MXFS_MKFS \$LOOP >/tmp/mkfs.log 2>&1 && echo MKFS1_OK
    mkdir -p /mnt/resize_mount
    mount -t mxfs ${MXFS_MOUNT_OPTS} \$LOOP /mnt/resize_mount && echo MOUNT1_OK

    # Write a known payload
    mkdir -p /mnt/resize_mount/data
    for i in \$(seq 1 64); do
        dd if=/dev/urandom of=/mnt/resize_mount/data/f\$i bs=4K count=4 2>/dev/null
    done
    sync
    md5sum /mnt/resize_mount/data/* | sort > /tmp/pre.md5

    pre_mb=\$(df -BM /mnt/resize_mount | awk 'NR==2 {print \$2}' | tr -d M)
    echo PRE_MB=\$pre_mb

    # Unmount, grow the file, refresh the loop, resize, remount
    umount /mnt/resize_mount
    truncate -s 2G img.raw
    losetup -c \$LOOP
    new_size=\$(blockdev --getsize64 \$LOOP)
    echo NEW_BYTES=\$new_size

    $MXFS_RESIZE \$LOOP 2>&1 | tail -10
    echo RESIZE_RC=\$?

    mount -t mxfs ${MXFS_MOUNT_OPTS} \$LOOP /mnt/resize_mount && echo MOUNT2_OK
    post_mb=\$(df -BM /mnt/resize_mount | awk 'NR==2 {print \$2}' | tr -d M)
    echo POST_MB=\$post_mb

    md5sum /mnt/resize_mount/data/* | sort > /tmp/post.md5
    if diff -q /tmp/pre.md5 /tmp/post.md5 >/dev/null; then echo MD5_OK; else echo MD5_DIFF; fi

    umount /mnt/resize_mount
    losetup -d \$LOOP
    rm -f img.raw
    rmmod mxfs 2>/dev/null
")

# Parse
mkfs_ok=$(echo "$out"   | grep -c '^MKFS1_OK')
mount1_ok=$(echo "$out" | grep -c '^MOUNT1_OK')
pre_mb=$(echo "$out"    | sed -n 's/^PRE_MB=//p'   | tail -1)
resize_rc=$(echo "$out" | sed -n 's/^RESIZE_RC=//p' | tail -1)
mount2_ok=$(echo "$out" | grep -c '^MOUNT2_OK')
post_mb=$(echo "$out"   | sed -n 's/^POST_MB=//p'  | tail -1)
md5=$(echo "$out"       | grep -E '^MD5_(OK|DIFF)' | tail -1)

pre_mb=${pre_mb:-0}
post_mb=${post_mb:-0}
resize_rc=${resize_rc:-99}

# Thresholds: the device grew by 1024MB; the FS must recover >=90% of
# that delta.  Fixed mkfs overhead (envelope + per-node log slices) is
# architectural and identical pre/post, so it cancels in the delta.
ADDED_MB=1024
EXPECTED_DELTA_MB=922   # 90% of the added 1024MB
delta_mb=$(( post_mb - pre_mb ))
measured="pre=${pre_mb}MB post=${post_mb}MB delta=${delta_mb}MB resize_rc=$resize_rc md5=${md5:-missing}"
threshold="delta>=${EXPECTED_DELTA_MB}MB(90% of ${ADDED_MB}MB added) resize_rc=0 md5=MD5_OK"

[ "$mkfs_ok"   = "1" ] || result_fail "$measured" "$threshold" "mkfs.mxfs on loopback failed"
[ "$mount1_ok" = "1" ] || result_fail "$measured" "$threshold" "initial mount on loopback failed"
[ "$resize_rc" = "0" ] || result_fail "$measured" "$threshold" "resize_mxfs returned $resize_rc"
[ "$mount2_ok" = "1" ] || result_fail "$measured" "$threshold" "remount after resize failed"
[ "$delta_mb" -ge "$EXPECTED_DELTA_MB" ] || result_fail "$measured" "$threshold" "FS did not grow as expected"
[ "$md5" = "MD5_OK" ]  || result_fail "$measured" "$threshold" "pre-resize data did not survive grow"
result_pass "$measured" "$threshold"
