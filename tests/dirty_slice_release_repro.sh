#!/bin/bash
# dirty_slice_release_repro.sh — D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE
# + D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE (no-survivor arm) repro/verify.
#
# Loop-device, single-node repro on one test node (no PR, untagged writes):
#   arm race    — mount, fsync a marker, XFS_IOC_GOINGDOWN, umount IMMEDIATELY.
#                 Pre-fix: umount cancels the queued withdraw work before it
#                 runs -> depart_clean -> "clean teardown" release of a DIRTY
#                 slice (DIAG-DSR-1, sess180).
#                 PASS = P163-WITHDRAW-STAMP in dmesg AND no "clean teardown".
#   arm delay   — same but sleep 3 before umount (withdraw work runs).
#                 PASS = same verdict; this arm was already correct pre-fix.
#   arm remount — after race arm: remount the loop device and check the
#                 fsync'd marker survived. Pre-Fix-3: pass-2 claim consumes
#                 the WITHDRAWN slot ("slice ADOPTED"), images skipped, marker
#                 GONE (DIAG-DSR-2, sess180).
#                 PASS = marker file present with content B4-dirty-slice.
#
# Usage: tests/dirty_slice_release_repro.sh [node] [race|delay|remount|all]
# Budget (RULE 0): mkfs 4G loop ~2s + mount/umount ~2s + module reload ~5s;
# whole 'all' run must finish < 60s.
set -u
cd "$(dirname "$0")/.."
NODE=${1:-test32}
ARM=${2:-all}
SSH=tools/mxfs_sshpass.sh
IMG=/tmp/vergate_loop.img
DEV=/dev/loop7
MNT=/mnt/vgate
RUN=$$   # unique per-run dmesg tag suffix — the kernel ring buffer keeps
         # prior runs' tags, and sed anchors on the FIRST match

WANT_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/^srcversion/{print $2}')
[ -n "$WANT_SV" ] || { echo "FAIL: no local mxfs.ko srcversion"; exit 1; }

reload() {
  $SSH "$NODE" "umount $MNT 2>/dev/null; umount /mnt/shared 2>/dev/null; \
    losetup -d $DEV 2>/dev/null; rmmod mxfs 2>/dev/null; \
    insmod /src/mxfs/mxfs.ko 2>&1; cat /sys/module/mxfs/srcversion" \
    2>/dev/null | tail -1
}

setup_loop() {
  $SSH "$NODE" "mkdir -p $MNT; rm -f $IMG; truncate -s 4G $IMG && \
    losetup $DEV $IMG && /src/mxfs/tools/mkfs_mxfs -f $DEV 2>&1 | tail -1" 2>/dev/null
}

shutdown_arm() {  # $1 = tag, $2 = pre-umount sleep seconds (0 = race)
  # sess187: single_node_exclusive=1 for the VICTIM mount too — the sess184
  # ruling requires the incarnation to durably classify itself snlocal BEFORE
  # writing (MXFS_HB_FEAT_SNLOCAL at claim); a victim without the write-time
  # marker must be REFUSED untagged replay, so the operator scenario this
  # repro models keeps the param set across the whole single-node deployment.
  local tag=$1 slp=$2
  # sess187: the GOINGDOWN ioctl MUST only ever hit a mounted mxfs — if the
  # mount failed, $MNT is a plain directory on the node's ROOT filesystem and
  # the ioctl shuts down the root FS (took test32 down this exact way).
  $SSH "$NODE" "echo $tag > /dev/kmsg; \
echo 1 > /sys/module/mxfs/parameters/single_node_exclusive; \
mount -t mxfs $DEV $MNT 2>&1; mrc=\$?; echo mount_rc=\$mrc; \
[ \$mrc -ne 0 ] && { echo ABORT-mount-failed; exit 1; }; python3 - <<'PYEOF'
import os, fcntl, struct
os.makedirs('$MNT/b4', exist_ok=True)
fd=os.open('$MNT/b4/marker', os.O_CREAT|os.O_WRONLY, 0o644)
os.write(fd, b'B4-dirty-slice')
os.fsync(fd)
os.close(fd)
dfd=os.open('$MNT', os.O_RDONLY)
fcntl.ioctl(dfd, 0x8004587d, struct.pack('I', 2))
os.close(dfd)
print('shutdown-ok')
PYEOF
[ $slp -gt 0 ] && sleep $slp; umount $MNT 2>&1; echo urc=\$?; \
echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; \
dmesg | sed -n \"/$tag/,\\\$p\" | grep -E 'P163-WITHDRAW-STAMP|clean teardown|released heartbeat|Shutting down|shut down'" 2>/dev/null
}

verdict_shutdown() {  # stdin = arm output; $1 = arm name
  local out arm=$1
  out=$(cat)
  echo "$out" | sed 's/^/  | /'
  if echo "$out" | grep -q "P163-WITHDRAW-STAMP" && \
     ! echo "$out" | grep -q "clean teardown"; then
    echo "ARM-$arm PASS: WITHDRAWN stamped, no clean-teardown release"
    return 0
  fi
  echo "ARM-$arm FAIL: expected P163-WITHDRAW-STAMP and no 'clean teardown'"
  return 1
}

remount_arm() {
  # Fix 3c: the loop device is host-private, so the operator assertion behind
  # single_node_exclusive=1 is TRUE here — the WITHDRAWN slot's fence gets a
  # SINGLE_NODE_EXCLUSIVE certificate and the dirty slice must be REPLAYED.
  # Reset to 0 after so nothing later inherits the assertion.
  local out tag=DSR-REMOUNT-$RUN
  out=$($SSH "$NODE" "echo $tag > /dev/kmsg; \
    echo 1 > /sys/module/mxfs/parameters/single_node_exclusive; \
    mount -t mxfs $DEV $MNT 2>&1; echo rc=\$?; \
    cat $MNT/b4/marker 2>&1; umount $MNT 2>&1; \
    echo 0 > /sys/module/mxfs/parameters/single_node_exclusive; \
    dmesg | sed -n \"/$tag/,\\\$p\" | grep -E 'ADOPTED|adopt|WITHDRAWN|recovery|Recovery|P227|P273|P163|P274|P238|slot' | head -30" 2>/dev/null)
  echo "$out" | sed 's/^/  | /'
  if echo "$out" | grep -q "B4-dirty-slice"; then
    echo "ARM-remount PASS: fsync'd marker survived shutdown+umount+remount"
    return 0
  fi
  echo "ARM-remount FAIL: marker lost (dirty slice consumed without replay)"
  return 1
}

echo "=== reload module on $NODE (want sv $WANT_SV) ==="
sv=$(reload | tr -d '\r\n ')
if [ "$sv" != "$WANT_SV" ]; then
  echo "FAIL: $NODE running sv=$sv want=$WANT_SV"; exit 1
fi
echo "loaded sv=$sv"

rc=0
case "$ARM" in
  race|all)
    echo "=== arm race: setup ==="; setup_loop
    shutdown_arm DIAG-DSR-RACE-$RUN 0 | verdict_shutdown race || rc=1
    if [ "$ARM" = all ]; then
      echo "=== arm remount (after race) ==="
      remount_arm || rc=1
    fi
    ;;&
  delay|all)
    echo "=== arm delay: setup ==="; setup_loop
    shutdown_arm DIAG-DSR-DELAY-$RUN 3 | verdict_shutdown delay || rc=1
    ;;&
  remount)
    remount_arm || rc=1
    ;;
esac
exit $rc
