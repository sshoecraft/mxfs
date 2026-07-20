#!/bin/bash
# Create an ISOLATED high-latency SCST scratch target to widen the abort race
# window (disk1 is LVM/ms-latency; the fileio scratch disk2 completes in us, so
# orderly teardown never catches a command in the vulnerable parked-but-owning
# state). Backing: sparse file -> loop -> dm-delay (real per-IO latency) ->
# vdisk_blockio "delaydisk" -> iSCSI target iqn.2026-06.repro:delay.
# All separate from disk1/disk2. Use --teardown to remove everything.
set -u
IMG=/home/steve/disk-delay.img
DM=scst_delay
DEV=delaydisk
TGT=iqn.2026-06.repro:delay
SZ_SECT=$((2*1024*1024*1024/512))   # 2 GiB
RDELAY=${RDELAY:-6}                  # ms read latency
WDELAY=${WDELAY:-6}                  # ms write latency
H=/sys/kernel/scst_tgt/handlers/vdisk_blockio
TROOT=/sys/kernel/scst_tgt/targets/iscsi

setup() {
  sudo modprobe dm-delay 2>/dev/null
  [ -f $IMG ] || sudo truncate -s 2G $IMG
  local LOOP; LOOP=$(losetup -j $IMG 2>/dev/null | cut -d: -f1)
  [ -z "$LOOP" ] && LOOP=$(sudo losetup --find --show $IMG)
  echo "loop=$LOOP"
  sudo dmsetup ls 2>/dev/null | grep -q "^$DM" || \
    echo "0 $SZ_SECT delay $LOOP 0 $RDELAY $LOOP 0 $WDELAY" | sudo dmsetup create $DM
  echo "dm=/dev/mapper/$DM rdelay=${RDELAY}ms wdelay=${WDELAY}ms"
  [ -d $H/../../devices/$DEV ] || \
    echo "add_device $DEV filename=/dev/mapper/$DM" | sudo tee $H/mgmt >/dev/null
  [ -d $TROOT/$TGT ] || echo "add_target $TGT" | sudo tee $TROOT/mgmt >/dev/null
  [ -d $TROOT/$TGT/luns/0 ] || echo "add $DEV 0" | sudo tee $TROOT/$TGT/luns/mgmt >/dev/null
  echo 1 | sudo tee $TROOT/$TGT/enabled >/dev/null
  echo "target $TGT enabled, lun0=$DEV"
}

teardown() {
  for i in $(seq 1 8); do
    sudo iscsiadm -m node -T $TGT -p 127.0.0.1:3260 -I dl_$i -u >/dev/null 2>&1
    sudo iscsiadm -m node -T $TGT -p 127.0.0.1:3260 -I dl_$i -o delete >/dev/null 2>&1
    sudo iscsiadm -m iface -I dl_$i -o delete >/dev/null 2>&1
  done
  echo 0 | sudo tee $TROOT/$TGT/enabled >/dev/null 2>&1
  echo "del 0" | sudo tee $TROOT/$TGT/luns/mgmt >/dev/null 2>&1
  echo "del_target $TGT" | sudo tee $TROOT/mgmt >/dev/null 2>&1
  echo "del_device $DEV" | sudo tee $H/mgmt >/dev/null 2>&1
  sudo dmsetup remove $DM 2>/dev/null
  local LOOP; LOOP=$(losetup -j $IMG 2>/dev/null | cut -d: -f1)
  [ -n "$LOOP" ] && sudo losetup -d $LOOP
  echo "torn down (image $IMG left in place)"
}

case "${1:-setup}" in
  --teardown) teardown ;;
  *) setup ;;
esac
