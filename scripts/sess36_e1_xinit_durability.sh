#!/bin/bash
# Sess36 E1: cross-initiator durability test (no mxfs).
#
# Two VMs (test1, test2) each have /dev/sda mapped to the same shared
# LUN via tcm_loop. From VM1 write a known pattern to an LBA. From VM2
# read it back. If the pattern appears, the storage stack is sound. If
# zeros, the cliff is real.
#
# Per RULE 3: persistent script lives in source tree.
#
# WARNING: writes to /dev/sda directly. Picks an LBA at the end of the
# disk that's unlikely to collide with mxfs's structures, but ALWAYS
# unmount mxfs first to be safe. Restorable via cluster_reset.sh +
# cluster_mkfs_mount.sh.
#
# Usage: sess36_e1_xinit_durability.sh [<LBA-sector>]
# Default LBA: 3900000000 (~1.95 TB into the 2 TB SSD).

set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
LBA="${1:-3900000000}"
TEST1=192.168.120.186
TEST2=192.168.120.182

echo "=== Phase 0: unmount mxfs on both nodes ==="
for h in "$TEST1" "$TEST2"; do
  $SSH "$h" "$PF" 'sudo umount /mnt/shared 2>&1 | head -3' 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  ${h}: |"
done

echo
echo "=== Phase 1: VM1 writes a known pattern to LBA $LBA ==="
PATTERN="SESS36-E1-XINIT-DURABILITY-TEST-$(date +%s)"
$SSH "$TEST1" "$PF" "
  echo -n '$PATTERN' | sudo dd of=/tmp/pattern bs=$((${#PATTERN})) count=1 status=none 2>&1
  sudo dd if=/dev/zero of=/tmp/blk bs=4096 count=1 status=none 2>&1
  sudo dd if=/tmp/pattern of=/tmp/blk conv=notrunc bs=$((${#PATTERN})) count=1 status=none 2>&1
  sudo dd if=/tmp/blk of=/dev/sda bs=4096 count=1 seek=$((${LBA} / 8)) oflag=direct,sync status=none 2>&1
  sudo blockdev --flushbufs /dev/sda
  echo VM1_WRITE_DONE pattern_first8=\$(head -c 8 /tmp/blk | xxd | head -1)
" 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  VM1: |"

echo
echo "=== Phase 2: VM2 reads the LBA back ==="
$SSH "$TEST2" "$PF" "
  sudo blockdev --flushbufs /dev/sda
  out=\$(sudo dd if=/dev/sda bs=4096 count=1 skip=$((${LBA} / 8)) iflag=direct status=none 2>&1)
  echo \"\$out\" | head -c $((${#PATTERN} + 16)) | xxd | head -2
  if echo \"\$out\" | head -c $((${#PATTERN})) | grep -q 'SESS36-E1'; then
    echo VERDICT_PASS: VM2 sees VM1\\'s pattern intact
  else
    echo VERDICT_FAIL: VM2 does NOT see VM1\\'s pattern
  fi
" 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  VM2: |"

echo
echo "=== Phase 3: host-side read verification ==="
echo "  HOST /dev/sda:"
sudo dd if=/dev/sda bs=4096 count=1 skip=$((LBA / 8)) iflag=direct status=none 2>&1 | head -c $((${#PATTERN} + 16)) | xxd | head -2 | sed "s|^|    |"
echo "  HOST /dev/sdc (the LIO loopback):"
sudo dd if=/dev/sdc bs=4096 count=1 skip=$((LBA / 8)) iflag=direct status=none 2>&1 | head -c $((${#PATTERN} + 16)) | xxd | head -2 | sed "s|^|    |"

echo
echo "=== Phase 4: zero out the test region (clean up) ==="
sudo dd if=/dev/zero of=/dev/sda bs=4096 count=1 seek=$((LBA / 8)) oflag=direct,sync status=none 2>&1
echo "  Zeroed."

echo
echo "=== Interpretation ==="
echo " - If VM2 sees VM1's pattern → storage stack is sound."
echo "   The mxfs bug is in v5 itself; sess36 should start v6 work."
echo " - If VM2 sees zeros → cross-initiator durability cliff confirmed."
echo "   Even a perfect cluster filesystem won't pass on this hardware."
echo "   sess36 should evaluate alternate storage (ramdisk, NVMe with PLP, fileio backstore)."
