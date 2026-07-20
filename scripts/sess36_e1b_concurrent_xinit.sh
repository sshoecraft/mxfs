#!/bin/bash
# Sess36 E1b: cross-initiator CONCURRENT writes test.
# E1 showed simple writes work cross-initiator. This tests concurrent
# writes (both VMs writing to same LBA simultaneously) which is closer
# to what mxfs's CAW path does.
#
# Per RULE 3: persistent script lives in source tree.

set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
LBA="${1:-3900000000}"
TEST1=192.168.120.186
TEST2=192.168.120.182
N_WRITES=100

echo "=== Phase 0: ensure mxfs unmounted ==="
for h in "$TEST1" "$TEST2"; do
  $SSH "$h" "$PF" 'sudo umount /mnt/shared 2>&1 | head -3' 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  ${h}: |"
done

echo
echo "=== Phase 1: both VMs concurrently write+read same LBA ($N_WRITES iters) ==="

# VM1 will write pattern 'AAAA' N_WRITES times in a tight loop.
# VM2 will write pattern 'BBBB' N_WRITES times in a tight loop.
# After both finish, VM2 reads and we check what's there.

for h in "$TEST1" "$TEST2"; do
  letter=A; [ "$h" = "$TEST2" ] && letter=B
  $SSH "$h" "$PF" "
    set -e
    sudo dd if=/dev/zero of=/tmp/blk bs=4096 count=1 status=none
    pattern=\$(printf '%${N_WRITES}s' | tr ' ' $letter)
    echo -n \"\$pattern\" | sudo dd of=/tmp/blk conv=notrunc bs=$N_WRITES count=1 status=none 2>&1
    for i in \$(seq 1 $N_WRITES); do
      sudo dd if=/tmp/blk of=/dev/sda bs=4096 count=1 seek=$((LBA / 8)) oflag=direct,sync status=none 2>&1
    done
    echo \"$h DONE\"
  " 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  ${h}: |" &
done
wait

echo
echo "=== Phase 2: blkdev_flushbufs + read from each VM + host ==="
for h in "$TEST1" "$TEST2"; do
  $SSH "$h" "$PF" "
    sudo blockdev --flushbufs /dev/sda
    out=\$(sudo dd if=/dev/sda bs=4096 count=1 skip=$((LBA / 8)) iflag=direct status=none 2>&1)
    n_a=\$(echo -n \"\$out\" | head -c 4096 | tr -d -c 'A' | wc -c)
    n_b=\$(echo -n \"\$out\" | head -c 4096 | tr -d -c 'B' | wc -c)
    n_zero=\$(echo -n \"\$out\" | head -c 4096 | tr -d -c '\0' | wc -c)
    echo \"$h read: n_A=\$n_a n_B=\$n_b n_zeros=\$n_zero (out of 4096)\"
    echo \"$h first16: \$(echo \"\$out\" | head -c 16 | xxd | head -1)\"
  " 2>&1 | grep -vE 'Unauthorized|disconnect|Warning|^$' | sed "s|^|  ${h}: |"
done

echo
echo "  HOST /dev/sda:"
out=$(sudo dd if=/dev/sda bs=4096 count=1 skip=$((LBA / 8)) iflag=direct status=none 2>&1)
n_a=$(echo -n "$out" | head -c 4096 | tr -d -c 'A' | wc -c)
n_b=$(echo -n "$out" | head -c 4096 | tr -d -c 'B' | wc -c)
n_zero=$(echo -n "$out" | head -c 4096 | tr -d -c '\0' | wc -c)
echo "    HOST n_A=$n_a n_B=$n_b n_zeros=$n_zero (out of 4096)"
echo "    first16: $(echo "$out" | head -c 16 | xxd | head -1)"

echo
echo "=== Phase 3: cleanup (zero) ==="
sudo dd if=/dev/zero of=/dev/sda bs=4096 count=1 seek=$((LBA / 8)) oflag=direct,sync status=none

echo
echo "=== Interpretation ==="
echo "  Either A's or B's pattern should win (last writer); the buf"
echo "  should be MOSTLY one letter or the other. Zeros suggests the"
echo "  bug surface (writes ack'd but lost)."
