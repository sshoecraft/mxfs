#!/bin/bash
# MXFS v0.3.0 Quick Single-Node Test
# Run from dev machine. Requires: test VM running, NFS mounted, password file.

set -e

VM=${1:-test13}
PASS_FILE=${2:-/tmp/.mxfs_pass}
MXFS_SSHPASS="$(dirname $(dirname $0))/tools/mxfs_sshpass.sh"

echo "Testing on $VM..."

$MXFS_SSHPASS $VM $PASS_FILE "
mount -t nfs 192.168.1.4:/src /src 2>/dev/null
rmmod mxfs 2>/dev/null; umount /mnt/mxfs 2>/dev/null
dd if=/dev/zero of=/tmp/t.img bs=1M count=500 2>/dev/null
losetup -d /dev/loop0 2>/dev/null; losetup /dev/loop0 /tmp/t.img
echo y | /src/mxfs/tools/mkfs_mxfs /dev/loop0 2>&1 | tail -1
insmod /src/mxfs/mxfs.ko && mkdir -p /mnt/mxfs && mount -t mxfs /dev/loop0 /mnt/mxfs
P=0; F=0; T=0
r() { T=\\\$((T+1)); if eval \"\\\$2\" >/dev/null 2>&1; then P=\\\$((P+1)); else echo \"FAIL: \\\$1\"; F=\\\$((F+1)); fi; }
r 'create+read' 'echo hi > /mnt/mxfs/f && test \"\\\$(cat /mnt/mxfs/f)\" = hi'
r 'mkdir+rmdir' 'mkdir /mnt/mxfs/d && echo n > /mnt/mxfs/d/x && rm /mnt/mxfs/d/x && rmdir /mnt/mxfs/d'
r 'symlink' 'ln -s f /mnt/mxfs/s'
r 'large' 'dd if=/dev/urandom of=/mnt/mxfs/big bs=4k count=200 2>/dev/null'
r 'fallocate' 'fallocate -l 5M /mnt/mxfs/pre'
r 'xattr' 'python3 -c \"import os; os.setxattr(\\\\\\\"/mnt/mxfs/f\\\\\\\",\\\\\\\"user.k\\\\\\\",b\\\\\\\"v\\\\\\\")\"'
r 'many' 'for i in \\\$(seq 1 50); do touch /mnt/mxfs/m\\\$i 2>/dev/null; done; test \\\$(ls /mnt/mxfs/m* | wc -l) -ge 40'
MD5=\\\$(md5sum /mnt/mxfs/big | awk '{print \\\$1}')
sync && umount /mnt/mxfs && mount -t mxfs /dev/loop0 /mnt/mxfs
r 'persist-md5' 'test \"\\\$(md5sum /mnt/mxfs/big | awk \"{print \\\\\\\$1}\")\" = \"\\\$MD5\"'
r 'persist-data' 'test \"\\\$(cat /mnt/mxfs/f)\" = hi'
r 'persist-xattr' 'python3 -c \"import os; assert os.getxattr(\\\\\\\"/mnt/mxfs/f\\\\\\\",\\\\\\\"user.k\\\\\\\")==b\\\\\\\"v\\\\\\\"\"'
echo \"\\\$P/\\\$T PASS, \\\$F FAIL\"
" 2>&1 | tail -3

echo "Done."
