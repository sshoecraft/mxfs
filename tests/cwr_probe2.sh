#!/bin/bash
# cwr_probe2.sh — distinguish dir-coherency (peer resolves wrong inode) from
# write-persistence for the cross_write_read di_size=0 failure.
# Assumes test1,test2 mounted at /mnt/shared.  Both nodes CONCURRENTLY create
# a 1MB file in a SHARED dir, then each reports the ino+size IT resolves for
# BOTH files.  If a node resolves the peer's file to a different ino than the
# owner sees -> dir-coherency (stale dirent).  If same ino but size 0 ->
# persistence/flush.
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
D=/mnt/shared/.probe2
s() { timeout 40 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning|Unauthorized|authorized|^$'; }
s test1 "mkdir -p $D; sync"; sleep 1
echo "== concurrent write (file + .md5 sidecar, mimics test) =="
s test1 "dd if=/dev/urandom of=/tmp/src1 bs=1M count=1 status=none; cp /tmp/src1 $D/f1; sync; md5sum /tmp/src1 | awk '{print \$1}' > $D/f1.md5; rm -f /tmp/src1" &
s test2 "dd if=/dev/urandom of=/tmp/src2 bs=1M count=1 status=none; cp /tmp/src2 $D/f2; sync; md5sum /tmp/src2 | awk '{print \$1}' > $D/f2.md5; rm -f /tmp/src2" &
wait
sleep 2
echo "== owner view =="
s test1 "stat -c 'test1 sees f1 ino=%i size=%s' $D/f1"
s test2 "stat -c 'test2 sees f2 ino=%i size=%s' $D/f2"
echo "== cross view: md5sum (read) FIRST, then stat (mimics the test) =="
s test2 "echo -n 'test2 md5 f1: '; md5sum $D/f1 | awk '{print \$1}'; stat -c 'test2 sees f1 ino=%i size=%s' $D/f1"
s test1 "echo -n 'test1 md5 f2: '; md5sum $D/f2 | awk '{print \$1}'; stat -c 'test1 sees f2 ino=%i size=%s' $D/f2"
echo "(empty md5 = d41d8cd98f00b204e9800998ecf8427e)"
echo "== cleanup =="
s test1 "rm -rf $D; sync"
