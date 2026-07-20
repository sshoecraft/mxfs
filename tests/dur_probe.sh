#!/bin/bash
# dur_probe.sh — isolate inode di_size durability vs peer-read corruption.
# Assumes a 2-node cluster (test1,test2) is already mounted at /mnt/shared.
# 1) test1 writes a 1MB file + sync.
# 2) test1 reads back its OWN size (owner view) BEFORE any peer touch.
# 3) test2 stats the file (peer view) — the suspected corrupting access.
# 4) test1 re-reads its own size AFTER the peer touch.
# 5) test2 stats again.
# Each step timestamped.  No md5/cat (avoids extra atime churn beyond stat).
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
F=/mnt/shared/durprobe.$$
s() { timeout 30 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -v 'Warning\|Unauthorized\|authorized user' | sed '/^$/d'; }
echo "== [t1] write 1MB + sync =="
s test1 "dd if=/dev/urandom of=$F bs=1M count=1 status=none; sync; echo wrote; stat -c 't1_own_after_write=%s' $F"
sleep 2
echo "== [t1] own size before peer touch =="
s test1 "stat -c 't1_own_pre_peer=%s' $F"
echo "== [t2] FIRST peer stat (suspected corruptor) =="
s test2 "stat -c 't2_peer_1=%s' $F"
echo "== [t1] own size after peer stat =="
s test1 "stat -c 't1_own_post_peer=%s' $F"
echo "== [t2] second peer stat =="
s test2 "stat -c 't2_peer_2=%s' $F"
echo "== [t1] cleanup =="
s test1 "rm -f $F; sync"
