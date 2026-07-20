#!/bin/bash
# cross_visibility discriminator: H1 (in-core staleness / reload-not-firing)
# vs H2 (durability / node's write never reached readable disk).
#
# Each node writes nodeN.txt+sync into a shared dir.  After a settle, every
# node stats every nodeM.txt.  For each MISS we then drop_caches on the
# reader and re-stat:
#   - reappears after drop_caches  => H1 (on-disk correct, in-core stale)
#   - still missing after drop_caches+reread => H2 (durability)
#
# Usage: tests/cv_discriminator.sh [N]   (default 4 nodes test1..testN)
set -u
N="${1:-4}"
PASS=/tmp/.mxfs_pass
SSH=/src/mxfs/tools/mxfs_sshpass.sh
MNT=/mnt/shared
DIR="$MNT/.cvdisc"

ssh_n() { timeout 30 "$SSH" "test$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning:|Unauthorized|authorized user|disconnect immediately'; }

echo "=== reset test dir on node1 ==="
ssh_n 1 "rm -rf $DIR; mkdir -p $DIR; sync"
sleep 1

echo "=== phase 1: each node writes its file + sync (parallel) ==="
pids=""
for i in $(seq 1 "$N"); do
  ssh_n "$i" "echo 'hello from node $i' > $DIR/node$i.txt; sync" &
  pids="$pids $!"
done
wait $pids
echo "all writes+sync returned"

echo "=== settle 2s ==="
sleep 2

echo "=== phase 2: verify + discriminate ==="
for r in $(seq 1 "$N"); do
  echo "--- reader test$r ---"
  for m in $(seq 1 "$N"); do
    out=$(ssh_n "$r" "if [ -f $DIR/node$m.txt ]; then echo VIS; else echo MISS; fi")
    if echo "$out" | grep -q VIS; then
      echo "  node$m.txt: VIS"
    else
      echo "  node$m.txt: MISS  -> dropping caches + reread"
      out2=$(ssh_n "$r" "echo 2 > /proc/sys/vm/drop_caches; sync; sleep 0.3; if [ -f $DIR/node$m.txt ]; then echo VIS_AFTER_DROP; cat $DIR/node$m.txt; else echo STILL_MISS_AFTER_DROP; fi")
      echo "    after drop_caches: $out2"
    fi
  done
done
echo "=== done ==="
