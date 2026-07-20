#!/bin/bash
# Fast reproducer for cross_write_read tiny-sidecar empty-read.
# All N nodes concurrently: write data_nodeN (1MB) + data_nodeN.md5 (tiny)
# into the SAME dir, barrier via shared file, then each node reads ALL
# nodes' .md5 files and reports any that come back empty/short.
set -u
NODES=(test1 test2 test3 test4)
N=${#NODES[@]}
PW=/tmp/.mxfs_pass
DIR=/mnt/shared/.mxfs_test/cross_write_read
ROUNDS=${1:-1}

# clean
timeout 10 bash tools/mxfs_sshpass.sh test1 $PW "rm -rf $DIR; mkdir -p $DIR; sync" 2>/dev/null

for r in $(seq 1 $ROUNDS); do
  echo "===== ROUND $r ====="
  timeout 10 bash tools/mxfs_sshpass.sh test1 $PW "rm -f $DIR/*; sync" 2>/dev/null
  # launch concurrent writers
  for i in $(seq 1 $N); do
    node=${NODES[$((i-1))]}
    timeout 25 bash tools/mxfs_sshpass.sh $node $PW "
      dd if=/dev/urandom of=/tmp/cwr_$i bs=1M count=1 2>/dev/null
      cp /tmp/cwr_$i $DIR/data_node$i
      sync
      md5sum /tmp/cwr_$i | awk '{print \$1}' > $DIR/data_node$i.md5
      sync
      touch $DIR/.done_$i
      rm -f /tmp/cwr_$i
    " 2>/dev/null &
  done
  wait
  # barrier: wait for all .done markers visible from test1
  timeout 15 bash tools/mxfs_sshpass.sh test1 $PW "
    for t in \$(seq 1 30); do
      c=\$(ls $DIR/.done_* 2>/dev/null | wc -l)
      [ \$c -ge $N ] && break
      sleep 0.3
    done" 2>/dev/null
  sleep 2
  # each node reads ALL md5 files; report empties
  for i in $(seq 1 $N); do
    node=${NODES[$((i-1))]}
    out=$(timeout 15 bash tools/mxfs_sshpass.sh $node $PW "
      for n in \$(seq 1 $N); do
        sz=\$(stat -c%s $DIR/data_node\$n.md5 2>/dev/null)
        content=\$(cat $DIR/data_node\$n.md5 2>/dev/null)
        if [ \"\$sz\" != 33 ]; then echo \"  $node reads node\$n.md5: size=\$sz content=[\$content]\"; fi
      done" 2>/dev/null)
    [ -n "$out" ] && echo "$out"
  done
  echo "  (round $r done; empties above if any)"
done
