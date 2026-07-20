#!/bin/bash
# sess49 repro: concurrent mkdir -p <shared>/sub on all nodes + touch sub/nodeN.
# Mimics tests/lib/cluster.sh barrier_signal. Counts touch ENOENT failures
# (peer-created subdir not visible to the losing node).
set -u
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
NODES=(test1 test2 test3 test4)
ITERS=${1:-20}
fails=0
for i in $(seq 1 "$ITERS"); do
  sub="$MNT/.repro_bar/b$i"
  bash tools/mxfs_sshpass.sh test1 "$PASS" "mkdir -p $MNT/.repro_bar 2>/dev/null; rm -rf $sub 2>/dev/null" >/dev/null 2>&1
  tmpd=$(mktemp -d)
  for idx in 1 2 3 4; do
    n=${NODES[$((idx-1))]}
    bash tools/mxfs_sshpass.sh "$n" "$PASS" \
      "mkdir -p $sub 2>/dev/null; touch $sub/node$idx 2>&1; echo RC=\$?" \
      >"$tmpd/$idx" 2>/dev/null &
  done
  wait
  for idx in 1 2 3 4; do
    if ! grep -q "RC=0" "$tmpd/$idx" 2>/dev/null; then
      fails=$((fails+1))
      echo "FAIL iter=$i node=$idx: $(grep -v '^$' $tmpd/$idx | tr '\n' ' ')"
    fi
  done
  rm -rf "$tmpd"
done
echo "TOTAL touch fails: $fails / $((ITERS*4))"
