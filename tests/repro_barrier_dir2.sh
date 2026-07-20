#!/bin/bash
# sess49 repro+classifier: concurrent mkdir -p <shared>/sub + touch sub/nodeN.
# On a touch failure, CLASSIFY the cause:
#   - re-stat the subdir from the FAILING node after 0s and after a short retry.
#   - check the subdir from node1 (the reference).
# If node1 sees it but the failing node keeps missing it -> READ-SIDE STALE
# (the peer's mkdir is on disk/visible to node1 but the failing node's cached
#  parent dir block is stale).  If neither sees it briefly then both do ->
# DURABILITY (not yet durable when read).
set -u
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
NODES=(test1 test2 test3 test4)
ITERS=${1:-20}
fails=0
for i in $(seq 1 "$ITERS"); do
  sub="$MNT/.repro_bar2/b$i"
  bash tools/mxfs_sshpass.sh test1 "$PASS" "mkdir -p $MNT/.repro_bar2 2>/dev/null; rm -rf $sub 2>/dev/null" >/dev/null 2>&1
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
      n=${NODES[$((idx-1))]}
      # classify: failing node immediate re-stat, then after retry; node1 reference
      cls=$(bash tools/mxfs_sshpass.sh "$n" "$PASS" \
        "test -d $sub && echo NOW=Y || echo NOW=N; sleep 2; test -d $sub && echo RETRY=Y || echo RETRY=N" 2>/dev/null | tr '\n' ' ')
      ref=$(bash tools/mxfs_sshpass.sh test1 "$PASS" "test -d $sub && echo REF1=Y || echo REF1=N" 2>/dev/null)
      echo "FAIL iter=$i node=$idx: $(grep -v '^$' $tmpd/$idx|tr '\n' ' ') | $cls $ref"
    fi
  done
  rm -rf "$tmpd"
done
echo "TOTAL touch fails: $fails / $((ITERS*4))"
