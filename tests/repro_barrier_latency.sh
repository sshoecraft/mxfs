#!/bin/bash
# sess50 repro: measure barrier-VISIBILITY latency (Q3 from sess49 handoff).
# Mimics tests/lib/cluster.sh barrier_signal+barrier_wait exactly:
#   each node: mkdir -p <bdir>; touch <bdir>/nodeN   (signal)
#   each node: poll  find <bdir> -name 'node*' | wc -l  until ==4 (wait)
# Reports per-node, per-iter the seconds until each node SEES all 4 markers.
# This isolates the ~120s stall: is it touch-create (ENOENT) or readdir-visibility?
set -u
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
NODES=(test1 test2 test3 test4)
ITERS=${1:-10}
TIMEOUT=${2:-130}
for i in $(seq 1 "$ITERS"); do
  bdir="$MNT/.repro_lat/b$i"
  bash tools/mxfs_sshpass.sh test1 "$PASS" "mkdir -p $MNT/.repro_lat 2>/dev/null; rm -rf $bdir 2>/dev/null" >/dev/null 2>&1
  tmpd=$(mktemp -d)
  for idx in 1 2 3 4; do
    n=${NODES[$((idx-1))]}
    # signal then poll-wait, printing elapsed at the moment all 4 are visible
    bash tools/mxfs_sshpass.sh "$n" "$PASS" "
      mkdir -p $bdir 2>/dev/null
      touch $bdir/node$idx 2>&1
      sig=\$?
      start=\$(date +%s.%N)
      seen=0; el=0
      while [ \$el -lt $TIMEOUT ]; do
        c=\$(find $bdir -maxdepth 1 -name 'node*' 2>/dev/null | wc -l | tr -d ' ')
        if [ \"\$c\" -ge 4 ]; then seen=1; break; fi
        sleep 0.25
        now=\$(date +%s.%N); el=\$(printf '%.0f' \$(echo \"\$now - \$start\" | bc))
      done
      end=\$(date +%s.%N)
      lat=\$(echo \"\$end - \$start\" | bc)
      finalc=\$(find $bdir -maxdepth 1 -name 'node*' 2>/dev/null | wc -l | tr -d ' ')
      echo \"sig=\$sig seen=\$seen lat=\$lat finalcount=\$finalc\"
    " >"$tmpd/$idx" 2>/dev/null &
  done
  wait
  bino=$(bash tools/mxfs_sshpass.sh test1 "$PASS" "stat -c %i $bdir 2>/dev/null" 2>/dev/null | tr -d ' ')
  echo "=== iter $i (bdir_ino=$bino) ==="
  for idx in 1 2 3 4; do
    printf '  node%s: %s\n' "$idx" "$(grep -v '^$' $tmpd/$idx | tr '\n' ' ')"
  done
  rm -rf "$tmpd"
done
