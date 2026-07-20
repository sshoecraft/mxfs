#!/bin/bash
# dirvis_probe.sh — minimal cross-node directory-entry visibility latency.
# test1 creates a uniquely-named file in a SHARED dir; test2 polls `ls` until
# it appears (or 30s).  Reports appearance latency per iteration.  This is the
# barrier_wait primitive that test_rename/unlink_visibility depend on.
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
D=/mnt/shared/.dvp
ITERS=${1:-8}
s(){ timeout 45 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning|Unauthorized|authorized user'; }
s test1 "rm -rf $D; mkdir -p $D; sync"; sleep 1
for k in $(seq 1 $ITERS); do
  f="mark_${k}_$RANDOM"
  # test1 creates the marker (mimics barrier_signal: touch in shared dir)
  s test1 "touch $D/$f; sync" >/dev/null
  # test2 polls for visibility, measuring latency in 0.1s steps up to 30s
  lat=$(s test2 "for t in \$(seq 1 300); do if [ -e $D/$f ]; then echo \$((t-1)); exit 0; fi; sleep 0.1; done; echo TIMEOUT")
  echo "iter $k: visible_after=${lat} (x0.1s)"
done
s test1 "rm -rf $D; sync"
