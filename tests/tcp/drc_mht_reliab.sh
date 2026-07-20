#!/bin/bash
# drc_mht_reliab.sh N MHT — run N clean-reboot 8/tcp dir_reuse iters at given
# inode_mht_ms, logging PASS/FAIL + wall time each. (sess2 ccloop)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
N="${1:-5}"; MHT="${2:-1500}"
pass=0
for i in $(seq 1 "$N"); do
  t0=$SECONDS
  r=$(MXFS_EXTRA_MODARGS="inode_mht_ms=$MHT" bash tests/tcp/drc_reliab_iter.sh 8 2>&1 | grep -oE 'ITER_RESULT=(PASS|FAIL)')
  dt=$((SECONDS - t0))
  echo "ITER $i: $r wall=${dt}s"
  [ "$r" = "ITER_RESULT=PASS" ] && pass=$((pass+1))
done
echo "SUMMARY: $pass/$N PASS at mht=$MHT"
