#!/bin/bash
# Time `run.sh N tcp dir_reuse_coherency` (the actual criterion cmd, NO reboot)
# at a given MHT, to compare against the RULE-0 budget (60*N). sess2 ccloop.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
N="${1:-8}"; MHT="${2:-1500}"
t0=$SECONDS
OUT=$(MXFS_EXTRA_MODARGS="inode_mht_ms=$MHT" ./run.sh "$N" tcp dir_reuse_coherency 2>&1)
dt=$((SECONDS-t0))
echo "$OUT" | grep -E 'PASS|FAIL|dir_reuse' | tail -3
echo "RUNSH_WALL=${dt}s  BUDGET=$((60*N))s  $([ $dt -le $((60*N)) ] && echo WITHIN || echo OVER)"
