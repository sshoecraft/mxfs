#!/bin/bash
# drc_modarg_reliab.sh N "MODARGS" — N clean-reboot 8/tcp dir_reuse iters with
# arbitrary MXFS_EXTRA_MODARGS, logging PASS/FAIL + wall. sess2 ccloop.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
N="${1:-3}"; MA="${2:-}"
pass=0
for i in $(seq 1 "$N"); do
  t0=$SECONDS
  r=$(MXFS_EXTRA_MODARGS="$MA" bash tests/tcp/drc_reliab_iter.sh 8 2>&1 | grep -oE 'ITER_RESULT=(PASS|FAIL)')
  echo "ITER $i: $r wall=$((SECONDS-t0))s  [$MA]"
  [ "$r" = "ITER_RESULT=PASS" ] && pass=$((pass+1))
done
echo "SUMMARY: $pass/$N PASS  [$MA]"
