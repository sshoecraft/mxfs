#!/bin/bash
# drc_reliability.sh (sess49 ccloop 4cb2d0a2) — reliability sweep for the
# 1/2/4/8-node tcp dir_reuse_coherency criterion.  Runs drc_dirtyskip.sh
# (reboot-clean + run) REPEAT times per node count and tallies PASS/FAIL so a
# "100%" claim is backed by consecutive clean-reboot runs, not a single pass.
#
# Usage: tests/drc_reliability.sh "<modargs>" <rounds> <repeat> <N1> [N2 ...]
#   e.g. tests/drc_reliability.sh "" 24 3 8        # 3× 8-node, 24 rounds each
#        tests/drc_reliability.sh "" 12 1 1 2 4    # one run each at 1,2,4
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
MODARGS="${1:-}"; ROUNDS="${2:-24}"; REPEAT="${3:-3}"; shift 3 || true
NLIST="$*"; [ -z "$NLIST" ] && NLIST="8"
SCR="${SCRATCH:-/tmp}"
echo "########## RELIABILITY SWEEP modargs=[$MODARGS] rounds=$ROUNDS repeat=$REPEAT nodes=[$NLIST] @ $(date -u +%T) ##########"
declare -A pass fail
for N in $NLIST; do
  pass[$N]=0; fail[$N]=0
  for r in $(seq 1 "$REPEAT"); do
    LOG="$SCR/drcrel_N${N}_r${r}.log"
    bash tests/drc_dirtyskip.sh "$MODARGS" "$ROUNDS" "$N" >"$LOG" 2>&1
    if grep -qE "PASS  dir_reuse_coherency  \(nodes_pass=$N/$N\)" "$LOG"; then
      pass[$N]=$(( ${pass[$N]} + 1 )); verdict=PASS
    else
      fail[$N]=$(( ${fail[$N]} + 1 )); verdict=FAIL
    fi
    res=$(grep -E 'nodes_pass=' "$LOG" | tail -1)
    echo "  N=$N run=$r/$REPEAT -> $verdict | $res | log=$LOG @ $(date -u +%T)"
  done
done
echo "===== TALLY ====="
ok=1
for N in $NLIST; do
  echo "  N=$N: PASS=${pass[$N]} FAIL=${fail[$N]} (of $REPEAT)"
  [ "${fail[$N]}" -ne 0 ] && ok=0
done
echo "OVERALL: $([ $ok = 1 ] && echo ALL-PASS || echo HAS-FAILURES)"
echo "########## sweep done @ $(date -u +%T) ##########"
