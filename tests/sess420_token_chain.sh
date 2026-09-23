#!/bin/bash
# sess420_token_chain.sh — build + verify 0.30.0 (TCP token plumbing, step 1
# of docs/tcp-authority-ledger.md), relay-proof (setsid+nohup).
#
#  0. build VERSION (make modules + make tools) and PROVE it complete (second
#     make compiles nothing — see sess419_master_chain.sh for why).
#  1. 32/tcp prep (mpatha condition); tests/tcp_token_plumbing_verify.sh
#  2. 32/caw prep; full board (tests/sess416_board_0286.sh) — CAW regression
#     for a change that only touches the TCP arms, but the arms are shared
#     entry points and the zero-defect bar wants the board green on every build boarded.
#
# the budget rule (derived): build 2x ~450 s; preps 236 s (cap 300) x2; token verify
# ~60 s (cap 90); board chain ~29 min => ~55 min total.
# Usage: setsid nohup tests/sess420_token_chain.sh <label>
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/sess420_token_${LABEL}.log
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
E=tests/evidence
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess420_token_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess420_token_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
{
  echo "=== token chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess420_token_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC ' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_tcp 1
  timeout 90 tests/tcp_token_plumbing_verify.sh "$LABEL"; echo "STAGE tcptok rc=$?"
  prep_caw 1
  echo "--- board chain $(date -u +%FT%TZ)"
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
