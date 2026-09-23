#!/bin/bash
# sess422_chain.sh — build + rig-verify 0.34.0 (tcp-authority-ledger step 3:
# master-side durable grants) on the CURRENT fleet.
#
#  0. build VERSION (make modules + make tools) and PROVE it complete (second
#     make compiles nothing — see sess419_master_chain.sh for why).
#  1. usermode gate: tests/tauth (store + ledger + engine harness) must PASS
#     on the built tree before any rig time is spent.
#  2. prep 32/tcp on the multipath LUN (the `tcp` condition's own rig is
#     gone — trap-32-tcp-condition-device-is-xml-sda; MXFS_DEV + MXFS_CRIT
#     keep the run off the primary board), then
#     tests/tcp_token_plumbing_verify.sh (tokens now = durable grant ids)
#  3. prep; tests/d0287_remaster_measure.sh (W must NOT be served during
#     H's pause across a membership change — the step-3 blocker import)
#  4. P-TAUTH sweep: every node's dmesg for ATTACH / IMPORT / GHOST /
#     DOUBLE-GRANT / COLLISION / FAILSTOP / REFUSE / UNACKED counts
#  5. prep 32/caw; full 32/caw board (CAW is untouched by step 3: this is
#     the regression gate for the shared dlm.c / v5_mount.c edits)
#
# budget: build 500 + proof 500 + tauth 120 + 3 preps x 300 + token 400 +
# d0287 600 + board 1900 => ~4900 s.  Each stage carries its own timeout.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s422}
E=tests/evidence
mkdir -p "$E"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess422_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess422_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
{
  echo "=== sess422 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess422_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 120 make -C tests/tauth clean test > "$E/sess422_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -E 'RESULT|fails=' "$E/sess422_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_tcp token
  env $TCPENV timeout 400 tests/tcp_token_plumbing_verify.sh "$LABEL"; echo "STAGE token rc=$?"
  prep_tcp d0287
  env $TCPENV timeout 600 tests/d0287_remaster_measure.sh "$LABEL"; echo "STAGE d0287 rc=$?"
  echo "STAGE ptauth-sweep start"
  for i in $(seq 1 32); do
    ( timeout 20 tools/mxfs_sshpass.sh "test$i" "dmesg | grep -c 'P-TAUTH-ATTACH'; dmesg | grep -c 'P-TAUTH-IMPORT-ACTIVE'; dmesg | grep -c 'P-TAUTH-GHOST'; dmesg | grep -c 'P-TAUTH-DOUBLE-GRANT'; dmesg | grep -c 'P-TAUTH-COLLISION'; dmesg | grep -c 'P-TAUTH-FAILSTOP'; dmesg | grep -c 'P-TAUTH-REFUSE'; dmesg | grep -c 'P-TAUTH-RELEASE-UNACKED'; dmesg | grep -c 'P-TAUTH-POISON'" 2>/dev/null | tr '\n' ' ' > "$E/sess422_${LABEL}_ptauth_test$i.txt"; echo "rc=$?" >> "$E/sess422_${LABEL}_ptauth_test$i.txt" ) &
  done
  wait
  for i in $(seq 1 32); do echo "PTAUTH test$i attach/import/ghost/dblgrant/collision/failstop/refuse/unacked/poison: $(cat "$E/sess422_${LABEL}_ptauth_test$i.txt")"; done
  prep_caw board
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess422_${LABEL}.log" 2>&1
