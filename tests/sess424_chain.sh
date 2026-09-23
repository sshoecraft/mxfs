#!/bin/bash
# sess424_chain.sh — build + rig-verify 0.35.0 (tcp-authority-ledger step 4:
# ordered page-authority handoff, v5 wiring) on the CURRENT fleet.
#
# Same shape as sess422_chain.sh, plus instrumented evidence capture the s422 run
# lacked: after EVERY tcp prep / stage, each node's dmesg lines for the
# ledger (P-TAUTH-*), mount refusals, REMASTER (status=12) and lock-retry
# exhaustion are copied out RAW (not just counted), so a hung workload or
# a refused mount can be diagnosed from the evidence dir.  The s422 run on
# 0.34.0 had 4/32 tcp mounts refused, a hung 30 s workload and 13 hung
# unmounts with nothing captured.
#
#  0. build VERSION + prove complete; 1. tests/tauth usermode gate
#  2. prep 32/tcp (mpatha) + sweep; tcp_token_plumbing_verify + sweep
#  3. prep + sweep; d0287_remaster_measure + sweep
#  4. prep 32/caw; full 32/caw board (regression gate for the shared edits)
#
# budget: build 500 + proof 500 + tauth 120 + 3 preps x 300 + 4 sweeps x 60
# + token 400 + d0287 600 + board 1900 => ~5260 s.  Each stage has its own
# timeout.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s424}
E=tests/evidence
D="$E/sess424_${LABEL}_dmesg"
mkdir -p "$E" "$D"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
PAT='P-TAUTH|P-GOODBYE|MXFS-MEMBERSHIP|P-TCPDEATH|status=12|lock request failed after|P-LKTIMEOUT|P240-QUAR|mount.*refus|can.t read superblock|P-D512|P-DEPART|bad superblock|mxfs: mount'
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess424_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess424_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
sweep() {
  # per-node raw evidence, own file + own rc; one fleet call
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "dmesg | grep -aE '$PAT' | tail -400" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -ac P-TAUTH "$D/${st}_test$i.txt")" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -aoE 'P-TAUTH-[A-Z0-9-]+' | sort | uniq -c | sort -rn | tr '\n' ' ')"
}
{
  echo "=== sess424 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess424_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 120 make -C tests/tauth clean test > "$E/sess424_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -E 'RESULT|fails=' "$E/sess424_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_tcp token; sweep prep_token
  env $TCPENV timeout 400 tests/tcp_token_plumbing_verify.sh "$LABEL"; echo "STAGE token rc=$?"; sweep token
  prep_tcp d0287; sweep prep_d0287
  env $TCPENV timeout 600 tests/d0287_remaster_measure.sh "$LABEL"; echo "STAGE d0287 rc=$?"; sweep d0287
  prep_caw board
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess424_${LABEL}.log" 2>&1
