#!/bin/bash
# sess426_chain.sh — build + rig-verify 0.36.1 on the CURRENT fleet:
#   D-0345 route + D-0347 conditional commit (verified once on s429, 0.36.0),
#   D-0349 per-phase commit timers (P-TAUTH-STORE-STATS, periodic every 200
#   commits), D-0348 errno capture in the token harness, the D-0346 P34H
#   alias instrumentation + reproducer, D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO
#   items 1+2 (P-HB-INC-ZERO), D-DUP-RELEASE invariant 4 (P283-REL-FINISH-SKIP),
#   D-0347 election refinement (v5_bootstrap_ready).
#
#  0. build VERSION + prove complete; 1. tests/tauth usermode gate
#  2. prep 32/caw; tests/dir_recreate_estale.sh (D-0346, 60 s) + sweep
#  3. tests/incarnation_mismatch_probe.sh zero (D-MONITOR item 3, 225 s) + sweep
#  4. prep 32/tcp (mpatha); tcp_token_plumbing_verify + sweep (D-0348/D-0349)
#  5. prep tcp; d0287_remaster_measure + sweep
#  6. prep 32/caw; full 32/caw board (regression gate)
#
# budget: build 500 + proof 500 + tauth 180 + 4 preps x 300 + dre 90 +
# incprobe 260 + token 400 + d0287 600 + board 1900 + 5 sweeps x 60 => ~5930 s.
# Every stage carries its own timeout.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s430}
E=tests/evidence
D="$E/sess426_${LABEL}_dmesg"
mkdir -p "$E" "$D"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
PAT='P-TAUTH|P-GOODBYE|MXFS-MEMBERSHIP|P-TCPDEATH|status=12|lock request failed after|P-LKTIMEOUT|P240-QUAR|mount.*refus|can.t read superblock|P-D512|P-DEPART|bad superblock|mxfs: mount|P-HB-INC-ZERO|P237-|P34H-POISON|P283-REL-FINISH-SKIP|P-DIRCRC-RETRY-FAIL'
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess426_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess426_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
sweep() {
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "dmesg | grep -aE '$PAT' | tail -400" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -ac 'P-TAUTH\|P34H\|P-HB-INC\|P283' "$D/${st}_test$i.txt")" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -aoE 'P-TAUTH-[A-Z0-9-]+|P34H-POISON-[A-Z]+|P-HB-INC-ZERO|P283-REL-FINISH-SKIP|P237-[A-Z-]+|P-DIRCRC-RETRY-FAIL' | sort | uniq -c | sort -rn | tr '\n' ' ')"
  echo "STAGE sweep $st mounts: refused=$(cat "$D"/${st}_test*.txt | grep -ac "can.t read superblock") remaster=$(cat "$D"/${st}_test*.txt | grep -ac 'status=12') retry_exhausted=$(cat "$D"/${st}_test*.txt | grep -ac 'lock request failed after') collisions=$(cat "$D"/${st}_test*.txt | grep -ac 'P-TAUTH-COLLISION')"
  echo "STAGE sweep $st store-stats: $(cat "$D"/${st}_test*.txt | grep -a 'P-TAUTH-STORE-STATS' | sed 's/.*tauth: //' | tail -3 | tr '\n' ' ')"
}
{
  echo "=== sess426 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess426_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 240 make -C tests/tauth clean test > "$E/sess426_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -E 'RESULT|fails=' "$E/sess426_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw dre
  timeout 90 tests/dir_recreate_estale.sh "$LABEL" test1 test2 test3 test4 20 250; echo "STAGE dre rc=$?"; sweep dre
  timeout 260 tests/incarnation_mismatch_probe.sh zero test32 test1; echo "STAGE incprobe rc=$?"; sweep incprobe
  prep_tcp token; sweep prep_token
  env $TCPENV timeout 400 tests/tcp_token_plumbing_verify.sh "$LABEL"; echo "STAGE token rc=$?"; sweep token
  echo "STAGE token-wl: $(for n in 1 2 3 4; do f=$(ls -t tests/evidence/*_tcptok/test$n.wl 2>/dev/null | head -1); printf 'test%s[%s] ' "$n" "$(grep -a 'PHASE\|^rc=\|WL_OK' "$f" | tr '\n' ' ')"; done)"
  echo "STAGE token-errs: $(cat $(ls -td tests/evidence/*_tcptok | head -1)/test*.wl | grep -a '^ERR' | sed 's/f[0-9]*: //' | sort | uniq -c | sort -rn | head -5 | tr '\n' ' ')"
  prep_tcp d0287; sweep prep_d0287
  env $TCPENV timeout 600 tests/d0287_remaster_measure.sh "$LABEL"; echo "STAGE d0287 rc=$?"; sweep d0287
  prep_caw board
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess426_${LABEL}.log" 2>&1
