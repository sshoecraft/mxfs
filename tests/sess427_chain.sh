#!/bin/bash
# sess427_chain.sh — build + rig-verify 0.38.1 on the CURRENT fleet:
#   D-0351 FREE-PUBLISH fix (docs/free-publish.md: FREE publication
#   obligation, P55C sanction + publication-write gate, audit FREE branch with
#   fail-closed deferral, recovery worker) and D-0348 step 2 (tauth format v2:
#   mkfs-sized ledger geometry + seeded hash, PROTO_GEN 9, mkfs -t).
#
#  0. build VERSION + prove complete; tools; tests/tauth usermode gate
#  1. prep 32/caw (format v2 mkfs); chk geometry line
#  2. tests/dir_recreate_estale.sh (D-0351 reproducer) x2 + sweeps
#  3. full 32/caw board (regression gate)
#  4. prep 32/tcp (mpatha); tcp_token_plumbing_verify + sweep (D-0348 step 2,
#     D-0349 measurement: collisions must stay 0, page_full 0, pace)
#  5. prep tcp; d0287_remaster_measure + sweep
#
# budget: build 500 + proof 500 + tools 120 + tauth 240 + 3 preps x 300 +
# 2 x dre 90 + board 1900 + token 400 + d0287 600 + 6 sweeps x 60 => ~5600 s.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s431}
E=tests/evidence
D="$E/sess427_${LABEL}_dmesg"
mkdir -p "$E" "$D"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
PAT='P-TAUTH|P-GOODBYE|MXFS-MEMBERSHIP|P-TCPDEATH|status=12|lock request failed after|P-LKTIMEOUT|P240-QUAR|mount.*refus|can.t read superblock|P-D512|P-DEPART|bad superblock|mxfs: mount|P-HB-INC-ZERO|P34H-POISON|P283-REL-FINISH-SKIP|P55C-|P-FREEOB|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|Internal error|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P87-|P88-'
TAGS='P-TAUTH-[A-Z0-9-]+|P34H-POISON-[A-Z]+|P-HB-INC-ZERO|P283-REL-FINISH-SKIP|P55C-[A-Z-]+|P-FREEOB-[A-Z-]+|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P8[78]-[A-Z-]+'
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess427_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess427_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
sweep() {
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "dmesg | grep -aE '$PAT' | tail -400" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -ac 'P-TAUTH\|P34H\|P-HB-INC\|P283\|P55C\|P-FREEOB\|P-CR' "$D/${st}_test$i.txt")" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -aoE "$TAGS" | sort | uniq -c | sort -rn | tr '\n' ' ')"
  echo "STAGE sweep $st mounts: refused=$(cat "$D"/${st}_test*.txt | grep -ac "can.t read superblock") remaster=$(cat "$D"/${st}_test*.txt | grep -ac 'status=12') retry_exhausted=$(cat "$D"/${st}_test*.txt | grep -ac 'lock request failed after') collisions=$(cat "$D"/${st}_test*.txt | grep -ac 'P-TAUTH-COLLISION') shutdowns=$(cat "$D"/${st}_test*.txt | grep -ac 'P-SESSION-POISON\|P-CR3-CANCEL') freeob_bad=$(cat "$D"/${st}_test*.txt | grep -ac 'P-FREEOB-REFUSED\|P-FREEOB-FOREIGN\|P-FREEOB-NOSHELL\|P-FREEOB-NOEPOCH\|P55C-FREE-FOREIGN\|P-FREEOB-GATE-STUCK')"
  echo "STAGE sweep $st store-stats: $(cat "$D"/${st}_test*.txt | grep -a 'P-TAUTH-STORE-STATS' | sed 's/.*tauth: //' | tail -3 | tr '\n' ' ')"
}
{
  echo "=== sess427 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess427_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 240 make -C tests/tauth clean test > "$E/sess427_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -aoE '=== [a-z_]+ RESULT [A-Z]+ fails=[0-9]+|=== tauth_test: fails=[0-9]+' "$E/sess427_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw dre
  echo "STAGE chk-geometry: $(timeout 60 tools/mxfs_sshpass.sh test1 '/src/mxfs/tools/chk_mxfs -v '"$MXFS_DEV"' 2>&1 | grep -a "authority ledger"' 2>/dev/null | tr '\n' ' ')"
  timeout 90 tests/dir_recreate_estale.sh "${LABEL}a" test1 test2 test3 test4 20 250; echo "STAGE dre1 rc=$?"; sweep dre1
  timeout 90 tests/dir_recreate_estale.sh "${LABEL}b" test5 test6 test7 test8 20 250; echo "STAGE dre2 rc=$?"; sweep dre2
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  sweep board
  prep_tcp token; sweep prep_token
  env $TCPENV timeout 400 tests/tcp_token_plumbing_verify.sh "$LABEL"; echo "STAGE token rc=$?"; sweep token
  echo "STAGE token-wl: $(for n in 1 2 3 4; do f=$(ls -t tests/evidence/*_tcptok/test$n.wl 2>/dev/null | head -1); printf 'test%s[%s] ' "$n" "$(grep -a 'PHASE\|^rc=\|WL_OK' "$f" | tr '\n' ' ')"; done)"
  echo "STAGE token-errs: $(cat $(ls -td tests/evidence/*_tcptok | head -1)/test*.wl | grep -a '^ERR' | sed 's/f[0-9]*: //' | sort | uniq -c | sort -rn | head -5 | tr '\n' ' ')"
  prep_tcp d0287; sweep prep_d0287
  env $TCPENV timeout 600 tests/d0287_remaster_measure.sh "$LABEL"; echo "STAGE d0287 rc=$?"; sweep d0287
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess427_${LABEL}.log" 2>&1
