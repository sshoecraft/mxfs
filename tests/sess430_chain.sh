#!/bin/bash
# sess430_chain.sh — instrumented measure-then-fix chain for the D-0351 CHAIN defect
# (0.39.1: same-node free -> recycle -> free chains misread as P55C-FREE-FOREIGN;
# the live image left under an inobt-free bit; design-consult ruling ccmemory
# docs/rulings/free-foreign-chain.md).
# Derived from tests/sess429_chain.sh (MARK + journald-bounded sweeps).
#   0. wait for the prior chain's DONE line (never rebuild while a rig run is
#      in flight — the nodes insmod the TREE .ko over NFS)
#   A. PRE-FIX measurement on the fleet as the prior chain left it (0.39.0,
#      still mounted after its board): tests/free_foreign_realloc_repro.sh.
#      Expected on 0.39.0: FAIL — P55C-FREE-FOREIGN on the chain inos and a
#      P-CR62 DISK-LIVE shutdown on the peer.  Its rc is RECORDED, not gating.
#   1. build VERSION (0.39.1) + prove complete; tools; tauth usermode gate
#   2. prep 32/caw (also recovers the peer stage A may have shut down)
#   B. POST-FIX: the same reproducer must PASS (P-FREEOB-CHAIN-LIVE +
#      P55C-FREE-CHAIN present, zero FOREIGN, zero DISK-LIVE, peer healthy)
#   3. free_home_settle_repro + dir_recreate_estale x2 + sweeps
#   4. full 32/caw board + sweep (zero P55C-FREE-FOREIGN / P-FREEOB-FOREIGN
#      fleet-wide is the new gate; CHAIN-BROKEN / ANOMALY count as bad)
# budget: wait <= 2400 + repro 2 x 150 + build 500 + proof 500 + tools 120 +
# tauth 240 + prep 300 + fhs 150 + 2 x dre 90 + board 1900 + sweeps => ~6800 s.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s435}
WAITLOG=${2:-tests/evidence/sess429_s434.log}
E=tests/evidence
D="$E/sess430_${LABEL}_dmesg"
mkdir -p "$E" "$D"
PAT='P55C-|P237-EVICT|P-RECYCLE-|P-EVICT-OBLIG|P-FREEOB|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|Internal error|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P32D-DEADINCARN|P-RECYCLE-DEADSTAMP|P-RECYCLE-GATE|P87-|P88-|P34H-POISON|force-shutdown|xfs_trans_cancel|status=12|lock request failed after'
TAGS='P55C-[A-Z0-9-]+|P237-EVICT-[A-Z]+|P-FREEOB-[A-Z-]+|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P32D-DEADINCARN-SKIP|P-RECYCLE-DEADSTAMP-CLEAR|P34H-POISON-[A-Z]+|P8[78]-[A-Z-]+'
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess430_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
MARK="S430-${LABEL}-$$"
mark() {
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh "test$i" "echo '$MARK-$st' > /dev/kmsg" >/dev/null 2>&1 ) &
  done
  wait
  MARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  echo "STAGE mark $st $MARK-$st $(date -u +%FT%TZ)"
}
sweep() {
  local st=$1 i
  for i in $(seq 1 32); do
    # s435 lesson: the 400-line tail was saturated by P-FREEOB-CHAIN-LIVE
    # (~12k/node) and hid the residual FOREIGN lines — the high-volume
    # informational tags are COUNTED, the verdict-bearing tags kept verbatim.
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "J=\$(journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null); echo \"\$J\" | grep -aE '$PAT' | grep -avE 'P-FREEOB-CHAIN-LIVE|P128-INACT-DEFER|P55C-FREE-FLUSH|P55C-FREE-HOME|P-RECYCLE-DEADSTAMP-CLEAR' | tail -400; echo HIGHVOL: chain_live=\$(echo \"\$J\" | grep -ac P-FREEOB-CHAIN-LIVE) inact_defer=\$(echo \"\$J\" | grep -ac P128-INACT-DEFER) free_flush=\$(echo \"\$J\" | grep -ac 'P55C-FREE-FLUSH') free_home=\$(echo \"\$J\" | grep -ac 'P55C-FREE-HOME ') settled=\$(echo \"\$J\" | grep -ac 'P55C-FREE-HOME-SETTLED') recycle_clear=\$(echo \"\$J\" | grep -ac P-RECYCLE-DEADSTAMP-CLEAR); echo JOURNAL_LINES=\$(echo \"\$J\" | wc -l) UPTIME_SINCE=\$(uptime -s | tr ' ' T)" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st journal: $(for i in $(seq 1 32); do printf 'test%s=%s ' "$i" "$(grep -ao 'JOURNAL_LINES=[0-9]*' "$D/${st}_test$i.txt" | cut -d= -f2)"; done)"
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -ac 'P55C\|P-FREEOB\|P-CR\|P32D\|P-RECYCLE\|P-SESSION' "$D/${st}_test$i.txt")" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -av '^HIGHVOL' | grep -aoE "$TAGS" | sort | uniq -c | sort -rn | tr '\n' ' ')"
  echo "STAGE sweep $st highvol: $(cat "$D"/${st}_test*.txt | grep -a '^HIGHVOL' | tr ' ' '\n' | grep -a '=' | awk -F= '{s[$1]+=$2} END{for (k in s) printf "%s=%d ", k, s[k]}')"
  echo "STAGE sweep $st verdicts: shutdowns=$(cat "$D"/${st}_test*.txt | grep -ac 'P-SESSION-POISON\|P-CR3-CANCEL\|Internal error\|P237-EVICT-OBLIGATION') settled=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-HOME-SETTLED') unsettled=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-HOME-UNSETTLED') freeob_bad=$(cat "$D"/${st}_test*.txt | grep -ac 'P-FREEOB-REFUSED\|P-FREEOB-FOREIGN\|P-FREEOB-NOSHELL\|P-FREEOB-NOEPOCH\|P55C-FREE-FOREIGN\|P-FREEOB-GATE-STUCK\|P-FREEOB-CHAIN-BROKEN\|P-FREEOB-RECYCLE-ANOMALY\|P-FREEOB-ARM-ANOMALY\|P-FREEOB-UNPUBLISHED') chain_live=$(cat "$D"/${st}_test*.txt | grep -a '^HIGHVOL' | grep -ao 'chain_live=[0-9]*' | cut -d= -f2 | awk '{s+=$1} END{print s+0}') chain_written=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-CHAIN\|P-FREEOB-CHAIN ') deadskip=$(cat "$D"/${st}_test*.txt | grep -ac 'P32D-DEADINCARN-SKIP') disklive=$(cat "$D"/${st}_test*.txt | grep -ac 'P-CR62 .*DISK-LIVE\|P-CR63-DEFER-DISKLIVE') retry_exhausted=$(cat "$D"/${st}_test*.txt | grep -ac 'lock request failed after')"
}
{
  echo "=== sess430 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) wait_on=$WAITLOG ==="
  w=0
  while [ -f "$WAITLOG" ] && ! grep -aq '^DONE' "$WAITLOG" && [ $w -lt 2400 ]; do sleep 30; w=$((w+30)); done
  echo "STAGE wait prior_done=$(grep -ac '^DONE' "$WAITLOG" 2>/dev/null) waited_s=$w"
  # A. pre-fix measurement on the deployed build (whatever the nodes run now).
  # s435 lesson: the prior chain's board ends with node_death_replay, which
  # tears the cluster down — the reproducer ABORTed on "no mxfs mount".  A
  # prep re-insmods the TREE .ko, which is the OLD build only while the tree
  # is unbuilt; the pre-fix stage is therefore skipped unless PREFIX=1 and the
  # tree .ko srcversion still matches the fleet's.
  if [ "${PREFIX:-0}" = "1" ]; then
    echo "STAGE prefix-sv $(timeout 15 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | tr -dc 'A-F0-9') tree=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
    prep_caw prefix
    mark ffrpre; timeout 150 tests/free_foreign_realloc_repro.sh "${LABEL}pre" test1 100 test2; echo "STAGE ffr-prefix rc=$? (expected FAIL before the fix: the measurement)"; sweep ffrpre
  fi
  # 1. build the fix
  B="$E/sess430_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 240 make -C tests/tauth clean test > "$E/sess430_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -aoE '=== [a-z_]+ RESULT [A-Z]+ fails=[0-9]+|=== tauth_test: fails=[0-9]+' "$E/sess430_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw fix
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  echo "STAGE chk-geometry: $(timeout 60 tools/mxfs_sshpass.sh test1 '/src/mxfs/tools/chk_mxfs -v '"$MXFS_DEV"' 2>&1 | grep -a "authority ledger\|authority view\|control pages"' 2>/dev/null | tr '\n' ' ')"
  # B. post-fix: the reproducer must pass
  mark ffrfix; timeout 150 tests/free_foreign_realloc_repro.sh "${LABEL}fix" test1 100 test2; echo "STAGE ffr-fix rc=$?"; sweep ffrfix
  timeout 150 tests/free_home_settle_repro.sh "${LABEL}r" test3 200 test4; echo "STAGE fhs rc=$?"
  mark dre1; timeout 90 tests/dir_recreate_estale.sh "${LABEL}a" test1 test2 test3 test4 20 250; echo "STAGE dre1 rc=$?"; sweep dre1
  mark dre2; timeout 90 tests/dir_recreate_estale.sh "${LABEL}b" test5 test6 test7 test8 20 250; echo "STAGE dre2 rc=$?"; sweep dre2
  mark board; timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  sweep board
  echo "STAGE board-rows: $(./showstat.sh 32 caw 2>/dev/null | grep -E 'FAIL|FLAKY|BLOCKED|Total|VERDICT' | cut -c1-160 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess430_${LABEL}.log" 2>&1
