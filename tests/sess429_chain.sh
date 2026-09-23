#!/bin/bash
# sess429_chain.sh — build + rig-verify 0.39.0 (D-0351 FREE-PUBLISH fix, third
# lap: 0.38.4 home-free ledger settle; plus tauth view-record step 1, format
# v3 — usermode/mkfs/chk only) on the CURRENT fleet, 32/caw only.
# sess429: every dmesg sweep is MARK-BOUNDED — a marker is written to each
# node's kmsg before the stage and the sweep reads only lines after it, so the
# ring's stale lines from earlier laps no longer pollute the verdict counters.
# Derived from tests/sess428_chain.sh:
#   0. wait for a prior chain's DONE line (never two builds in flight; the rig
#      insmods the TREE .ko over NFS — ccmemory trap-never-rebuild-mxfs-ko-
#      while-rig-run-in-flight)
#   1. build VERSION + prove complete; tools; tests/tauth usermode gate
#   2. prep 32/caw; chk geometry line
#   3. tests/dir_recreate_estale.sh (D-0351 reproducer, sess428-fixed harness)
#      x2 + sweeps (P55C-FREE-FOREIGN must be 0 for disk_mode=00 images;
#      P32D-DEADINCARN-SKIP must be 0; P-RECYCLE-DEADSTAMP-CLEAR counted)
#   4. full 32/caw board (the 0.38.1 regression gate: cache_coherency 32/32)
#   5. sweep board
#
# budget: wait <= 1800 + build 500 + proof 500 + tools 120 + tauth 240 +
# prep 300 + 2 x dre 90 + board 1900 + 4 sweeps x 60 => ~5700 s.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s433}
WAITLOG=${2:-tests/evidence/sess428_s432.log}
E=tests/evidence
D="$E/sess429_${LABEL}_dmesg"
mkdir -p "$E" "$D"
PAT='P55C-|P237-EVICT|P-RECYCLE-|P-EVICT-OBLIG|P-FREEOB|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|Internal error|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P32D-DEADINCARN|P-RECYCLE-DEADSTAMP|P-RECYCLE-GATE|P87-|P88-|P34H-POISON|force-shutdown|xfs_trans_cancel|status=12|lock request failed after'
TAGS='P55C-[A-Z0-9-]+|P237-EVICT-[A-Z]+|P-FREEOB-[A-Z-]+|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P32D-DEADINCARN-SKIP|P-RECYCLE-DEADSTAMP-CLEAR|P34H-POISON-[A-Z]+|P8[78]-[A-Z-]+'
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess429_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
MARK="S429-${LABEL}-$$"
mark() {
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh "test$i" "echo '$MARK-$st' > /dev/kmsg" >/dev/null 2>&1 ) &
  done
  wait
  MARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  echo "STAGE mark $st $MARK-$st $(date -u +%FT%TZ)"
}
# sess429: the sweep reads JOURNALD (kernel facility, since the mark time, node
# clocks are UTC) — the dmesg ring wraps within minutes under the probe volume
# (the s433 board left ~2 min of ring on test1, and a node rebooted by
# node_death_replay loses the kmsg marker entirely).  journald on the nodes
# retained the whole 22-minute board window (79k kernel lines on test1).
sweep() {
  local st=$1 i
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null | grep -aE '$PAT' | tail -400; echo JOURNAL_LINES=\$(journalctl -k -q --since '$MARKTIME' 2>/dev/null | wc -l) UPTIME_SINCE=\$(uptime -s | tr ' ' T)" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st journal: $(for i in $(seq 1 32); do printf 'test%s=%s ' "$i" "$(grep -ao 'JOURNAL_LINES=[0-9]*' "$D/${st}_test$i.txt" | cut -d= -f2)"; done)"
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -ac 'P55C\|P-FREEOB\|P-CR\|P32D\|P-RECYCLE\|P-SESSION' "$D/${st}_test$i.txt")" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -aoE "$TAGS" | sort | uniq -c | sort -rn | tr '\n' ' ')"
  echo "STAGE sweep $st verdicts: shutdowns=$(cat "$D"/${st}_test*.txt | grep -ac 'P-SESSION-POISON\|P-CR3-CANCEL\|Internal error\|P237-EVICT-OBLIGATION') settled=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-HOME-SETTLED') unsettled=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-HOME-UNSETTLED') freeob_bad=$(cat "$D"/${st}_test*.txt | grep -ac 'P-FREEOB-REFUSED\|P-FREEOB-FOREIGN\|P-FREEOB-NOSHELL\|P-FREEOB-NOEPOCH\|P55C-FREE-FOREIGN\|P-FREEOB-GATE-STUCK') deadskip=$(cat "$D"/${st}_test*.txt | grep -ac 'P32D-DEADINCARN-SKIP') foreign_mode0=$(cat "$D"/${st}_test*.txt | grep -a 'P55C-FREE-FOREIGN' | grep -ac 'disk_mode=00') retry_exhausted=$(cat "$D"/${st}_test*.txt | grep -ac 'lock request failed after')"
}
{
  echo "=== sess429 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) wait_on=$WAITLOG ==="
  w=0
  while [ -f "$WAITLOG" ] && ! grep -aq '^DONE' "$WAITLOG" && [ $w -lt 1800 ]; do sleep 30; w=$((w+30)); done
  echo "STAGE wait prior_done=$(grep -ac '^DONE' "$WAITLOG" 2>/dev/null) waited_s=$w"
  B="$E/sess429_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 240 make -C tests/tauth clean test > "$E/sess429_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -aoE '=== [a-z_]+ RESULT [A-Z]+ fails=[0-9]+|=== tauth_test: fails=[0-9]+' "$E/sess429_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then echo "ABORT: usermode gate failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw dre
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  echo "STAGE chk-geometry: $(timeout 60 tools/mxfs_sshpass.sh test1 '/src/mxfs/tools/chk_mxfs -v '"$MXFS_DEV"' 2>&1 | grep -a "authority ledger\|authority view\|control pages"' 2>/dev/null | tr '\n' ' ')"
  timeout 150 tests/free_home_settle_repro.sh "${LABEL}r" test1 200 test2; echo "STAGE fhs rc=$?"
  mark dre1; timeout 90 tests/dir_recreate_estale.sh "${LABEL}a" test1 test2 test3 test4 20 250; echo "STAGE dre1 rc=$?"; sweep dre1
  mark dre2; timeout 90 tests/dir_recreate_estale.sh "${LABEL}b" test5 test6 test7 test8 20 250; echo "STAGE dre2 rc=$?"; sweep dre2
  mark board; timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  sweep board
  echo "STAGE board-rows: $(./showstat.sh 32 caw 2>/dev/null | grep -E 'FAIL|FLAKY|BLOCKED|Total|VERDICT' | cut -c1-160 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess429_${LABEL}.log" 2>&1
