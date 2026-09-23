#!/bin/bash
# sess430_containment_chain.sh — instrumented measure-then-fix chain for the D-0351
# dialloc CONTAINMENT (0.39.3: two-phase candidate validation, DISK-LIVE
# quarantine; design-consult ruling ccmemory ccloop-c7ee71c6-sess430-GPT-ruling-d0351-
# dialloc-containment-two-phase).  Derived from tests/sess430_chain.sh.
#   0. wait for the prior chain's DONE line
#   A. PRE-FIX measurement on the fleet's current build: prep (the prior
#      board's node_death_replay tears the cluster down; the tree .ko is the
#      OLD build until the make below) + tests/dialloc_disklive_inject.sh.
#      Expected before containment: FAIL — P-CR62 DISK-LIVE + node shutdown.
#      Recorded, not gating.  Skipped unless the deployed srcversion equals
#      the tree's (i.e. the tree is still unbuilt after the source edits).
#   1. build VERSION (0.39.3) + prove complete; tools; tauth usermode gate
#   2. prep 32/caw
#   B. POST-FIX: the injector must PASS (P-DIALLOC-DISKLIVE for X, no
#      shutdown, creates succeed, X never handed out)
#   3. free_foreign_realloc_repro, free_home_settle_repro, dre x2 + sweeps
#   4. full 32/caw board + sweep (zero FOREIGN / CHAIN-BROKEN / XRELEASE /
#      DISKLIVE fleet-wide; sustained_load + dirent pace rows are the budget rule
#      check on the per-create plain read)
# budget: wait <= 2400 + prep 300 + inject 120 + build 500 + proof 500 + tools
# 120 + tauth 240 + prep 300 + inject 120 + ffr 150 + fhs 150 + 2 x dre 90 +
# board 1900 + sweeps => ~7200 s.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s437}
WAITLOG=${2:-tests/evidence/sess430_s436.log}
E=tests/evidence
D="$E/sess430_${LABEL}_dmesg"
mkdir -p "$E" "$D"
PAT='P55C-|P237-EVICT|P-RECYCLE-|P-EVICT-OBLIG|P-FREEOB|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|Internal error|P119-NONEX-FLUSH-SKIP|P128-INACT-DEFER|P32D-DEADINCARN|P-RECYCLE-DEADSTAMP|P-RECYCLE-GATE|P87-|P88-|P34H-POISON|force-shutdown|xfs_trans_cancel|status=12|lock request failed after|P-DIALLOC-DISKLIVE|P-DIALLOC-VALIDATE|P-DIALLOC-ALL-QUARANTINED|P-DIALLOC-VALIDATED-LOST|P-FREEPUB-|P238-CLMERGE-LEDGER-ROLLBACK.*freepub'
TAGS='P55C-[A-Z0-9-]+|P237-EVICT-[A-Z]+|P-FREEOB-[A-Z-]+|P-CR62|P-CR3-CANCEL|P-CR63-DEFER-DISKLIVE|P-SESSION-POISON|P119-NONEX-FLUSH-SKIP|P32D-DEADINCARN-SKIP|P34H-POISON-[A-Z]+|P8[78]-[A-Z-]+|P-DIALLOC-[A-Z-]+|P-FREEPUB-CLAIM-STALE'
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess430_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
MARK="S430C-${LABEL}-$$"
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
    ( timeout 40 tools/mxfs_sshpass.sh "test$i" "J=\$(journalctl -k -q --since '$MARKTIME' -o short-monotonic 2>/dev/null); echo \"\$J\" | grep -aE '$PAT' | grep -avE 'P-FREEOB-CHAIN-LIVE|P-FREEOB-CHAIN-KEPT|P128-INACT-DEFER|P55C-FREE-FLUSH|P55C-FREE-HOME|P-RECYCLE-DEADSTAMP-CLEAR|P-FREEPUB-CLAIM |P-FREEPUB-KEEP|P-FREEPUB-WRITE|P-FREEPUB-CLAIM-CLEAR' | tail -400; echo HIGHVOL: chain_live=\$(echo \"\$J\" | grep -ac P-FREEOB-CHAIN-LIVE) chain_kept=\$(echo \"\$J\" | grep -ac P-FREEOB-CHAIN-KEPT) foreign_raw=\$(echo \"\$J\" | grep -ac P55C-FREE-FOREIGN) disklive_raw=\$(echo \"\$J\" | grep -ac 'P-DIALLOC-DISKLIVE ') fp_claim=\$(echo \"\$J\" | grep -ac 'P-FREEPUB-CLAIM ') fp_keep=\$(echo \"\$J\" | grep -ac P-FREEPUB-KEEP) fp_write=\$(echo \"\$J\" | grep -ac P-FREEPUB-WRITE) fp_durable=\$(echo \"\$J\" | grep -ac 'P-FREEPUB-CLAIM-CLEAR.*why=durable') fp_clear_other=\$(echo \"\$J\" | grep -a P-FREEPUB-CLAIM-CLEAR | grep -avc 'why=durable') inact_defer=\$(echo \"\$J\" | grep -ac P128-INACT-DEFER) free_flush=\$(echo \"\$J\" | grep -ac 'P55C-FREE-FLUSH') free_home=\$(echo \"\$J\" | grep -ac 'P55C-FREE-HOME ') settled=\$(echo \"\$J\" | grep -ac 'P55C-FREE-HOME-SETTLED') recycle_clear=\$(echo \"\$J\" | grep -ac P-RECYCLE-DEADSTAMP-CLEAR); echo JOURNAL_LINES=\$(echo \"\$J\" | wc -l) UPTIME_SINCE=\$(uptime -s | tr ' ' T)" > "$D/${st}_test$i.txt" 2>"$D/${st}_test$i.err"; echo "rc=$?" >> "$D/${st}_test$i.err" ) &
  done
  wait
  echo "STAGE sweep $st journal: $(for i in $(seq 1 32); do printf 'test%s=%s ' "$i" "$(grep -ao 'JOURNAL_LINES=[0-9]*' "$D/${st}_test$i.txt" | cut -d= -f2)"; done)"
  echo "STAGE sweep $st: $(for i in $(seq 1 32); do printf 'test%s=%s/%s ' "$i" "$(grep -av '^HIGHVOL' "$D/${st}_test$i.txt" | grep -ac 'P55C\|P-FREEOB\|P-CR\|P32D\|P-SESSION\|P-DIALLOC')" "$(tail -1 "$D/${st}_test$i.err")"; done)"
  echo "STAGE sweep $st tags: $(cat "$D"/${st}_test*.txt | grep -av '^HIGHVOL' | grep -aoE "$TAGS" | sort | uniq -c | sort -rn | tr '\n' ' ')"
  echo "STAGE sweep $st highvol: $(cat "$D"/${st}_test*.txt | grep -a '^HIGHVOL' | tr ' ' '\n' | grep -a '=' | awk -F= '{s[$1]+=$2} END{for (k in s) printf "%s=%d ", k, s[k]}')"
  echo "STAGE sweep $st verdicts: shutdowns=$(cat "$D"/${st}_test*.txt | grep -ac 'P-SESSION-POISON\|P-CR3-CANCEL\|Internal error\|P237-EVICT-OBLIGATION') unsettled=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-HOME-UNSETTLED') freeob_bad=$(cat "$D"/${st}_test*.txt | grep -ac 'P-FREEOB-REFUSED\|P-FREEOB-FOREIGN\|P-FREEOB-NOSHELL\|P-FREEOB-NOEPOCH\|P55C-FREE-FOREIGN\|P-FREEOB-GATE-STUCK\|P-FREEOB-CHAIN-BROKEN\|P-FREEOB-RECYCLE-ANOMALY\|P-FREEOB-ARM-ANOMALY\|P-FREEOB-UNPUBLISHED\|P-FREEOB-XRELEASE') chain_written=$(cat "$D"/${st}_test*.txt | grep -ac 'P55C-FREE-CHAIN\|P-FREEOB-CHAIN ') deadskip=$(cat "$D"/${st}_test*.txt | grep -ac 'P32D-DEADINCARN-SKIP') disklive=$(cat "$D"/${st}_test*.txt | grep -ac 'P-CR62 .*DISK-LIVE\|P-CR63-DEFER-DISKLIVE') dialloc_disklive=$(cat "$D"/${st}_test*.txt | grep -ac 'P-DIALLOC-DISKLIVE ') dialloc_bad=$(cat "$D"/${st}_test*.txt | grep -ac 'P-DIALLOC-VALIDATE-EIO\|P-DIALLOC-ALL-QUARANTINED\|P-DIALLOC-DISKLIVE-STORM\|P-DIALLOC-DISKLIVE-QFULL\|P-DIALLOC-VALIDATED-LOST') retry_exhausted=$(cat "$D"/${st}_test*.txt | grep -ac 'lock request failed after') freepub_stale=$(cat "$D"/${st}_test*.txt | grep -ac 'P-FREEPUB-CLAIM-STALE\|cls=freepub-stale')"
}
{
  echo "=== sess430 containment chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) wait_on=$WAITLOG ==="
  w=0
  while [ -f "$WAITLOG" ] && ! grep -aq '^DONE' "$WAITLOG" && [ $w -lt 2400 ]; do sleep 30; w=$((w+30)); done
  echo "STAGE wait prior_done=$(grep -ac '^DONE' "$WAITLOG" 2>/dev/null) waited_s=$w"
  # A. pre-fix measurement on the deployed (old) build
  fsv=$(timeout 15 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | tr -dc 'A-F0-9'); tsv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE prefix-sv fleet=$fsv tree=$tsv"
  if [ "$fsv" = "$tsv" ]; then
    prep_caw prefix
    mark ddlpre; timeout 180 tests/dialloc_disklive_inject.sh "${LABEL}pre" test3 test4 16; echo "STAGE ddl-prefix rc=$? (expected FAIL before containment: the measurement)"; sweep ddlpre
  else
    echo "STAGE ddl-prefix SKIPPED (tree already rebuilt: fleet != tree)"
  fi
  # 1. build the containment
  B="$E/sess430_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; grep -a ' error:' "$B" | head -20; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 240 make -C tests/tauth clean test > "$E/sess430_${LABEL}_tauth.log" 2>&1; urc=$?
  echo "STAGE tauth usermode rc=$urc $(grep -aoE '=== [a-z_]+ RESULT [A-Z]+ fails=[0-9]+|=== tauth_test: fails=[0-9]+' "$E/sess430_${LABEL}_tauth.log" | tr '\n' ' ')"
  if [ $urc -ne 0 ]; then
    # sess431: formation_test check 1 ("no lock request failed across the
    # ramp", rc=-35/-11) is the OPEN ledgered defect D-0352 (D-TAUTH-FORMATION-
    # RAMP-LEDGER-DENY-EXHAUSTS-RETRIES-EAGAIN-0352); it fails ~50% of local
    # runs (s441 gate + 3/6 at 17:58Z) and is unrelated to the D-0351 lap this
    # chain measures.  Record the occurrence loudly and continue ONLY when
    # that is the sole failing usermode test; anything else still aborts.
    TL="$E/sess430_${LABEL}_tauth.log"
    other_fail=$(grep -aoE '=== [a-z_]+ RESULT FAIL fails=[0-9]+|=== tauth_test: fails=[1-9][0-9]*' "$TL" | grep -av 'formation_test' | wc -l)
    ft_c1=$(grep -ac 'FAIL 1 no lock request failed across the ramp' "$TL")
    ft_other=$(grep -aE '^  FAIL ' "$TL" | grep -avc 'FAIL 1 no lock request failed across the ramp')
    if [ "$other_fail" -eq 0 ] && [ "$ft_c1" -gt 0 ] && [ "$ft_other" -eq 0 ]; then
      echo "STAGE tauth gate: D-0352 OCCURRENCE (formation_test check 1 only: $(grep -a 'node .*fails=\|INFO iters' "$TL" | tr '\n' ' ' | cut -c1-200)) — recorded for the D-0352 ledger; lap continues"
    else
      echo "ABORT: usermode gate failed (other_fail=$other_fail ft_c1=$ft_c1 ft_other=$ft_other)"; echo "DONE $(date -u +%FT%TZ)"; exit 1
    fi
  fi
  prep_caw fix
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  echo "STAGE chk-geometry: $(timeout 60 tools/mxfs_sshpass.sh test1 '/src/mxfs/tools/chk_mxfs -v '"$MXFS_DEV"' 2>&1 | grep -a "authority ledger\|authority view\|control pages"' 2>/dev/null | tr '\n' ' ')"
  # B. post-fix: the injector must pass; with the 0.39.4 knob the A/B harness
  #    also measures the pre-containment shutdown arm on the SAME build
  #    (knob off -> expected P-CR62 + node shutdown -> prep -> knob on -> PASS)
  if [ -n "${AB:-}" ]; then
    mark ddlab; timeout 700 tests/dialloc_validate_ab.sh "${LABEL}" test3 test4; echo "STAGE ddl-ab rc=$?"; sweep ddlab
  else
    mark ddlfix; timeout 180 tests/dialloc_disklive_inject.sh "${LABEL}fix" test3 test4 16; echo "STAGE ddl-fix rc=$?"; sweep ddlfix
  fi
  if [ -n "${SHORT:-}" ]; then echo "STAGE short-lap: stopping after the injector stage"; echo "DONE $(date -u +%FT%TZ)"; exit 0; fi
  mark ffrfix; timeout 150 tests/free_foreign_realloc_repro.sh "${LABEL}fix" test1 100 test2; echo "STAGE ffr-fix rc=$?"; sweep ffrfix
  # sess431 (0.39.9): the design-consult-required directed measurement — buffer != media
  # for a claimed free image; P55C must classify from the platter and land it.
  timeout 120 tests/freepub_platter_home_inject.sh "${LABEL}" test5 test6; echo "STAGE fph rc=$?"
  timeout 150 tests/free_home_settle_repro.sh "${LABEL}r" test5 200 test6; echo "STAGE fhs rc=$?"
  mark dre1; timeout 90 tests/dir_recreate_estale.sh "${LABEL}a" test1 test2 test3 test4 20 250; echo "STAGE dre1 rc=$?"; sweep dre1
  mark dre2; timeout 90 tests/dir_recreate_estale.sh "${LABEL}b" test5 test6 test7 test8 20 250; echo "STAGE dre2 rc=$?"; sweep dre2
  mark board; timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  sweep board
  echo "STAGE board-rows: $(./showstat.sh 32 caw 2>/dev/null | grep -E 'FAIL|FLAKY|BLOCKED|Total|VERDICT' | cut -c1-160 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess430_${LABEL}.log" 2>&1
