#!/bin/bash
# sess445 chain 39: D-0512 ruling A′ (0.53.0) — build, then the ruling's
# required validation: (1) fleet create burst -> zero P-AUTHCAP-VOID and
# RETYPE-OK lines on the converters; (2) a victim slice holding an sf->block
# conversion foreign-replays COMPLETE; (3) negative arms inject=1 (MIXED) and
# inject=2 (re-type never re-dirtied) are REFUSED.
# budget: build 3-4 min (bound 500) + tools (120); prep 79-120 s (bound 300);
# handoff_anatomy 32x4 + harvest ~90 s (bound 240); d0512 arms 300 each; 3 preps.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess445_chain38_0512_sf_to_block_void_s445a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s445b}
LOG=tests/evidence/sess445_chain39_0512_Aprime_$LABEL.log
EV=tests/evidence/sess445_chain39_0512_Aprime_$LABEL
mkdir -p "$EV"
SSH=tools/mxfs_sshpass.sh
PASS=$(tools/mxfs_secrets.sh passfile 2>/dev/null)
{
  echo "=== sess445 chain39 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  strings mxfs.ko | grep -q 'P-AUTHCAP-RETYPE-OK' && echo "probe: P-AUTHCAP-RETYPE-OK present" || { echo "ABORT: A′ probe missing from mxfs.ko"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  STAMP=@$(date +%s)
  T0=$(date +%s); timeout 240 tests/handoff_anatomy.sh ${LABEL}burst 32 4 keep 50; echo "STAGE burst rc=$? wall=$(( $(date +%s) - T0 ))s"
  for i in $(seq 1 32); do
    ( timeout 40 "$SSH" "test$i" "$PASS" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'P-AUTHCAP-VOID\|P-AUTHCAP-RETYPE\|P240-AUTHCAP'" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you' > "$EV/test$i.burst" ) &
  done; wait
  echo "BURST: void=$(cat "$EV"/test*.burst | grep -ac 'P-AUTHCAP-VOID') retype_ok=$(cat "$EV"/test*.burst | grep -ac 'P-AUTHCAP-RETYPE-OK') retype_mixed=$(cat "$EV"/test*.burst | grep -ac 'P-AUTHCAP-RETYPE-MIXED')"
  grep -aH 'P-AUTHCAP-VOID\|P-AUTHCAP-RETYPE' "$EV"/test*.burst | cut -c1-260 | head -12
  for arm in fix inject1 inject2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_$arm rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before arm $arm"; break; fi
    T0=$(date +%s); timeout 300 tests/d0512_sf_to_block_replay.sh $LABEL $arm test2 32 test1; echo "STAGE d0512_$arm rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
