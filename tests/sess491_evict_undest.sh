#!/bin/bash
# sess491: DOES A DIRECTORY GRANT LEAVE THROUGH INODE RECLAIM WITH COMMITTED
# BLOCKS UNWRITTEN?
# (D-DIR-BLOCK-COMMITTED-UNWRITTEN-AT-PR-RELEASE-RELAND-FENCE-SUPPRESSED-F4-ORPHAN-DIRENT-LOST-0491)
#
# The lost-dirent run (20260904T065945Z, mode 0) shows test23's last create
# logging a data block under EX, the block's log item freed without a write in
# the same second, the verify phase's drop_caches reclaiming the directory
# inode, and the next release of the directory entering at PR — where the
# write fence refused the re-land and the block was freed with its obligation
# open.  0.70.4 counts committed-unwritten data blocks at inode reclaim
# (P491-EVICT-UNDEST, with fork format and modes), at the release pipeline's
# pre-handoff point (P491-REL-UNDEST), names every undestaged block the
# acquire-side new-tenure retire drops (P491-NEWTENURE-RETIRE-UNDEST), and
# stamps the overlay retire site on the P285-F4-BLI-FREED-OPEN census line.
#
# This chain: install the frozen 0.70.4, prep with dir_persig_flush=0 (the
# mode that lost the entry; the mechanism is knob-independent, the knob only
# widens the window), run crash_consistency LAPS times on fresh directories
# (CC_TAG), sweep every node's kernel log since the prep, and report:
#   VERDICT evict_undest=.. evict_undest_ex=.. evict_btree=.. rel_undest=..
#           rel_undest_subex=.. newtenure_undest=.. bli_freed_open=..
#           reland=.. fence_skip=.. f4_orphan=.. cc_fail=.. shutdown=..
# The question is answered by evict_undest_ex (reclaim released an EX-held
# directory with undestaged blocks cached) and rel_undest_subex (a sub-EX
# release found them).  cc_fail>0 is the loss itself.  Then the tree module is
# restored.
#
# derived time budgets, derived: prep 300 (measured 110-146 s); each cc row 160
# (manifest 90 + harness overhead, measured 150 s); sweep 90 per node in
# parallel.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess491_evict_undest.sh s491a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s491a}
GATE=${GATE:-tests/evidence/sess488_ailpin_fleet_umount_s490i.log}
KO=${KO:-tests/evidence/sess491_frozen_0704/mxfs.ko}
RESTORE_KO=${RESTORE_KO:-tests/evidence/sess488_frozen_0695_tree/mxfs.ko}
LAPS=${LAPS:-3}
MODARGS=${MODARGS:-dir_persig_flush=0}
LOG=tests/evidence/sess491_evict_undest_$LABEL.log
O=tests/evidence/sess491_evict_undest_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }

{
  echo "=== sess491 evict_undest START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO LAPS=$LAPS MODARGS='$MODARGS' ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  echo "STAGE install_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') marker=$(strings -a mxfs.ko | grep -ac 'P491-EVICT-UNDEST')"
  SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
  MXFS_EXTRA_MODARGS="$MODARGS" timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep.out" | tail -1)"
  if [ "$rc" = 0 ]; then
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion /sys/module/mxfs/parameters/dir_persig_flush 2>/dev/null | tr '\n' ' '" 2>/dev/null > "$O/readback_$n.out" ) &
    done
    wait
    want="$(modinfo mxfs.ko | awk '/srcversion/{print $2}') 0 "
    ok=0; for n in $(nodes); do [ "$(cat "$O/readback_$n.out" 2>/dev/null)" = "$want" ] && ok=$((ok + 1)); done
    echo "READBACK sv+persig0: $ok/32"
    for lap in $(seq 1 "$LAPS"); do
      t0=$(date +%s)
      MXFS_EXTRA_MODARGS="$MODARGS" MXFS_TEST_ENV="CC_TAG=s491lap$lap" timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$lap.out" 2>&1; rc=$?
      echo "STAGE cc_$lap rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s $(grep -a 'crash_consistency' "$O/cc_$lap.out" | grep -ao 'nodes_pass=[0-9/]*' | head -1)"
    done
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P491-|P285-F4-BLI-FREED-OPEN|P285-F4-CENSUS|P286-F4-ORPHAN|P287-F4|P3R-RELAND|P3F-UNLANDED|P123-DIRFENCE-SKIP|P-FENCE-AILLEAK|P6R-RETAIN|P237-EVICT|P125-EVICT-SUSPECT|mxfs-cc-FAIL|mxfs-CCph|P304-RETIRE|P304-IOCNT-UNTOKENED|P490-|P-SHRINK-UNDEST|P5-UNDEST-SALVAGE|shut down'" 2>/dev/null | gzip > "$O/ctx_$n.gz" ) &
    done
    wait
    cnt() { zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac "$1"; }
    ev=$(cnt 'P491-EVICT-UNDEST')
    evex=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-EVICT-UNDEST' | grep -aEc 'mode=[45] ')
    evbt=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-EVICT-UNDEST' | grep -ac 'fmt=3 ')
    rl=$(cnt 'P491-REL-UNDEST')
    rlsub=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-REL-UNDEST' | grep -aEc 'held_mode=[0-3] ')
    nt=$(cnt 'P491-NEWTENURE-RETIRE-UNDEST')
    bf=$(cnt 'P285-F4-BLI-FREED-OPEN')
    for n in $(nodes); do
        echo "$n evict_undest=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P491-EVICT-UNDEST') rel_undest=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P491-REL-UNDEST') newtenure=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P491-NEWTENURE-RETIRE-UNDEST') cc_fail=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'mxfs-cc-FAIL') reland=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P3R-RELAND') orphan=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P286-F4-ORPHAN')" >> "$O/per_node.txt"
    done
    echo "VERDICT evict_undest=$ev evict_undest_ex=$evex evict_btree=$evbt rel_undest=$rl rel_undest_subex=$rlsub newtenure_undest=$nt bli_freed_open=$bf reland=$(cnt 'P3R-RELAND') unlanded_lost=$(cnt 'P3F-UNLANDED-LOST') fence_skip=$(cnt 'P123-DIRFENCE-SKIP') f4_orphan=$(cnt 'P286-F4-ORPHAN') f4_suppressed=$(cnt 'P287-F4-SUPPRESSED') cc_fail=$(cnt 'mxfs-cc-FAIL') untokened=$(cnt 'P304-IOCNT-UNTOKENED') not_quiesced=$(cnt 'P304-RETIRE-NOT-QUIESCED') shutdown=$(cnt 'shut down')"
    if [ "$evex" -gt 0 ] || [ "$nt" -gt 0 ] || [ "$rlsub" -gt 0 ]; then echo "RESULT OBSERVED"; else echo "RESULT NOT-OBSERVED"; fi
    sort -t= -k2 -rn "$O/per_node.txt" | head -6 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-EVICT-UNDEST' | grep -aE 'mode=[45] ' | head -3 | cut -c1-330 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-NEWTENURE-RETIRE-UNDEST' | head -3 | cut -c1-330 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-REL-UNDEST' | head -3 | cut -c1-330 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P285-F4-BLI-FREED-OPEN' | grep -ao 'site=[0-9]*:[0-9]*' | sort | uniq -c | sort -rn | head -5 | sed 's/^/    site: /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'mxfs-cc-FAIL' | head -3 | cut -c1-200 | sed 's/^/    LOSS: /'
  else
    echo "NOT RUN: prep rc=$rc"
  fi
  cp "$RESTORE_KO" mxfs.ko && echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$RESTORE_KO" || echo "WARN: could not restore $RESTORE_KO into the tree"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
