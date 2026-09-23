#!/bin/bash
# sess488: WHO COMMITS AG METADATA FOR A GRANT THE NODE NO LONGER HOLDS, ON A
# LIVE MOUNT?  (the producer behind D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-
# PIN-0487's refusals in the shared-directory storm)
#
# The refusal itself is correct — xfsaild must not write an image for an AG a
# peer now owns — but the item should not exist: every release drains to a
# fixed point under the held grant before the on-disk unlock, and a mutation
# after the release is an exclusion violation.  On 0.69.5 the plain
# crash_consistency row (chain 139 leg A, run_crash_consistency_20260904T064818Z)
# logged 393 P126-XFSAILD-SKIP-AGMETA lines fleet-wide; the 0.64.37 heavy
# storm logged ~50 per node on 12 nodes for ~25 s each, always one AG's
# agi/inobt/finobt right after the BAST worker released that AG.  The old line
# carries no identity.  0.69.6's P126-XFSAILD-REFUSE line carries the item's
# LSN and its captured authority: cap_epoch nonzero = the image was dirtied
# UNDER a grant and the release then unlocked without draining it (a drain
# gap); cap_epoch zero = the image was dirtied AFTER the grant was gone (an
# exclusion gap).  That single field decides which code path is the defect.
#
# This chain: install the frozen 0.69.6, prep, run crash_consistency twice,
# and sweep every node for the REFUSE lines plus the release/inactivation
# context around each first refusal.  Then put the 0.69.5 tree module back so
# the tree's mxfs.ko is again the build the boards run.
#
# derived time budgets, derived: prep 300 (measured 106-146 s); each cc row 160
# (manifest 90 + harness overhead, measured 91 s); sweep 90 per node parallel.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess488_p126_producer.sh s488g &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s488g}
GATE=${GATE:-tests/evidence/sess488_ailpin_fleet_umount_s488f.log}
KO=${KO:-tests/evidence/sess488_frozen_0696/mxfs.ko}
RESTORE_KO=${RESTORE_KO:-tests/evidence/sess488_frozen_0695_tree/mxfs.ko}
LAPS=${LAPS:-2}
LOG=tests/evidence/sess488_p126_producer_$LABEL.log
O=tests/evidence/sess488_p126_producer_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }

{
  echo "=== sess488 p126_producer START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO LAPS=$LAPS ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  echo "STAGE install_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') refuse_line=$(strings -a mxfs.ko | grep -ac 'P126-XFSAILD-REFUSE ')"
  t0=$(date +%s)
  timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep.out" | tail -1)"
  if [ "$rc" = 0 ]; then
    for lap in $(seq 1 "$LAPS"); do
      SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
      timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$lap.out" 2>&1; rc=$?
      echo "STAGE cc_$lap rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s $(grep -a 'crash_consistency' "$O/cc_$lap.out" | grep -a 'nodes_pass' | grep -ao 'nodes_pass=[0-9/]*' | head -1)"
      D="$O/lap$lap"; mkdir -p "$D"
      for n in $(nodes); do
          ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P126-|P12-LATCH|P12-WORK|P-INACT-CERT|P-INACT-EX|P243-AGAUTH|P150-|P-AGIFC-MOD|P82-ADD|P82-REM|P-FREEOB|P128-AILSTUCK|P88-|P131|shut down'" 2>/dev/null | gzip > "$D/ctx_$n.gz" ) &
      done
      wait
      tot=0; nodes_hit=0; ep0=0; epnz=0
      for n in $(nodes); do
          c=$(zcat "$D/ctx_$n.gz" 2>/dev/null | grep -ac 'P126-XFSAILD-REFUSE '); c=${c:-0}
          [ "$c" -gt 0 ] && nodes_hit=$((nodes_hit + 1)); tot=$((tot + c))
          ep0=$(( ep0 + $(zcat "$D/ctx_$n.gz" 2>/dev/null | grep -a 'P126-XFSAILD-REFUSE ' | grep -ac 'cap_epoch=0 ') ))
          epnz=$(( epnz + $(zcat "$D/ctx_$n.gz" 2>/dev/null | grep -a 'P126-XFSAILD-REFUSE ' | grep -a -v 'cap_epoch=0 ' | grep -ac 'cap_epoch=') ))
      done
      echo "  LAP $lap: refuse_lines=$tot nodes_with_refusals=$nodes_hit/32 cap_epoch_zero=$ep0 cap_epoch_nonzero=$epnz pinned=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-AIL-PINNED ') relog=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'REFUSE-RELOG') transient_skip_lines=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-XFSAILD-SKIP-AGMETA')"
      zcat "$D"/ctx_*.gz 2>/dev/null | grep -a 'P126-XFSAILD-REFUSE ' | grep -ao 'cap_class=[0-9]* cap_st=[0-9]*' | sort | uniq -c | sort -rn | head -5 | sed 's/^/    class\/status: /'
      zcat "$D"/ctx_*.gz 2>/dev/null | grep -a -m3 'P126-XFSAILD-REFUSE ' | cut -c1-300 | sed 's/^/    /'
      # the 12 context lines before the first refusal on the first node that has one
      for n in $(nodes); do
          if zcat "$D/ctx_$n.gz" 2>/dev/null | grep -aq 'P126-XFSAILD-REFUSE '; then
              echo "    CONTEXT before first refusal on $n:"
              zcat "$D/ctx_$n.gz" | grep -a -B12 -m1 'P126-XFSAILD-REFUSE ' | head -12 | cut -c1-200 | sed 's/^/      /'
              break
          fi
      done
    done
  else
    echo "NOT RUN: prep rc=$rc"
  fi
  cp "$RESTORE_KO" mxfs.ko && echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$RESTORE_KO" || echo "WARN: could not restore $RESTORE_KO into the tree"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
