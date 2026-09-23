#!/bin/bash
# sess490: DOES A CLEAN UNMOUNT DEPART CLEAN AGAIN?
# (D-SYNC-EMULATED-COMPLETION-RUNS-TERMINAL-IOEND-TWICE-UNTOKENED-DIRTY-DEPARTURE-0490)
#
# On 0.69.5 every unmount after a directory-release drain or a create's durable
# bmbt flush printed P304-RETIRE-NOT-QUIESCED untokened=93..177 and departed
# DIRTY (slot ACTIVE, PR key retained: P302-PR-KEY-RETAINED-FENCE-TARGET), because
# a synchronous write completed without a bio ran its terminal completion twice
# and the second pass retired a departure token that was no longer there.
# 0.70.3 lets the waiter skip the second pass (P490-SYNC-IOEND-SKIP names the
# first two on each node).
#
# This chain: install the frozen 0.70.3, prep, run crash_consistency LAPS times
# (the shared-directory create workload whose release drains produce the
# emulated sync completions), then unmount every node at once and sweep each
# node's kernel log from the first prep to the unmount.  Verdict line:
#   VERDICT untokened_lines=.. skip_marker_nodes=../32 quiesced=../32
#           not_quiesced=.. key_retained=.. underflow=.. orphan=.. iowait_stuck=..
#           sema=.. shutdown=..
# PASS needs: untokened_lines=0, quiesced=32, not_quiesced=0, key_retained=0,
# and skip_marker_nodes>0 (otherwise the workload never exercised the path and
# the run is vacuous — the P61-FUA-SKIP-BMBT / P63 counts say whether the
# emulated arms fired at all).  Then the tree module is restored.
#
# derived time budgets, derived: prep 300 (measured 106-146 s); each cc row 160
# (manifest 90 + harness overhead, measured 91 s); mass umount 90 (1-2 s per
# node in parallel on a healthy fleet); sweep 90 per node in parallel.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess490_untokened_verify.sh s490h &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s490h}
GATE=${GATE:-tests/evidence/sess487_chain139_persig_ab_s490g.log}
KO=${KO:-tests/evidence/sess490_frozen_0703/mxfs.ko}
RESTORE_KO=${RESTORE_KO:-tests/evidence/sess488_frozen_0695_tree/mxfs.ko}
LAPS=${LAPS:-2}
MNT=/mnt/shared
LOG=tests/evidence/sess490_untokened_verify_$LABEL.log
O=tests/evidence/sess490_untokened_verify_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }

{
  echo "=== sess490 untokened_verify START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO LAPS=$LAPS ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  echo "STAGE install_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') skip_marker=$(strings -a mxfs.ko | grep -ac 'P490-SYNC-IOEND-SKIP')"
  t0=$(date +%s)
  timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep.out" | tail -1)"
  # The capture window opens AFTER prep: prep unmounts whatever the previous
  # chain left mounted on the previous build, and that departure is the
  # previous build's, not this one's (s490h counted 32 retained keys from the
  # 0.69.5 teardown at 08:37:58 inside a window opened at 08:37:5x).
  SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
  if [ "$rc" = 0 ]; then
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null > "$O/readback_$n.out" ) &
    done
    wait
    want=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
    ok=0; for n in $(nodes); do [ "$(head -1 "$O/readback_$n.out" 2>/dev/null)" = "$want" ] && ok=$((ok + 1)); done
    echo "READBACK sv=$want: $ok/32"
    for lap in $(seq 1 "$LAPS"); do
      t0=$(date +%s)
      timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$lap.out" 2>&1; rc=$?
      echo "STAGE cc_$lap rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s $(grep -a 'crash_consistency' "$O/cc_$lap.out" | grep -a 'nodes_pass' | grep -ao 'nodes_pass=[0-9/]*' | head -1)"
    done
    # the mass unmount, every node at once, each timed on the node itself
    t0=$(date +%s)
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "t=\$(date +%s%3N); timeout 60 umount $MNT; rc=\$?; echo UMOUNT_RC=\$rc UMOUNT_MS=\$(( \$(date +%s%3N) - t ))" > "$O/umount_$n.txt" 2>&1 ) &
    done
    wait
    echo "STAGE mass_umount wall=$(( $(date +%s) - t0 ))s budget=90s rc0=$(cat "$O"/umount_*.txt | grep -ac 'UMOUNT_RC=0') not_rc0=$(cat "$O"/umount_*.txt | grep -a 'UMOUNT_RC=' | grep -avc 'UMOUNT_RC=0')"
    sleep 5
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P304-|P490-|P302-|P301-|P303-|P-WRCNT-UNDERFLOW|P-IOWAIT-STUCK|P-SEMA|P61-FUA-SKIP|P63-LEAFWR|P63-BMBT|P-SYNCWAIT-OVERRIDE|shut down|Filesystem has been shut down'" 2>/dev/null | gzip > "$O/ctx_$n.gz" ) &
    done
    wait
    untok=0; skipn=0; q=0; nq=0; kr=0
    for n in $(nodes); do
        c=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P304-IOCNT-UNTOKENED'); untok=$((untok + c))
        [ "$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P490-SYNC-IOEND-SKIP')" -gt 0 ] && skipn=$((skipn + 1))
        # only the LAST departure line of the node counts: the prep's own
        # teardown of the previous (0.69.5) mount also prints one
        last=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -a 'P304-RETIRE-QUIESCED\|P304-RETIRE-NOT-QUIESCED' | tail -1)
        case "$last" in *NOT-QUIESCED*) nq=$((nq + 1));; *QUIESCED*) q=$((q + 1));; esac
        echo "$n untokened=$c skip_marker=$(zcat "$O/ctx_$n.gz" 2>/dev/null | grep -ac 'P490-SYNC-IOEND-SKIP') last_departure=$(echo "$last" | grep -ao 'P304-RETIRE-[A-Z-]*QUIESCED[^—]*' | cut -c1-160) umount=$(tr '\n' ' ' < "$O/umount_$n.txt" | grep -ao 'UMOUNT_RC=[0-9]* UMOUNT_MS=[0-9]*')" >> "$O/per_node.txt"
    done
    kr=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P302-PR-KEY-RETAINED' | wc -l)
    echo "VERDICT untokened_lines=$untok skip_marker_nodes=$skipn/32 quiesced=$q/32 not_quiesced=$nq key_retained=$kr underflow=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P-WRCNT-UNDERFLOW') orphan=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P304-IOCNT-ORPHAN') iowait_stuck=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P-IOWAIT-STUCK') sema=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P-SEMA') syncwait_override=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P-SYNCWAIT-OVERRIDE') shutdown=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'shut down') fua_skip_bmbt=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P61-FUA-SKIP-BMBT') leafwr=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P63-LEAFWR') incomplete=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P301-DEPARTURE-INCOMPLETE') indeterminate=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'P303-DEPARTURE-INDETERMINATE')"
    if [ "$untok" = 0 ] && [ "$q" = 32 ] && [ "$nq" = 0 ] && [ "$kr" = 0 ] && [ "$skipn" -gt 0 ]; then echo "RESULT PASS"; else echo "RESULT FAIL"; fi
    sort -t= -k2 -rn "$O/per_node.txt" | head -6 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P490-SYNC-IOEND-SKIP' | head -3 | cut -c1-240 | sed 's/^/    /'
    zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P304-IOCNT-UNTOKENED' | head -3 | cut -c1-240 | sed 's/^/    /'
  else
    echo "NOT RUN: prep rc=$rc"
  fi
  cp "$RESTORE_KO" mxfs.ko && echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$RESTORE_KO" || echo "WARN: could not restore $RESTORE_KO into the tree"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
