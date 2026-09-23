#!/bin/bash
# sess489: HOW LONG DOES A HEALTHY REFUSAL LAST?  (the margin behind the
# D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-PIN-0487 fail-stop grace)
#
# 0.70.0 refuses a committed AG-metadata image for a grant this node does not
# hold and, after mxfs.ailpin_grace_ms (10 s), shuts the mount down.  The
# steady-state producer of refusals is the AG handoff itself: on 0.69.5 the
# plain crash_consistency row logged 393 refusals fleet-wide, each in the gap
# between a release commit and the drain that writes the image home.  Those
# must clear in milliseconds for the grace to be safe; nobody had measured
# it.  0.70.2 counts every refused item at retirement (age from first
# coherent refusal) in a per-mount census at debugfs ailpin_stats and names
# any item slower than mxfs.ailpin_clear_report_ms (P126-REFUSE-CLEARED).
#
# This chain: install the frozen 0.70.2, prep, run crash_consistency LAPS
# times, and after each lap read every node's ailpin_stats and sweep its
# kernel log for the refusal, cleared, pinned and shutdown lines.  Then put
# the tree module back.  Verdict lines:
#   CENSUS lap N: refused=.. cleared=.. max_ms=.. slow=.. pinned=.. shutdown=..
# A max_ms anywhere near the grace, a PINNED line, or a shutdown on a lap that
# the row itself passed is the finding: the grace is too short for this
# fleet's release drain and the fail-stop cannot ship at 10 s.
#
# derived time budgets, derived: prep 300 (measured 106-146 s); each cc row 160
# (manifest 90 + harness overhead, measured 91 s); sweep 90 per node parallel.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess489_ailpin_census.sh s489a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s489a}
GATE=${GATE:-tests/evidence/sess488_p126_producer_s488h.log}
KO=${KO:-tests/evidence/sess489_frozen_0702/mxfs.ko}
RESTORE_KO=${RESTORE_KO:-tests/evidence/sess488_frozen_0695_tree/mxfs.ko}
LAPS=${LAPS:-2}
LOG=tests/evidence/sess489_ailpin_census_$LABEL.log
O=tests/evidence/sess489_ailpin_census_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
nodes() { seq 1 32 | sed 's/^/test/'; }

{
  echo "=== sess489 ailpin_census START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO LAPS=$LAPS ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  echo "STAGE install_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') cleared_line=$(strings -a mxfs.ko | grep -ac 'P126-REFUSE-CLEARED')"
  t0=$(date +%s)
  timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; rc=$?
  echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$O/prep.out" | tail -1)"
  if [ "$rc" = 0 ]; then
    # the fleet must be running the installed build, or the census is vacuous
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null; ls /sys/kernel/debug/mxfs/*/ailpin_stats 2>/dev/null | wc -l" 2>/dev/null > "$O/readback_$n.out" ) &
    done
    wait
    want=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
    ok=0; for n in $(nodes); do [ "$(head -1 "$O/readback_$n.out" 2>/dev/null)" = "$want" ] && [ "$(sed -n 2p "$O/readback_$n.out" 2>/dev/null)" = 1 ] && ok=$((ok + 1)); done
    echo "READBACK sv=$want with ailpin_stats: $ok/32"
    for lap in $(seq 1 "$LAPS"); do
      SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
      timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$lap.out" 2>&1; rc=$?
      echo "STAGE cc_$lap rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s $(grep -a 'crash_consistency' "$O/cc_$lap.out" | grep -a 'nodes_pass' | grep -ao 'nodes_pass=[0-9/]*' | head -1)"
      D="$O/lap$lap"; mkdir -p "$D"
      for n in $(nodes); do
          ( timeout 90 $SSH "$n" "for f in /sys/kernel/debug/mxfs/*/ailpin_stats; do echo \"STATS \$f \$(cat \$f 2>/dev/null | tr '\n' ' ')\"; done; journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P126-|P12-LATCH|P128-AILSTUCK|P131|shut down|Filesystem has been shut down'" 2>/dev/null | gzip > "$D/ctx_$n.gz" ) &
      done
      wait
      refused=0; cleared=0; slow=0; byshut=0; maxall=0; nodes_ref=0; nodes_stats=0
      for n in $(nodes); do
          s=$(zcat "$D/ctx_$n.gz" 2>/dev/null | grep -a '^STATS ' | head -1)
          [ -n "$s" ] && nodes_stats=$((nodes_stats + 1))
          r=$(echo "$s" | grep -ao 'refused=[0-9]*' | cut -d= -f2); r=${r:-0}
          c=$(echo "$s" | grep -ao ' cleared=[0-9]*' | cut -d= -f2); c=${c:-0}
          sl=$(echo "$s" | grep -ao 'slow=[0-9]*' | cut -d= -f2); sl=${sl:-0}
          bs=$(echo "$s" | grep -ao 'cleared_by_shutdown=[0-9]*' | cut -d= -f2); bs=${bs:-0}
          mx=$(echo "$s" | grep -ao 'max_ms=[0-9]*' | cut -d= -f2); mx=${mx:-0}
          [ "$r" -gt 0 ] && nodes_ref=$((nodes_ref + 1))
          refused=$((refused + r)); cleared=$((cleared + c)); slow=$((slow + sl)); byshut=$((byshut + bs))
          [ "$mx" -gt "$maxall" ] && maxall=$mx
      done
      echo "  CENSUS lap $lap: nodes_with_stats=$nodes_stats/32 refused=$refused cleared=$cleared outstanding=$((refused - cleared)) nodes_with_refusals=$nodes_ref slow=$slow max_ms=$maxall cleared_by_shutdown=$byshut pinned=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-AIL-PINNED') shutdown_lines=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'shut down') refuse_lines=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-XFSAILD-REFUSE ') transient=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'REFUSE-TRANSIENT') cleared_lines=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-REFUSE-CLEARED') epoch_mismatch=$(zcat "$D"/ctx_*.gz 2>/dev/null | grep -ac 'P126-EPOCH-MISMATCH')"
      # per-node max, descending, top 8
      for n in $(nodes); do
          s=$(zcat "$D/ctx_$n.gz" 2>/dev/null | grep -a '^STATS ' | head -1)
          mx=$(echo "$s" | grep -ao 'max_ms=[0-9]*' | cut -d= -f2); r=$(echo "$s" | grep -ao 'refused=[0-9]*' | cut -d= -f2)
          echo "${mx:-0} $n refused=${r:-0} mean=$(echo "$s" | grep -ao 'mean_ms=[0-9]*' | cut -d= -f2)"
      done | sort -rn | head -8 | sed 's/^/    max_ms /'
      zcat "$D"/ctx_*.gz 2>/dev/null | grep -a 'P126-REFUSE-CLEARED' | head -5 | cut -c1-260 | sed 's/^/    /'
      zcat "$D"/ctx_*.gz 2>/dev/null | grep -a -E 'P126-AIL-PINNED|shut down' | head -5 | cut -c1-260 | sed 's/^/    /'
    done
  else
    echo "NOT RUN: prep rc=$rc"
  fi
  cp "$RESTORE_KO" mxfs.ko && echo "STAGE restore_tree_ko sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$RESTORE_KO" || echo "WARN: could not restore $RESTORE_KO into the tree"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
