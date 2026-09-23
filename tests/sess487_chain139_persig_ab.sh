#!/bin/bash
# sess487 chain 139: IS THE PER-MODIFY DIRECTORY FLUSH STILL NEEDED, AND WHAT
# DOES IT COST THE FAILING ROW?
#
# THE TERM.  Chain 137 (0.69.4) decomposed the create a node pays WHILE IT
# HOLDS the shared directory's EX grant: 16.0 ms, of which dirsig_ms = 4.5 ms
# (28%) is mxfs_dlm_dir_durable_signal -- a synchronous xfs_bwrite of the
# directory's dirty data blocks on EVERY create once a peer has ever touched
# the directory (mxfs.dir_persig_flush=1, the default).  The private arm pays
# 0.  Mode 2 ("only when a peer wants EX") did not ablate it: in a 32-way
# storm a peer always wants EX.
#
# WHY IT EXISTS.  sess48 re-introduced the per-modify flush as a WORKAROUND for
# a proven release-drain gap: a node's last committed dir deletes were not
# destaged at its EX->PR downgrade, so a peer cold-read stale disk (uv "none
# remain got=10").  The release/drain pipeline has since been rebuilt around
# architectural invariant 1 (full drain before the on-disk unlock).  A per-
# create synchronous flush under the held ILOCK is also known to be harmful on
# its own (sess7: gen==0 flush-on-every-create -> peer EX acquires timed out ->
# mass shutdown).
#
# Design-consult ruling (sess487): make the flush RELEASE-ONLY first -- the largest
# fully identified in-tenure term -- and decide it by an A/B in which mode 1
# (A) and mode 0 (B, never flush per modify; the release drain is the only
# durability point) both run the real crash_consistency row AND the directory-
# coherency rows that are the sess48 loss workloads.  Acceptance for B needs
# BOTH: zero stale observations on the coherency rows, and dirsig_ms ~0 with
# the row's create phase faster.  This chain is that A/B; it changes no default
# and builds nothing -- mxfs.dir_persig_flush is a module parameter, shipped to
# every node's insmod through MXFS_EXTRA_MODARGS (tests/setup/prep_node.sh).
#
# sess489 REWRITE.  The s488c run measured nothing: its armed crash_consistency
# ran on the mount the rows had left behind, so the row's 3200 "creates" were
# O_TRUNC overwrites of files the failed in-chain row had already made (the
# create probe fired 102 times on 9 nodes instead of ~3200 on 32) and the
# 23-29 s PASS was not a create measurement.  Worse, the in-chain mode-0 row
# LOST AN ENTRY: three readers of node 23 could not find node23_f50.md5, the
# last file node 23 created, 10 s after node 23's sync and the written
# barrier -- the sess48 shape -- and the harness reported it only as
# BUDGET_EXHAUSTED.  So each leg now runs, in this order:
#   1. prep with the leg's module argument; read the fleet back.
#   2. the ARMED crash_consistency row on the fresh filesystem (create_cost_ms=1
#      by sysfs; the marker matches, so no reload): real creates, the
#      decomposition and the per-node phase timeline (tools/ccph_timeline.py).
#   3. the row set, so the harness's own budgets/verdicts apply.  Its
#      crash_consistency runs on a fresh directory of its own (the board
#      shape: right after rsync_paired); the sweep keeps only the last row's
#      window.
#   4. crash_consistency once more on ANOTHER fresh directory (CC_TAG) on the
#      post-rows mount, to separate the predecessor state from the create
#      pace.
# Every sweep counts mxfs-cc-FAIL (a cold reader that could not reproduce a
# writer's checksum -- an entry or contents missing from the platter after the
# writer's sync) as the loss detector for mode 0, independent of the harness
# verdict; a nonzero count in B is the sess48 gap re-opened.
# derived time budgets, derived: prep 300 (measured 106-146 s); each cc row 160
# (manifest 90 + harness overhead); rows: manifest walls
# 90+120+240+60+60+60+60+30+60 = 780 + 12 s x 9 + 15 = ~900 -> timeout 1300;
# sweep 90.  ~40 min per leg, ~80 min total after the gate.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess487_chain139_persig_ab.sh s489b &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s489b}
GATE=${GATE:-tests/evidence/sess489_ailpin_census_s489a.log}
LOG=tests/evidence/sess487_chain139_persig_ab_$LABEL.log
O=tests/evidence/sess487_persig_ab_$LABEL
SSH=tools/mxfs_sshpass.sh
ROWS=${ROWS:-crash_consistency dir_reuse_coherency dirent_durability dirent_publish_integrity dirent_type_integrity zero_silent_loss cache_coherency strong_consistency rsync_paired}
LEGS=${LEGS:-A B}
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

readback() { # <param> <want>  -> prints ok/32
    local p=$1 v=$2 ok=0 bad="" n
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/parameters/$p 2>/dev/null" > "$O/.rb.$p.$n" 2>/dev/null ) &
    done
    wait
    for n in $(nodes); do
        [ "$(tr -d '[:space:]' < "$O/.rb.$p.$n" 2>/dev/null)" = "$v" ] && ok=$((ok + 1)) || bad="$bad $n"
    done
    echo "  READBACK $p=$v: $ok/32${bad:+ ; MISMATCH:$bad}"
    [ "$ok" -eq 32 ]
}

arm() { # <param> <value>
    local p=$1 v=$2 n
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "echo $v > /sys/module/mxfs/parameters/$p 2>/dev/null" >/dev/null 2>&1 ) &
    done
    wait
    readback "$p" "$v"
}

sweep() { # <since> <dir>  -- keeps each node's log from its LAST cc start in the window
    local since=$1 d=$2 n c hit=0 creates=0 fails=0 vd=0
    mkdir -p "$d"
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P132-CREATE|P483-DIRTENURE|P-DSIG|mxfs-CCph|mxfs-cc-FAIL|mxfs-cc-DISCRIM|P-DIRWR|P10-RDBLK|P11-|P-RELFLUSH|P141-UNLK-EXCLR|P126-DEMOTE' | awk '/mxfs-CCph rank=[0-9]+ PHASE=start/{buf=\"\"} {buf=buf \$0 \"\\n\"} END{printf \"%s\", buf}'" \
            2>/dev/null | gzip > "$d/kernlog_$n.gz" ) &
    done
    wait
    for n in $(nodes); do
        c=$(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'P132-CREATE'); c=${c:-0}
        [ "$c" -gt 0 ] && hit=$((hit + 1)); creates=$((creates + c))
        fails=$((fails + $(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'mxfs-cc-FAIL')))
        zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -aq 'PHASE=verify-done' && vd=$((vd + 1))
    done
    echo "  STAGE sweep dir=$d nodes_with_P132=$hit/32 P132_lines=$creates (3200 = every create sampled) cc_FAIL_lines=$fails nodes_reaching_verify=$vd/32"
    [ "$fails" -gt 0 ] && zcat "$d"/kernlog_*.gz 2>/dev/null | grep -a 'mxfs-cc-FAIL' | head -6 | cut -c1-160 | sed 's/^/    LOSS: /'
    python3 tools/ccph_timeline.py "$d" 2>&1 | tail -4 | sed 's/^/  /'
    python3 tools/p132_phase_summary.py "$d" 2>&1 | grep -aE 'IN-TENURE|in-tenure|dirsig_ms|rfr_ms|icr_ms|other_ms|total_ms|dlk_ms|dia_ms' | head -24 | sed 's/^/  /'
    python3 tools/dirtenure_summary.py "$d" 2>&1 | grep -aE 'SECTION 2|tenures|K \[|gap_ms|creates' | head -12 | sed 's/^/  /'
}

cc_row() { # <name> <outfile> [MXFS_TEST_ENV]
    local name=$1 out=$2 env=${3:-} t0 rc
    t0=$(date +%s)
    MXFS_TEST_ENV="$env" timeout 160 ./run.sh 32 caw crash_consistency > "$out" 2>&1; rc=$?
    echo "STAGE $name rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s env='$env'"
    grep -aE 'crash_consistency' "$out" | grep -a 'nodes_pass' | cut -c1-300 | sed "s/^/  $name ROW: /"
}

{
  echo "=== sess487 chain139 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ko_sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  strings -a mxfs.ko | grep -q 'rfr_ms=' || { echo "ABORT: tree mxfs.ko lacks the 0.69.4 rfr_ms= probe; dirsig cannot be attributed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  grep -q 'CC_TAG' tests/suite/crash_consistency.sh || { echo "ABORT: tests/suite/crash_consistency.sh lacks CC_TAG; the post-rows row would overwrite"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for leg in $LEGS; do
    case "$leg" in
        A) mode=1; extra="" ;;
        B) mode=0; extra="dir_persig_flush=0" ;;
        *) echo "ABORT: unknown leg $leg"; echo "DONE $(date -u +%FT%TZ)"; exit 1 ;;
    esac
    echo "--- leg=$leg dir_persig_flush=$mode MXFS_EXTRA_MODARGS='$extra' ---"
    # sess488: run.sh with a test filter never preps, so the leg's module
    # argument only reaches insmod through an explicit prep; read the fleet
    # back BEFORE any row so a leg is never scored on a mode it did not run.
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$extra" timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep_$leg.out" 2>&1; prc=$?
    echo "STAGE prep_$leg rc=$prc wall=$(( $(date +%s) - t0 ))s budget=300s"
    [ "$prc" = 0 ] || { echo "  LEG $leg NOT RUN: prep rc=$prc"; continue; }
    readback dir_persig_flush "$mode" || { echo "  LEG $leg NOT RUN: the fleet did not come up at dir_persig_flush=$mode"; continue; }
    if ! arm create_cost_ms 1; then
        echo "  LEG $leg NOT RUN: create_cost_ms did not land 32/32"; continue
    fi
    # 2. the armed row on the fresh filesystem: real creates
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
    cc_row "cc_fresh_$leg" "$O/cc_fresh_$leg.out"
    sweep "$SINCE" "$O/${leg}_fresh"
    # 3. the row set (its crash_consistency lands on a fresh directory of its own)
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$extra" MXFS_TEST_ENV="CC_TAG=rows" timeout 1300 ./run.sh 32 caw $ROWS > "$O/rows_$leg.out" 2>&1; rc=$?
    echo "STAGE rows_$leg rc=$rc wall=$(( $(date +%s) - t0 ))s budget=1300s"
    [ "$rc" = 124 ] && echo "  budget: the row set hit its wrapper budget — a result, not a number to widen."
    grep -aE '^\s+(PASS|FAIL)\s' "$O/rows_$leg.out" | cut -c1-230 | sed "s/^/  $leg ROW: /"
    readback dir_persig_flush "$mode" || echo "  LEG $leg NOT TRUSTED: the fleet is not uniformly at dir_persig_flush=$mode after the rows"
    sweep "$SINCE" "$O/${leg}_rows"
    # 4. one more fresh directory on the post-rows mount
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
    cc_row "cc_postrows_$leg" "$O/cc_postrows_$leg.out" "CC_TAG=postrows"
    sweep "$SINCE" "$O/${leg}_postrows"
    readback dir_persig_flush "$mode" || echo "  LEG $leg NOT TRUSTED: mode drifted"
  done

  echo "--- VERDICT ---"
  echo "  Read P132_lines first: a sweep far below 3200 measured overwrites, not creates, and its statistics are void."
  echo "  B passes the correctness half only if every row that PASSED in A also PASSED in B AND every B sweep shows cc_FAIL_lines=0; a cold reader that cannot find a writer's synced file in B is the sess48 gap re-opened and mode 0 is REFUTED as a fix direction until the release drain is fixed."
  echo "  B's saving is the in-tenure dirsig_ms delta (A ~4.5 ms -> B ~0) and the write_phase_s delta on the fresh rows; the row is not expected to PASS on this change alone (GPT arithmetic: needs ~6 ms in-tenure AND handoff < ~30 ms)."
  echo "  cc_fresh vs the rows' cc vs cc_postrows on the same leg separates the predecessor state from the create pace."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
