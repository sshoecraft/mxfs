#!/bin/bash
# sess495 chain 141: DOES SKIPPING THE ADOPT CHECK'S FUA INODE READ UNDER A
# CONTINUOUSLY HELD EX GRANT REMOVE THE rfr TERM WITHOUT A COHERENCY REGRESSION?
# (D-32NODE-SHARED-DIR-CREATE-PACE, sess487 ruling item 2, landed 0.70.14)
#
# THE TERM.  Chain 137/139 decomposed the in-tenure create: rfr_ms 1.0 ms in
# the shared directory against 0.2 ms private.  The rfr window covers the
# modify-refresh evict walk and mxfs_dir_modify_adopt_disk_format's synchronous
# FUA read of the directory's inode cluster (gated at the call site on
# dir_gen>0, which is why the private arm does not pay it).  0.70.14 records
# the (hold-epoch, incarnation, dir gen) tuple after a clean read taken under
# EX and skips the read while the tuple still matches and the grant is still
# held and not stale (mxfs.dir_adopt_skip_held_ex, default 1).
#
# THE A/B.  Same frozen 0.70.14 module on both legs; the knob flips by sysfs
# after prep (no reload), read back 32/32 before any row:
#   A  dir_adopt_skip_held_ex=1  (the fix)
#   B  dir_adopt_skip_held_ex=0  (the control: read on every modify)
# Each leg: fresh prep, the ARMED crash_consistency row on the fresh filesystem
# (create_cost_ms=1 -> every create sampled), then the directory-coherency row
# set on a fresh directory of its own (CC_TAG=rows).  The sweep keeps P132 +
# P495-ADOPT-SKIP + P61-ADOPT + P190 lines and counts mxfs-cc-FAIL.
# PASS for the fix = A's in-tenure rfr_ms well below B's (expected ~0.1 vs
# ~1.0), P495-ADOPT-SKIP present on every node in A and absent in B, and every
# coherency row that passed in B also passed in A with cc_FAIL_lines=0.
# derived time budgets, derived: prep 300 (measured 104-146 s); cc row 160 (manifest
# 90 + harness); rows: manifest walls 90+120+240+60+60+60+60+30+60 = 780 +
# 12 s x 9 + 15 = ~900 -> 1300; sweep 90.  ~22 min per leg.
#
# Usage: GATE=<log> setsid nohup bash tests/sess495_chain141_adopt_skip.sh s495b &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s495b}
GATE=${GATE:-tests/evidence/sess495_chain140_board_s495a.log}
KO=${KO:-tests/evidence/sess495_frozen_07014/mxfs.ko}
WANT_SV=${WANT_SV:-A84A673F00C9B914F386CB6}
LOG=tests/evidence/sess495_chain141_adopt_skip_$LABEL.log
O=tests/evidence/sess495_adopt_skip_$LABEL
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

sweep() { # <since> <dir>
    local since=$1 d=$2 n c hit=0 creates=0 fails=0 vd=0 skipn=0 adopt=0
    mkdir -p "$d"
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P132-CREATE|P483-DIRTENURE|P495-ADOPT-|P61-ADOPT|P190-MODIFY-BASE-BEHIND|mxfs-CCph|mxfs-cc-FAIL|mxfs-cc-DISCRIM|Corruption of in-memory|Shutting down|P126-REFUSE|P128-'" \
            2>/dev/null | gzip > "$d/kernlog_$n.gz" ) &
    done
    wait
    for n in $(nodes); do
        c=$(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'P132-CREATE'); c=${c:-0}
        [ "$c" -gt 0 ] && hit=$((hit + 1)); creates=$((creates + c))
        fails=$((fails + $(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'mxfs-cc-FAIL')))
        zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -aq 'P495-ADOPT-SKIP' && skipn=$((skipn + 1))
        adopt=$((adopt + $(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'P61-ADOPT-DISK\|P190-MODIFY-BASE-BEHIND')))
        zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -aq 'PHASE=verify-done' && vd=$((vd + 1))
    done
    echo "  STAGE sweep dir=$d nodes_with_P132=$hit/32 P132_lines=$creates (3200 = every create sampled) cc_FAIL_lines=$fails nodes_reaching_verify=$vd/32 nodes_with_P495_skip=$skipn/32 adopt_reload_lines=$adopt shutdown_lines=$(zcat "$d"/kernlog_*.gz 2>/dev/null | grep -ac 'Shutting down')"
    [ "$fails" -gt 0 ] && zcat "$d"/kernlog_*.gz 2>/dev/null | grep -a 'mxfs-cc-FAIL' | head -6 | cut -c1-160 | sed 's/^/    LOSS: /'
    # 0.70.16: which tuple term re-armed the read, when the skip did not fire
    zcat "$d"/kernlog_*.gz 2>/dev/null | grep -a 'P495-ADOPT-READ' | python3 -c '
import sys, re, collections
c = collections.Counter(); n = 0
for line in sys.stdin:
    kv = dict(re.findall(r"(\w+)=(\S+)", line)); n += 1
    why = []
    if kv.get("mode") != "5": why.append("mode=" + kv.get("mode", "?"))
    if kv.get("stale") == "1": why.append("stale")
    if kv.get("epoch") != kv.get("ok_epoch"): why.append("epoch")
    if kv.get("incarn") != kv.get("ok_incarn"): why.append("incarn")
    c["+".join(why) or "none(dir_gen-only?)"] += 1
print("  ADOPT-READ lines=%d by mismatched term: %s" % (n, " ".join("%s=%d" % kv for kv in c.most_common())))'
    python3 tools/ccph_timeline.py "$d" 2>&1 | tail -4 | sed 's/^/  /'
    python3 tools/p132_phase_summary.py "$d" 2>&1 | grep -aE 'IN-TENURE|in-tenure|rfr_ms|lkp_ms|dirsig_ms|other_ms|total_ms|dlk_ms|lkp_fua' | head -30 | sed 's/^/  /'
}

cc_row() { # <name> <outfile> [MXFS_TEST_ENV]
    local name=$1 out=$2 env=${3:-} t0 rc
    t0=$(date +%s)
    MXFS_TEST_ENV="$env" timeout 160 ./run.sh 32 caw crash_consistency > "$out" 2>&1; rc=$?
    echo "STAGE $name rc=$rc wall=$(( $(date +%s) - t0 ))s budget=160s env='$env'"
    grep -aE 'crash_consistency' "$out" | grep -a 'nodes_pass' | cut -c1-300 | sed "s/^/  $name ROW: /"
}

{
  echo "=== sess495 chain141 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO want_sv=$WANT_SV ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do
    [ -f "$(dirname "$KO")/tools/$t" ] && cp "$(dirname "$KO")/tools/$t" tools/$t
  done
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_ko sv=$sv want=$WANT_SV marker=$(strings -a mxfs.ko | grep -ac 'P495-ADOPT-SKIP')"
  [ "$sv" = "$WANT_SV" ] || { echo "ABORT: installed sv $sv != $WANT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for leg in $LEGS; do
    case "$leg" in
        A) knob=1 ;;
        B) knob=0 ;;
        *) echo "ABORT: unknown leg $leg"; echo "DONE $(date -u +%FT%TZ)"; exit 1 ;;
    esac
    echo "--- leg=$leg dir_adopt_skip_held_ex=$knob $(date -u +%FT%TZ) ---"
    t0=$(date +%s)
    timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep_$leg.out" 2>&1; prc=$?
    echo "STAGE prep_$leg rc=$prc wall=$(( $(date +%s) - t0 ))s budget=300s"
    [ "$prc" = 0 ] || { echo "  LEG $leg NOT RUN: prep rc=$prc"; continue; }
    idok=0
    for n in $(nodes); do ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -dc 'A-F0-9' > "$O/.sv.$n" ) & done; wait
    for n in $(nodes); do [ "$(cat "$O/.sv.$n" 2>/dev/null)" = "$sv" ] && idok=$((idok + 1)); done
    echo "  STAGE fleet_identity match=$idok/32 sv=$sv"
    [ "$idok" -eq 32 ] || { echo "  LEG $leg NOT RUN: fleet identity mismatch"; continue; }
    arm dir_adopt_skip_held_ex "$knob" || { echo "  LEG $leg NOT RUN: knob did not land 32/32"; continue; }
    arm create_cost_ms 1 || { echo "  LEG $leg NOT RUN: create_cost_ms did not land 32/32"; continue; }
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
    cc_row "cc_fresh_$leg" "$O/cc_fresh_$leg.out"
    sweep "$SINCE" "$O/${leg}_fresh"
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    MXFS_TEST_ENV="CC_TAG=rows" timeout 1300 ./run.sh 32 caw $ROWS > "$O/rows_$leg.out" 2>&1; rc=$?
    echo "STAGE rows_$leg rc=$rc wall=$(( $(date +%s) - t0 ))s budget=1300s"
    [ "$rc" = 124 ] && echo "  budget: the row set hit its wrapper budget — a result, not a number to widen."
    grep -aE '^\s+(PASS|FAIL)\s' "$O/rows_$leg.out" | cut -c1-230 | sed "s/^/  $leg ROW: /"
    readback dir_adopt_skip_held_ex "$knob" || echo "  LEG $leg NOT TRUSTED: knob drifted during the rows"
    sweep "$SINCE" "$O/${leg}_rows"
  done

  echo "--- VERDICT ---"
  echo "  Read P132_lines first: a sweep far below 3200 measured overwrites, not creates."
  echo "  Fix verified if: A in-tenure rfr_ms << B (expected ~0.1 vs ~1.0); nodes_with_P495_skip=32/32 in A and 0/32 in B; every row PASS in B is PASS in A; cc_FAIL_lines=0 and shutdown_lines=0 in every A sweep."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
