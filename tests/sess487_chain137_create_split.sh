#!/bin/bash
# sess487 chain 137: WHERE DO THE 18 IN-TENURE MILLISECONDS GO?
#
# WHAT IS KNOWN (sess487, from evidence already on disk, no rig time):
#   - tools/dirtenure_summary.py on the 0.69.3 board's crash_consistency row
#     (run 20260904T043723Z): the shared directory rotates round the fleet,
#     each node completing ~10 creates per grant tenure (K mean 9.8, 63% in
#     8-15) and then waiting ~6.5 s for the grant to come back (gap_ms >= 3 s
#     on 96% of tenures; 45-84 s of every node's 88 s write phase is that
#     wait).  So one rotation of 32 turns takes ~6.5 s: ~200 ms per turn for
#     ~10 creates = ~20 ms per create WITH THE DIRECTORY EX HELD.  That
#     in-tenure cost sets the rotation length and therefore the row's wall.
#   - tools/p132_phase_summary.py on chain 128's armed P132-CREATE lines
#     (0.65.0, shared arm, 3144 creates): the in-tenure create (dlk_ms < 5,
#     n=2729) costs 17.9 ms: 9.6 ms unattributed between inode allocation and
#     the commit (other_ms, 53%), 4.7 ms in mxfs_dlm_dir_durable_signal
#     (dirsig_ms, 26% -- a synchronous xfs_bwrite of the directory's data
#     blocks on EVERY create while gen>0, mxfs.dir_persig_flush=1), 1.1 dlk,
#     1.0 dia, 0.5 pdur, 1.1 post-commit other.
#   - Native XFS creates in ~0.1-0.3 ms; MXFS at 1 node in 4.6 ms.
#
# WHAT 0.69.4 ADDS (this chain builds and deploys it): four stamps that split
# other_ms at the MXFS hooks that do synchronous I/O inside the held tenure --
# rfr_ms (mxfs_dlm_dir_modify_refresh + the adopt-disk-format FUA read of the
# directory inode, gated on i_dlm_dir_gen>0 which never returns to 0 once a
# peer has touched the dir), icr_ms (existence lookup + xfs_icreate), mrg_ms
# (peer merge + stale reconcile + pending replay), cc_ms (xfs_dir_create_child)
# -- and the always-stamped clock that makes P483-DIRTENURE's wall_ms real.
#
# HYPOTHESIS H-T1 (falsifiable): within a tenure, creates 2..K pay for
# synchronous I/O that is redundant while the EX grant is held -- the adopt
# FUA read (rfr_ms ~1-2 ms) and the per-modify durable flush (dirsig_ms ~5 ms)
# -- and these two account for most of the ~18 ms.  Predicts: in the SHARED
# arm, in-tenure rfr_ms mean >= 1 ms and dirsig_ms ~4-5 ms; in the PRIVATE arm
# (gen stays 0: no peer touches a node's private dir) both ~0 and the create
# ~5-8 ms.  Falsified if in-tenure rfr_ms ~0 and icr/mrg/cc carry the 9.6 ms.
#
# LEG 3 (ablation, NOT a fix, changes no default): the shared arm again with
# mxfs.dir_persig_flush=2 (flush only when a peer wants EX -- the knob that
# already exists for this A/B) on every node, arm-verified.  Measures how much
# of the in-tenure cost and of the row wall the per-modify flush is.  Whether
# mode 2 is CORRECT is a separate question with its own (sess48) history and
# is not decided here.
#
# ANTI-VACUITY: the build must contain 'rfr_ms=' (strings); every node must
# confirm create_cost_ms=1 (and, leg 3, dir_persig_flush=2) by read-back; the
# P132 lines are swept from every node's kernel journal by THIS chain (the
# harness archives kernlogs only on a FAILING row, which is why chain 128 lost
# its private arm), and a leg with fewer than 32 nodes carrying lines is
# reported as such.
#
# derived time budgets, derived: build 600 s (measured 37 s scratch incremental,
# 69-71 s full); prep 300 s (measured 88-137 s); each row 160 s = its
# UNCHANGED 90 s budget + ~37 s harness startup; sweep 90 s.  ~22 min.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess487_chain137_create_split.sh s487c &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s487c}
GATE=${GATE:-tests/evidence/sess485_chain133_agfree_hoist_s487b.log}
LOG=tests/evidence/sess487_chain137_create_split_$LABEL.log
O=tests/evidence/sess487_create_split_$LABEL
FREEZE=tests/evidence/sess487_frozen_0694_tree
SSH=tools/mxfs_sshpass.sh
THRESH=${THRESH:-1}
LEGS=${LEGS:-shared private shared_persig2}
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

# Set a module parameter on every node and PROVE it took.
arm() { # <param> <value>
    local p=$1 v=$2 ok=0 bad=""
    for n in $(nodes); do
        ( $SSH "$n" "echo $v > /sys/module/mxfs/parameters/$p 2>/dev/null;
                     cat /sys/module/mxfs/parameters/$p 2>/dev/null" \
              > "$O/.arm.$p.$n" 2>/dev/null ) &
    done
    wait
    for n in $(nodes); do
        if [ "$(tr -d '[:space:]' < "$O/.arm.$p.$n" 2>/dev/null)" = "$v" ]; then
            ok=$((ok + 1))
        else
            bad="$bad $n"
        fi
    done
    echo "  arm $p=$v: $ok/32 confirmed${bad:+ ; NOT ARMED:$bad}"
    [ "$ok" -eq 32 ]
}

# Sweep the probe lines from every node's kernel journal since $1 into $2/.
sweep() { # <since> <dir>
    local since=$1 d=$2 n c hit=0
    mkdir -p "$d"
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P132-CREATE|P483-DIRTENURE|P-DSIG|P61-ADOPT'" \
            2>/dev/null | gzip > "$d/kernlog_$n.gz" ) &
    done
    wait
    for n in $(nodes); do
        c=$(zcat "$d/kernlog_$n.gz" 2>/dev/null | grep -ac 'P132-CREATE'); c=${c:-0}
        [ "$c" -gt 0 ] && hit=$((hit + 1))
    done
    echo "  STAGE sweep dir=$d nodes_with_P132=$hit/32"
}

{
  echo "=== sess487 chain137 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      if [ "$(date +%s)" -ge "$gate_dl" ]; then
          echo "ABORT: gate $GATE never reached DONE within 6 h"
          echo "DONE $(date -u +%FT%TZ)"; exit 1
      fi
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # ---- build and deploy 0.69.4 into the tree ------------------------------
  t0=$(date +%s)
  timeout 600 make modules > "$O/build.log" 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - t0 ))s VERSION=$(cat VERSION)"
  if [ "$brc" -ne 0 ]; then
      tail -20 "$O/build.log"; echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE identity sv=$sv"
  if ! strings -a mxfs.ko | grep -q 'rfr_ms='; then
      echo "ABORT: mxfs.ko does not contain the rfr_ms= field; the link did not pick up xfs_inode.o."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  echo "STAGE probe_present rfr_ms=yes"
  mkdir -p "$FREEZE" && cp mxfs.ko "$FREEZE/mxfs.ko" && echo "STAGE freeze $FREEZE sv=$sv"

  for leg in $LEGS; do
    echo "--- leg=$leg ---"
    timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; prc=$?
    echo "STAGE prep_$leg rc=$prc"
    if [ "$prc" -ne 0 ]; then
        echo "LEG $leg NOT RUN: prep rc=$prc"
        continue
    fi
    # fleet identity: every node must run this build
    idok=0
    for n in $(nodes); do
        ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -dc 'A-F0-9' > "$O/.sv.$n" ) &
    done
    wait
    for n in $(nodes); do [ "$(cat "$O/.sv.$n" 2>/dev/null)" = "$sv" ] && idok=$((idok + 1)); done
    echo "  STAGE fleet_identity match=$idok/32 sv=$sv"
    [ "$idok" -eq 32 ] || { echo "LEG $leg NOT RUN: fleet identity mismatch"; continue; }
    # the prep reloads the module, so every knob resets here
    if ! arm create_cost_ms "$THRESH"; then
        echo "LEG $leg NOT RUN: the probe is not armed on all 32 nodes."
        continue
    fi
    if [ "$leg" = shared_persig2 ]; then
        if ! arm dir_persig_flush 2; then
            echo "LEG $leg NOT RUN: dir_persig_flush=2 did not land on all 32 nodes."
            continue
        fi
    fi
    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')
    t0=$(date +%s)
    if [ "$leg" = private ]; then
        MXFS_TEST_ENV="CC_PRIVATE=1" timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$leg.out" 2>&1
    else
        timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_$leg.out" 2>&1
    fi
    echo "STAGE cc_$leg rc=$? wall=$(( $(date +%s) - t0 ))s"
    grep -aE 'crash_consistency' "$O/cc_$leg.out" | grep -a 'nodes_pass' | cut -c1-320 | sed "s/^/  $leg ROW: /"
    sweep "$SINCE" "$O/$leg"
    echo "  --- create-cost attribution, leg=$leg (all creates, then in-tenure dlk_ms<5) ---"
    python3 tools/p132_attribute.py "$O/$leg" 2>&1 | sed 's/^/  /'
    python3 tools/p132_phase_summary.py "$O/$leg" 2>&1 | sed 's/^/  /'
    echo "  --- directory tenures, leg=$leg (wall_ms must be nonzero on 0.69.4) ---"
    python3 tools/dirtenure_summary.py "$O/$leg" 2>&1 | sed 's/^/  /' | head -60
  done

  echo "--- VERDICT ---"
  echo "  Read, per leg, the IN-TENURE table: which of rfr/icr/mrg/cc/dirsig carries the ~18 ms."
  echo "  H-T1 predicts shared: rfr_ms >= 1 ms and dirsig_ms ~5 ms; private: both ~0 and total ~5-8 ms."
  echo "  shared_persig2 vs shared: the dirsig_ms delta and the row wall delta are the per-modify flush's cost; correctness of mode 2 is NOT decided here."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
