#!/bin/bash
# sess483 chain 131: DOES THE UNMOUNT AG-RELEASE WINDOW GET CROSSED, AND DOES
# CROSSING IT CORRUPT THE PLATTER?
#
# THE DEFECT.  D-UNMOUNT-AG-GRANTS-PUBLISHED-BEFORE-METADATA-QUIESCE-0483.  An
# unmounting node publishes every allocation-group grant it still holds at
# pal/linux/xfs_super.c:2066, sets mp->m_mxfs_dlm = NULL sixteen lines later,
# and only then calls xfs_unmountfs -- whose first act, in upstream's own
# words, is to "perform all on-disk metadata updates required to inactivate
# inodes that the VFS evicted earlier in the unmount process", i.e. AGI and
# inode-btree mutation, followed by an inode flush and the whole-log AIL push.
# The inode-free path does ask for the AG lock (xfs_inactive_ifree,
# xfs/xfs_inode.c:4138, around the entire free transaction);
# __mxfs_ag_dlm_lock answers `if (!dlm) return 0`.  The AIL push takes no lock
# at all.
#
# So this node reads and writes AG metadata, and inode clusters beside it, for
# allocation groups it has already told the cluster are free, with no exclusion
# available.  That much is source-proven.  Two things are not, and this chain
# measures both.
#
#   (1) HOW MUCH TRAFFIC crosses the window.  0.68.1 counts it:
#       P483-AGFREE-WINDOW, one line per unmount.  nodlm_wr and iclus_nodlm_wr
#       are the sharp numbers -- a WRITE issued with the DLM already destroyed,
#       so no exclusion of any kind was possible.  The dlm_* pair is the
#       earlier half of the window, where an acquire could still succeed for
#       real; reported, never scored.
#   (2) WHETHER IT LEAVES DAMAGE.  D-408's symptom is an AGI freecount that
#       disagrees with the inode btrees on the platter after a CLEAN fleet
#       unmount, plus an inode still chained in an unlinked bucket.  With the
#       whole fleet unmounted the image is quiescent, so tools/chk_mxfs reads
#       exactly the state the window left behind.
#
# WHY THIS IS AN A/B AND NOT ONE LAP.  A chk_mxfs error after one lap says
# nothing about WHERE it came from -- mkfs, the mount, the workload, or the
# window.  So the chain runs the same fleet twice against a freshly prepped
# filesystem each time:
#
#   CONTROL    prep, then unmount immediately.  Almost no dirty AG metadata
#              exists, so the window should be near-empty and the platter
#              clean.  This is the baseline for BOTH measurements at once, and
#              it is also the check that a dirty result is not simply what a
#              mount-and-unmount cycle always produces here.
#   CHURN      prep, create and delete FILES files per node, then unmount.
#              The churn dirties inobt, finobt and the AGI across many AGs and
#              leaves deferred inactivation queued, which is precisely the
#              population that gets published and then written anyway.
#
# The result that matters is the DIFFERENCE.  Control clean and churn dirty
# attributes the damage to the window.  Both dirty points at the mount cycle
# rather than this defect.  Both clean bounds the rate under this workload and
# disproves nothing, because the ordering is source-proven and unchanged.
#
# WHY THE CHURN IS IN A PRIVATE DIRECTORY.  Measured sess483 (chain 129): a
# create into a SHARED directory at 32 nodes costs up to 2.15 s, so a shared
# arm would spend the entire budget without adding one inode to the inodegc
# queue.  Private per-node subdirectories run at the measured 27-32 ms.
#
# THE ANTI-VACUITY GATES, which are the point of the whole script.  A zero
# means nothing unless the thing that would have carried a nonzero actually
# ran.  Checked, in order, before any number is read:
#   G1 the built module must carry the probes (strings), with the pattern
#      AFTER-AGFREE, NOT the runtime tag -- the buffer probe's format string is
#      "P483-%s-AFTER-AGFREE" and picks its tag at runtime, so grepping for the
#      runtime tag would abort on a module that DOES carry the probe;
#   G2 every node's srcversion must equal the frozen build's;
#   G3 per-node churn accounting, so a node that made no files is not counted
#      as a clean zero;
#   G4 per-node umount rc AND a mountpoint recheck;
#   G5 the verdict refuses to score unless P483-AGFREE-WINDOW was actually
#      printed, and reports covered/32 as its denominator;
#   G6 P482-UMOUNT-AGREL ags_released is the POPULATION denominator -- an AG
#      handed off cooperatively before unmount is never published by this path,
#      so a fleet that released none has an empty window by construction.
#      Measured on the live fleet sess483 at ags_seen=63 ags_released=1 per
#      node, so this is expected to be nonzero; the gate exists because it is
#      the one way the whole measurement could be vacuous.
#
# derived time budgets, derived rather than rounded.  build 338 s measured (chain
# 128) -> 600.  prep 88-112 s measured -> 300 each leg.  Churn: 400 files/node
# at the measured private p50 of 27-32 ms is ~13 s, plus ~12 s ssh fan-out;
# 180 allows six times that.  Mass umount ~100 s measured for a 31-way
# (tests/clean_depart_mass_umount.sh header) -> 240 each leg.  chk_mxfs 240,
# matching tests/agifc_churn_experiment.sh's measured budget for the same
# image.  Sweep ~40 s -> 120 each leg.  Total ~2400 s.  A timeout on the
# umount step is a RESULT -- a stalling clean unmount is its own defect -- not
# a number to widen.
#
# Usage:  setsid nohup bash tests/sess483_chain131_agfree_window.sh s483a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s483a}
GATE=${GATE:-tests/evidence/sess482_chain130_affine_audit_s482b.log}
LOG=tests/evidence/sess483_chain131_agfree_$LABEL.log
EV=tests/evidence/sess483_agfree_$LABEL
NNODES=${NNODES:-32}
FILES=${FILES:-400}
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"

# Bounded gate: a predecessor that dies without writing DONE must not leave
# this chain waiting forever with the rig idle.
gate_dl=$(( $(date +%s) + 21600 ))
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$gate_dl" ]; then
        echo "=== sess483 chain131 ABORT: gate $GATE never reached DONE within 6 h ===" >> "$LOG"
        echo "DONE $(date -u +%FT%TZ)" >> "$LOG"
        exit 1
    fi
    sleep 30
done

# Extract "name=value" from a probe line.  Anchored on the space before the
# name because nodlm_wr is a SUFFIX of iclus_nodlm_wr and a greedy match would
# silently read the wrong field.
fld() { echo "$2" | sed -n "s/.* $1=\([0-9-]*\).*/\1/p" | head -1; }

# One leg: prep, optionally churn, unmount the whole fleet, sweep, chk.
# $1 = leg name (control|churn), $2 = 1 to churn.
leg() {
    local NAME=$1 DOCHURN=$2 i T0 rc
    local D="$EV/$NAME"
    mkdir -p "$D"
    echo "===== LEG $NAME (churn=$DOCHURN) $(date -u +%FT%TZ) ====="

    timeout 300 ./run.sh "$NNODES" caw prep_cluster; rc=$?
    echo "  STAGE prep rc=$rc"
    [ "$rc" = 0 ] || { echo "  ABORT LEG: prep rc=$rc — nothing below measures anything"; return 1; }

    # G2: the fleet must all be running the build we froze.
    : > "$D/fleet_sv.txt"
    for i in $(seq 1 "$NNODES"); do
        ( s=$(timeout 30 "$SSH" "test$i" "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null | tr -dc 'A-F0-9')
          echo "test$i ${s:-NONE}" > "$D/.sv.test$i" ) &
    done
    wait
    for i in $(seq 1 "$NNODES"); do cat "$D/.sv.test$i" >> "$D/fleet_sv.txt" 2>/dev/null; done
    local match; match=$(grep -c " $SV\$" "$D/fleet_sv.txt")
    echo "  STAGE fleet_identity match=$match/$NNODES sv=$SV"
    if [ "$match" -ne "$NNODES" ]; then
        echo "  ABORT LEG: only $match of $NNODES nodes run the frozen build:"
        grep -v " $SV\$" "$D/fleet_sv.txt" | head -8 | sed 's/^/    /'
        return 1
    fi

    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')

    if [ "$DOCHURN" = 1 ]; then
        T0=$(date +%s)
        : > "$D/churn.txt"
        for i in $(seq 1 "$NNODES"); do
            ( d="$MNT/p483_test$i"
              out=$(timeout 170 "$SSH" "test$i" \
                "mkdir -p $d && for k in \$(seq 1 $FILES); do : > $d/f\$k || break; done; \
                 n=\$(ls -1 $d 2>/dev/null | wc -l); \
                 find $d -type f -delete 2>/dev/null; \
                 r=\$(ls -1 $d 2>/dev/null | wc -l); echo CHURN made=\$n left=\$r" 2>/dev/null)
              echo "test$i ${out:-NO_OUTPUT}" > "$D/.churn.test$i" ) &
        done
        wait
        for i in $(seq 1 "$NNODES"); do cat "$D/.churn.test$i" >> "$D/churn.txt" 2>/dev/null; done
        local cwall=$(( $(date +%s) - T0 ))
        local cmade; cmade=$(grep -c "made=$FILES " "$D/churn.txt")
        echo "  STAGE churn wall=${cwall}s budget=180s nodes_at_full_count=$cmade/$NNODES files_per_node=$FILES"
        grep -v "made=$FILES " "$D/churn.txt" | head -6 | sed 's/^/    SHORT: /'
        [ "$cmade" -lt "$NNODES" ] && \
          echo "    NOTE: $(( NNODES - cmade )) node(s) fell short. They still unmount and report, but contribute less deferred inactivation."
    else
        echo "  STAGE churn skipped (control leg: the filesystem is as prep left it)"
    fi

    # THE MEASUREMENT: a clean fleet unmount, every node, per-node rc.
    T0=$(date +%s)
    : > "$D/umount.txt"
    for i in $(seq 1 "$NNODES"); do
        ( out=$(timeout 220 "$SSH" "test$i" \
            "umount $MNT 2>&1; echo RC=\$?; mountpoint -q $MNT && echo STILL_MOUNTED || echo UNMOUNTED" 2>/dev/null)
          echo "test$i $(echo "$out" | tr '\n' ' ')" > "$D/.um.test$i" ) &
    done
    wait
    for i in $(seq 1 "$NNODES"); do cat "$D/.um.test$i" >> "$D/umount.txt" 2>/dev/null; done
    local uwall=$(( $(date +%s) - T0 ))
    local uok; uok=$(grep -c 'RC=0 UNMOUNTED' "$D/umount.txt")
    echo "  STAGE umount wall=${uwall}s budget=240s clean=$uok/$NNODES"
    [ "$uwall" -ge 240 ] && \
      echo "    budget: the umount step hit its budget. That is a RESULT — a stalling clean unmount is its own defect — not a number to widen."
    grep -v 'RC=0 UNMOUNTED' "$D/umount.txt" | head -8 | sed 's/^/    NOT-CLEAN: /'

    # ON-PLATTER FORENSICS.  Every node is unmounted, so the image is
    # quiescent and this reads the state the window left behind.
    T0=$(date +%s)
    timeout 240 tools/chk_mxfs -v "$IMG" > "$D/chk.txt" 2>&1
    local chkrc=$?
    local cerr; cerr=$(grep -ac 'ERROR' "$D/chk.txt"); cerr=${cerr:-0}
    echo "  STAGE chk rc=$chkrc wall=$(( $(date +%s) - T0 ))s budget=240s img=$IMG ERROR_lines=$cerr"
    [ "$chkrc" = 124 ] && echo "    chk TIMED OUT — treat ERROR_lines as a floor, not a count."
    grep -aiE 'freecount|inobt|finobt|unlinked|ERROR' "$D/chk.txt" | head -14 | sed 's/^/    /'

    # SWEEP.  journalctl, not dmesg: the node ring wraps within minutes under
    # fleet load and a marker-bounded dmesg sweep then silently reads zero.
    # P482-UMOUNT-AGREL comes along because ags_released is the denominator.
    for i in $(seq 1 "$NNODES"); do
        ( timeout 90 "$SSH" "test$i" \
            "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P483-|P482-UMOUNT-AGREL|P482-AGIFC-AUDIT-COVERAGE|P-AGIFC-RELEASE-MISMATCH'" \
            > "$D/p483_test$i.txt" 2>/dev/null ) &
    done
    wait

    # G5: coverage before any verdict.
    local covered=0 missing="" c
    for i in $(seq 1 "$NNODES"); do
        c=$(grep -ac 'P483-AGFREE-WINDOW' "$D/p483_test$i.txt" 2>/dev/null); c=${c:-0}
        [ "$c" -ge 1 ] && covered=$(( covered + 1 )) || missing="$missing test$i"
    done
    echo "  STAGE coverage window_lines_present=$covered/$NNODES${missing:+ missing:$missing}"

    # G6: the population denominator.
    local tot_seen=0 tot_rel=0 relnodes=0 l s r
    for i in $(seq 1 "$NNODES"); do
        l=$(grep -a 'P482-UMOUNT-AGREL' "$D/p483_test$i.txt" 2>/dev/null | tail -1)
        [ -n "$l" ] || continue
        s=$(fld ags_seen "$l"); s=${s:-0}
        r=$(fld ags_released "$l"); r=${r:-0}
        tot_seen=$(( tot_seen + s )); tot_rel=$(( tot_rel + r ))
        [ "$r" -gt 0 ] && relnodes=$(( relnodes + 1 ))
    done
    echo "  POPULATION ags_seen=$tot_seen ags_released=$tot_rel relnodes=$relnodes/$NNODES"

    # The window numbers.
    local ndw=0 ndr=0 indw=0 indr=0 dw=0 dr=0 icw=0 icr=0 nu=0 hot=0 line
    local any=0 anynd=0
    local a b
    for i in $(seq 1 "$NNODES"); do
        line=$(grep -a 'P483-AGFREE-WINDOW' "$D/p483_test$i.txt" 2>/dev/null | tail -1)
        [ -n "$line" ] || continue
        a=$(fld nodlm_wr "$line");          ndw=$(( ndw + ${a:-0} ))
        b=$(fld nodlm_rd "$line");          ndr=$(( ndr + ${b:-0} ))
        a=$(fld iclus_nodlm_wr "$line");    indw=$(( indw + ${a:-0} ))
        b=$(fld iclus_nodlm_rd "$line");    indr=$(( indr + ${b:-0} ))
        a=$(fld dlm_wr "$line");            dw=$(( dw + ${a:-0} ))
        b=$(fld dlm_rd "$line");            dr=$(( dr + ${b:-0} ))
        a=$(fld iclus_dlm_wr "$line");      icw=$(( icw + ${a:-0} ))
        b=$(fld iclus_dlm_rd "$line");      icr=$(( icr + ${b:-0} ))
        a=$(fld nulldlm_acquires "$line");  nu=$(( nu + ${a:-0} ))
        a=$(fld anyio "$line");             any=$(( any + ${a:-0} ))
        b=$(fld anyio_nodlm "$line");       anynd=$(( anynd + ${b:-0} ))
        a=$(fld nodlm_wr "$line"); b=$(fld iclus_nodlm_wr "$line")
        if [ "${a:-0}" -gt 0 ] || [ "${b:-0}" -gt 0 ]; then
            hot=$(( hot + 1 ))
            [ "$hot" -le 6 ] && echo "    test$i: $line"
        fi
    done
    echo "  WINDOW  nodlm_wr=$ndw nodlm_rd=$ndr iclus_nodlm_wr=$indw iclus_nodlm_rd=$indr | dlm_wr=$dw dlm_rd=$dr iclus_dlm_wr=$icw iclus_dlm_rd=$icr | nulldlm_acquires=$nu | nodes_with_unserialised_write=$hot/$covered"
    echo "  CONTROL anyio=$any anyio_nodlm=$anynd — every buffer submission this fleet made inside the window, whatever its type. The eight counts above are only readable while this is nonzero."
    local mm; mm=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -ac 'P-AGIFC-RELEASE-MISMATCH'); mm=${mm:-0}
    echo "  P-AGIFC-RELEASE-MISMATCH (the platter audit's own verdict AT the release instant) = $mm"
    echo "  first AFTER-AGFREE lines (block, buffer type, calling task):"
    cat "$D"/p483_test*.txt 2>/dev/null | grep -a 'AFTER-AGFREE' | head -10 | sed 's/^/    /'
    cat "$D"/p483_test*.txt 2>/dev/null | grep -a 'P483-AGLOCK-NULLDLM' | head -6 | sed 's/^/    /'

    # Publish this leg's numbers for the cross-leg verdict.
    printf '%s covered=%d rel=%d ndw=%d ndr=%d indw=%d indr=%d nu=%d any=%d anynd=%d chkerr=%d chkrc=%d\n' \
        "$NAME" "$covered" "$tot_rel" "$ndw" "$ndr" "$indw" "$indr" "$nu" "$any" "$anynd" "$cerr" "$chkrc" \
        >> "$EV/legs.txt"
    return 0
}

{
  echo "=== sess483 chain131 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  echo "STAGE gate cleared: $GATE"
  : > "$EV/legs.txt"

  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  t0=$(date +%s)
  timeout 600 make modules > "$EV/build.log" 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - t0 ))s"
  if [ "$brc" != 0 ]; then
      echo "ABORT: build rc=$brc — $(grep -a -i 'error' "$EV/build.log" | head -5 | tr '\n' ' ')"
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  # G1: the probes must be IN the module about to be shipped.  Pattern note in
  # the header — the runtime tag is not in the binary, the format string is.
  np=$(strings mxfs.ko 2>/dev/null | grep -ac 'P483-AGFREE-WINDOW')
  nq=$(strings mxfs.ko 2>/dev/null | grep -ac 'AFTER-AGFREE')
  nr=$(strings mxfs.ko 2>/dev/null | grep -ac 'P483-AGLOCK-NULLDLM')
  echo "STAGE instrument_present window=$np agmeta=$nq nulldlm=$nr"
  if [ "${np:-0}" -lt 1 ] || [ "${nq:-0}" -lt 1 ] || [ "${nr:-0}" -lt 1 ]; then
      echo "ABORT: the built mxfs.ko does not carry the 0.68.x probes. Every number"
      echo "       below would be a zero produced by their absence, not their silence."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  FREEZE=tests/evidence/sess483_chain131_frozen_$(tr -d '.\n' < VERSION)
  mkdir -p "$FREEZE" && cp mxfs.ko "$FREEZE/mxfs.ko"
  echo "STAGE identity sv=$SV freeze=$FREEZE"

  leg control 0
  leg churn   1

  echo "--- VERDICT ---"
  cat "$EV/legs.txt" | sed 's/^/  LEG /'
  cget() { grep "^$1 " "$EV/legs.txt" | sed -n "s/.* $2=\([0-9-]*\).*/\1/p" | head -1; }
  c_cov=$(cget control covered); c_cov=${c_cov:-0}
  k_cov=$(cget churn   covered); k_cov=${k_cov:-0}
  k_rel=$(cget churn   rel);     k_rel=${k_rel:-0}
  k_ndw=$(cget churn   ndw);     k_ndw=${k_ndw:-0}
  k_indw=$(cget churn  indw);    k_indw=${k_indw:-0}
  k_ndr=$(cget churn   ndr);     k_ndr=${k_ndr:-0}
  k_nu=$(cget churn    nu);      k_nu=${k_nu:-0}
  k_any=$(cget churn   any);     k_any=${k_any:-0}
  c_err=$(cget control chkerr);  c_err=${c_err:-0}
  k_err=$(cget churn   chkerr);  k_err=${k_err:-0}

  if [ "$k_cov" -eq 0 ]; then
      echo "  VACUOUS: the churn leg produced no P483-AGFREE-WINDOW line on any node."
      echo "  The unmounts did not reach the print. NOTHING here is a measurement and"
      echo "  no zero from this run may be recorded."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  [ "$k_cov" -lt "$NNODES" ] && \
    echo "  PARTIAL COVERAGE: $k_cov of $NNODES nodes reported; every count is over those $k_cov."
  if [ "$k_rel" -eq 0 ]; then
      echo "  EMPTY BY CONSTRUCTION: ags_released=0 across the churn leg — no node still"
      echo "  held an AG at put_super, so this path published nothing and its zeros are"
      echo "  not evidence about the defect. Re-run with a workload that leaves AGs held."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  if [ "$k_ndw" -gt 0 ] || [ "$k_indw" -gt 0 ]; then
      echo "  CONFIRMED (exposure): the fleet WROTE to the platter with its DLM destroyed,"
      echo "  for allocation groups it had already published as free — nodlm_wr=$k_ndw"
      echo "  AG-metadata and iclus_nodlm_wr=$k_indw inode-cluster writes over $k_cov nodes,"
      echo "  against ags_released=$k_rel. D-0483 has its reproduction."
  elif [ "$k_ndr" -gt 0 ] || [ "$k_nu" -gt 0 ]; then
      echo "  PARTIAL: the window is reached but no WRITE crossed it with the DLM gone."
      echo "  Reads and/or acquires-that-acquired-nothing did (nodlm_rd=$k_ndr,"
      echo "  nulldlm_acquires=$k_nu). Still a protocol violation, not yet a lost update."
  elif [ "$k_any" -eq 0 ]; then
      echo "  NOT A MEASUREMENT: every window counter is zero AND so is the positive"
      echo "  control (anyio=0) — this fleet submitted NO buffer of any kind inside the"
      echo "  window, so a zero on the eight typed counters could not have been anything"
      echo "  else. Either the mount really does submit nothing after publishing its"
      echo "  grants — a strong claim that needs its own evidence, not an assumption —"
      echo "  or the counting point was never reached. Do not record this as a bound."
  else
      echo "  NOT REACHED in this run, and the instrument was LIVE: anyio=$k_any submissions"
      echo "  crossed the window over $k_cov node(s) with ags_released=$k_rel, of which"
      echo "  ZERO were AG metadata or inode clusters. That BOUNDS the rate under this"
      echo "  workload against a real denominator. It disproves nothing — the ordering is"
      echo "  source-proven and unchanged — and the next lap should hold files open across"
      echo "  unlink so the inodes reach unmount still needing inactivation."
  fi

  echo "  PLATTER: chk_mxfs ERROR lines — control=$c_err churn=$k_err"
  if [ "$k_err" -gt "$c_err" ]; then
      echo "  CONFIRMED (damage): the churn leg left MORE on-platter errors than the"
      echo "  control on an identically prepped filesystem. Read $EV/churn/chk.txt against"
      echo "  $EV/control/chk.txt; an AGI-freecount-versus-inode-btree disagreement there is"
      echo "  D-AGIFC-SHARED-AG-DOUBLE-VICTIM-REPLAY-DIVERGENCE-408's symptom reproduced on"
      echo "  demand, and this chain is the first thing to have produced it deliberately."
  elif [ "$k_err" -gt 0 ]; then
      echo "  Both legs show errors ($c_err vs $k_err) — NOT attributable to the window;"
      echo "  a plain prep/mount/unmount cycle produces them too. That is its own finding"
      echo "  and must be filed separately before this chain's exposure numbers are read"
      echo "  as damage."
  else
      echo "  Both legs clean on the platter. Whatever crossed the window did not corrupt"
      echo "  anything chk_mxfs checks in this run. Exposure without observed damage is"
      echo "  still a defect — the ordering permits the loss, and a clean lap only bounds"
      echo "  how often it lands."
  fi
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
