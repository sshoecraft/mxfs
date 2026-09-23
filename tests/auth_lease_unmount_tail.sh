#!/bin/bash
# auth_lease_unmount_tail.sh — after a mount detaches its DLM, is what it still
# writes decided by its authority lease, or by the absence of a pointer?
#
# WHAT THIS IS ABOUT.  put_super detaches the DLM (mp->m_mxfs_dlm = NULL) and
# joins the heartbeat thread, and only THEN does xfs_unmountfs write the log
# cover and the unmount record.  Until 0.89.21 every authority gate read that
# pointer and treated its absence as "not a clustered mount", so from the
# detach onwards this mount's submissions were admitted with no lease consulted
# at all — by a node that had stopped proving liveness to anybody.  A tail that
# stalls past the lease boundary is therefore a node writing its own "I left
# cleanly" record while its peer is entitled to fence it and replay its slice.
#
# WHY IT NEEDS INJECTION.  The tail is normally one to four seconds and the
# lease is thirty, so no workload reaches the ordering.  dbg_unmount_tail_delay_ms
# parks put_super immediately after the detach and the heartbeat join, which is
# the one place where authority can only run down.
#
# THE THREE ARMS, and each one is a different question:
#
#   clean  no park.  The tail runs inside a live lease and must be ADMITTED —
#          and admitted BY THE LEASE, which is what tail_admit>0 says.  This is
#          the positive control: without it, a zero refusal count in the other
#          arms would only mean the instrument never fired, and a fix that
#          broke every clean unmount would pass.
#
#   blind  park + dbg_auth_tail_blind=1.  The gate's PRE-FIX answer is restored
#          for exactly the case the fix changed, so the before and the after
#          are measured on ONE build with nothing else different.  This arm
#          PASSES when it reproduces the defect: the tail is admitted without
#          the lease being consulted (tail_blind>0, zero refusals) and the node
#          writes its unmount record on the far side of its own deadline.
#
#   gated  park, no blind.  The same ordering, the fix in force.  The tail must
#          be REFUSED (P290-AUTH-REFUSED-LOG, tail_refuse>0), the departure is
#          dirty and that is the correct outcome, and the unmount must still
#          COMPLETE — a refused write that becomes a hung task would trade one
#          release blocker for another.
#
# In every arm: no_authority must read 0, neither node may log a BUG or an
# Oops, and the peer must still be serving at the end.
#
# THE BUDGET (derived, a timeout is a failure):
#   prep 300 (measured 48-69) + pre-workload 30 (a native small-file batch is
#   under a second) + the dirty-metadata stage 30 (400 creates and 200 unlinks
#   is well under a second natively) + the park itself TAIL_MS + the tail's own
#   work 90 (a healthy tail measures 1-4 s; a refused one shuts the log down
#   sooner) + captures and peer liveness 180.  With TAIL_MS=45000 that is
#   675 s.  Caller bound 780 s.
#
# Usage: tests/auth_lease_unmount_tail.sh <label>
# Env:   ARM (clean|blind|gated, default gated), TAIL_MS (45000),
#        MXFS_NODE_LIST (test1,test2), MXFS_TRANSPORT (tcp)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}          # the node whose teardown tail is measured
ARM=${ARM:-gated}
TAIL_MS=${TAIL_MS:-45000}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_authtail_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
# The mark names the LAP, not the label: the three arms are normally run back
# to back under one label, the kernel ring buffer survives the module reload
# that prep does between them, and a window opened at a mark the previous arm
# also wrote counts that arm's lines as this one's.  Measured: the gated arm
# read park=2, park_end=2, three late-dirty injections and a blind_line the
# BLIND arm had produced.  The nonce makes each window its own.
MARK="AUTHTAIL-MARK-$LABEL-$ARM-$(date -u +%H%M%S)"
echo "=== auth_lease_unmount_tail label=$LABEL arm=$ARM A=$A B(tail measured)=$B tail_ms=$TAIL_MS $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# Multi-field lines are the norm here, so the match must not be anchored at ^:
# an anchored reader returns "" for every field after the first.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

case "$ARM" in clean|blind|gated) ;; *) echo "ABORT: unknown ARM=$ARM"; exit 2;; esac

for sym in P291-AUTH-TAIL P290-AUTH-CLOSED; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done
for knob in dbg_unmount_tail_delay_ms dbg_auth_tail_blind; do
    modinfo mxfs.ko 2>/dev/null | grep -q "parm: *$knob" || {
        echo "ABORT: mxfs.ko has no $knob parameter; this arm cannot reach its ordering"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done

for n in "$A" "$B"; do
    st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
    [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
done
w=0
for n in "$A" "$B"; do
    until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
        w=$((w+1)); sleep 5
    done
done
echo "STAGE boot-wait polls=$w at +$(el)s"

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    rs 20 "$n" "cat /sys/module/mxfs/srcversion" > "$OUT/${n}_srcversion.txt"
done
echo "STAGE build on the fleet: $A=$(cat "$OUT/${A}_srcversion.txt") $B=$(cat "$OUT/${B}_srcversion.txt")"

# ---- 1. give the tail something to do, and prove B is healthy first
measure "$B" 60 "$OUT/B_pre.txt" '^PRE_END$' "B mounted and writable before its teardown" \
    "echo $MARK > /dev/kmsg; d=$MNT/authtail_$LABEL; mkdir -p \$d && for i in \$(seq 1 64); do printf 'pre-%s\n' \$i > \$d/f\$i; done && sync -f $MNT && echo PRE_OK n=\$(ls \$d | wc -l); echo PRE_END"
ck "B accepts work while its lease is live" "$(cnt "$OUT/B_pre.txt" '^PRE_OK')" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=pre evidence=$OUT"; exit 2; }
rs 20 "$A" "echo $MARK > /dev/kmsg" >/dev/null

# ---- 2. arm the ordering
ARMLINE=""
if [ "$ARM" != clean ]; then
    ARMLINE="echo $TAIL_MS > $PARM/dbg_unmount_tail_delay_ms;"
fi
if [ "$ARM" = blind ]; then
    ARMLINE="$ARMLINE echo 1 > $PARM/dbg_auth_tail_blind;"
fi
# META=1 ARMS THE ONE PRODUCER THAT CAN REACH THE METADATA ARM AFTER THE
# DETACH, and it is not an invention of this harness — dbg_sb_late_dirty is the
# sess475 late-dirty invariant arm, already in the tree, and what it does is
# exactly what is needed here.
#
# Why nothing else reaches it.  put_super's final SB summary sync takes the
# cluster SB lock and runs xfs_log_quiesce under it (pal/linux/xfs_super.c:1851),
# and that quiesce pushes the AIL to empty.  Only then does it seal the mount
# and detach the DLM.  So however dirty the filesystem was at umount, the AIL
# that xfs_unmount_flush_inodes pushes AFTER the detach — the push this record
# is about — is already empty, and the zero the first lap read is a property of
# the producer rather than of the gate.
#
# dbg_sb_late_dirty logs the root inode core AFTER that seal and after the
# quiesce (xfs_super.c:1885-1905).  The inode item is therefore still in the
# AIL at the detach, nothing before the detach can push it, and
# xfs_ail_push_all_sync submits its cluster buffer with m_mxfs_dlm already
# NULL — a metadata write in exactly the state the gate was changed for.
# One-shot, and the departure is meant to go DIRTY when it fires.
if [ "${META:-0}" = 1 ]; then
    ARMLINE="$ARMLINE echo 1 > $PARM/dbg_sb_late_dirty;"
fi
# EXTRA_ARM: further knobs to set on B in the SAME command, for asking a
# different question about the same ordering.  Each arm check below still
# applies unchanged; this only adds.
if [ -n "${EXTRA_ARM:-}" ]; then
    ARMLINE="$ARMLINE $EXTRA_ARM"
fi
measure "$B" 30 "$OUT/B_arm.txt" '^ARMED ' "the arming of $ARM on $B" \
    "$ARMLINE echo ARMED park=\$(cat $PARM/dbg_unmount_tail_delay_ms) blind=\$(cat $PARM/dbg_auth_tail_blind)"
APARK=$(field "$OUT/B_arm.txt" park); ABLIND=$(field "$OUT/B_arm.txt" blind)
echo "STAGE armed park=$APARK blind=$ABLIND extra='${EXTRA_ARM:-}' at +$(el)s"
case "$ARM" in
  clean) [ "$APARK" = 0 ] && [ "$ABLIND" = 0 ] || { echo "  the clean arm must carry no injection"; echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; } ;;
  blind) [ "$APARK" = "$TAIL_MS" ] && [ "$ABLIND" = 1 ] || { echo "  the blind arm did not arm"; echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; } ;;
  gated) [ "$APARK" = "$TAIL_MS" ] && [ "$ABLIND" = 0 ] || { echo "  the gated arm did not arm, or the blind knob is still set from a previous lap"; echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; } ;;
esac

# ---- 3. THE MEASUREMENT.  The umount blocks for the whole park; its own bound
#         is the assertion that a refused tail does not become a hung task.
UBOUND=$(( TAIL_MS / 1000 + 90 ))
# DIRTY METADATA AT THE DETACH, and it runs in the SAME command as the umount
# so nothing pushes the AIL in between.  The pre-workload above ends in
# `sync -f`, which is what the healthy-before check needs and is also why the
# first metadata-arm lap had nothing to admit or refuse: a clean AIL gives the
# teardown no metadata to submit, and a zero then says only that the producer
# was empty.  Creates and unlinks with no sync leave inode clusters, the AGI,
# the AGF and the free-space btrees dirty; `unlink` rather than `rm` so no
# glob or variable ever reaches an rm.  DIRTY_N is reported, not asserted —
# what it buys is that a zero further down is about the gate.
DIRTY_N=${DIRTY_N:-400}
measure "$B" $(( UBOUND + 90 )) "$OUT/B_umount.txt" '^UMOUNT rc=' "the unmount whose tail outlives its lease on $B" \
    "d=$MNT/authtail_dirty_$LABEL; mkdir -p \$d; for i in \$(seq 1 $DIRTY_N); do printf 'dirty-%s\n' \$i > \$d/g\$i; done; for i in \$(seq 1 $(( DIRTY_N / 2 ))); do unlink \$d/g\$i; done; echo DIRTY_OK left=\$(ls \$d | wc -l); s=\$(date +%s); timeout $UBOUND umount $MNT; rc=\$?; echo UMOUNT rc=\$rc secs=\$(( \$(date +%s) - s )) still=\$(grep -c ' $MNT ' /proc/mounts)"
echo "STAGE dirty staged at the detach: $(grep -a '^DIRTY_OK' "$OUT/B_umount.txt" | head -1)"
ck "the dirty-metadata stage ran (a clean AIL would make the gate count vacuous)" "$(cnt "$OUT/B_umount.txt" '^DIRTY_OK')" 1
URC=$(field "$OUT/B_umount.txt" rc); USEC=$(field "$OUT/B_umount.txt" secs)
echo "STAGE umount rc=$URC secs=$USEC still_mounted=$(field "$OUT/B_umount.txt" still) at +$(el)s"
ck "the unmount COMPLETED rather than hanging" "$([ -n "$URC" ] && [ "$URC" != 124 ] && echo completed || echo hung)" completed
ck "the mount is gone from /proc/mounts" "$(field "$OUT/B_umount.txt" still)" 0

# ---- 4. what the tail actually did, read off B's own journal
measure "$B" 90 "$OUT/B_journal.txt" '^JOURNAL_END$' "B's journal from the mark" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-700; echo JOURNAL_END"
TAILLINE=$(grep -a 'P291-AUTH-TAIL ' "$OUT/B_journal.txt" | tail -1)
echo "    ${TAILLINE#*mxfs: }" | cut -c1-230
printf '%s\n' "$TAILLINE" > "$OUT/B_tail_counters.txt"
TADM=$(field "$OUT/B_tail_counters.txt" tail_admit)
TREF=$(field "$OUT/B_tail_counters.txt" tail_refuse)
TNOA=$(field "$OUT/B_tail_counters.txt" no_authority)
TBLD=$(field "$OUT/B_tail_counters.txt" tail_blind)
PARKED=$(cnt "$OUT/B_journal.txt" 'P291-AUTH-TAIL-PARK ms=')
PARKEND=$(cnt "$OUT/B_journal.txt" 'P291-AUTH-TAIL-PARK-END')
REFLOG=$(cnt "$OUT/B_journal.txt" 'P290-AUTH-REFUSED-LOG')
REFANY=$(cnt "$OUT/B_journal.txt" 'P290-AUTH-REFUSED')
CLOSED=$(cnt "$OUT/B_journal.txt" 'P290-AUTH-CLOSED')
BLINDLN=$(cnt "$OUT/B_journal.txt" 'P291-AUTH-TAIL-BLIND')
# The metadata arm is decided somewhere else and so is counted separately.
# tail_admit/tail_refuse are submissions that reached the mount's authority
# object; meta_detached counts metadata writes that reached THEIR gate while
# this mount's DLM was already detached, where that gate asks the detached
# pointer.  Reported, not asserted: a zero can mean the arm was never reached
# in this ordering, which is a different statement from the arm being sound,
# and REFMETA is what tells the two apart.
grep -a 'P291-AUTH-META ' "$OUT/B_journal.txt" | tail -1 > "$OUT/B_meta_counters.txt"
TMETA=$(field "$OUT/B_meta_counters.txt" meta_detached)
METALN=$(cnt "$OUT/B_journal.txt" 'P291-AUTH-META-DETACHED')
REFMETA=$(cnt "$OUT/B_journal.txt" 'P290-AUTH-REFUSED-META')
echo "STAGE tail_admit=$TADM tail_refuse=$TREF no_authority=$TNOA tail_blind=$TBLD | park=$PARKED park_end=$PARKEND closed=$CLOSED refused_log=$REFLOG refused_any=$REFANY blind_lines=$BLINDLN"
echo "STAGE meta_detached=${TMETA:-<no line>} meta_lines=$METALN refused_meta=$REFMETA — metadata writes that reached the metadata authority arm with the DLM detached, vs ones that arm refused"
grep -a 'P290-AUTH-CLOSED\|P290-AUTH-REFUSED-LOG\|P291-AUTH-TAIL-BLIND' "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-180 | head -4

ck "B printed the teardown-tail accounting at all" "$([ -n "$TAILLINE" ] && echo yes || echo no)" yes
ck "no clustered submission reached the gate without an authority object" "${TNOA:-x}" 0

if [ "${META:-0}" = 1 ]; then
    # The producer must have fired, or every metadata number below is vacuous
    # and says nothing about the arm.  Assert the injection landed BEFORE
    # asserting on what it produced.
    ck "the late-dirty producer fired (without it no metadata reaches the arm post-detach)" \
       "$(cnt "$OUT/B_journal.txt" 'P-DBG-SB-LATE-DIRTY slot=')" 1
    # Counted from THIS lap's own kernel-log mark.  meta_detached is a
    # module-wide total since load and would still read non-zero from a
    # previous lap on the same load; the line count cannot.
    ckge "a metadata write reached the authority arm with the DLM already detached" "$METALN" 1
fi

if [ "$ARM" != clean ]; then
    ck "the tail was parked past the lease" "$PARKED" 1
    ck "the park ended rather than the unmount dying inside it" "$PARKEND" 1
fi

case "$ARM" in
clean)
    # The tail ran inside a live lease.  It must have been admitted, and
    # admitted BY THE LEASE — a zero here is the instrument not firing.
    ckge "the teardown tail was admitted by the lease (positive control)" "${TADM:-0}" 1
    ck "nothing in a live-lease tail was refused" "${TREF:-x}" 0
    ck "no authority refusal of any kind on a healthy unmount" "$REFANY" 0
    ck "the pre-fix gate was not in force" "${TBLD:-x}" 0
    [ "${META:-0}" = 1 ] && ck "the post-detach metadata write was NOT refused inside a live lease" "$REFMETA" 0
    ;;
blind)
    # The defect, reproduced on this build: the tail went to the LUN with the
    # lease never consulted, on the far side of the node's own deadline.
    ckge "the pre-fix gate admitted the tail without consulting the lease" "${TBLD:-0}" 1
    ck "with the lease never consulted, nothing was refused" "$REFLOG" 0
    ck "the unmount reported success, having written its record unauthorised" "$URC" 0
    # This is the defect itself, on the metadata site: a metadata write issued
    # past this node's own deadline, admitted because the DLM reference was
    # gone rather than because anything still held authority.
    [ "${META:-0}" = 1 ] && ck "the pre-fix gate refused no metadata write either" "$REFMETA" 0
    ;;
gated)
    # The fix in force on the same ordering: the tail is refused, the log is
    # left dirty for recovery, and the unmount still finishes.
    # WHICH submission the refusal lands on depends on what the tail has to
    # write.  With META=1 the late-dirty inode item is pushed by xfsaild inside
    # xfs_unmount_flush_inodes, which runs BEFORE xfs_log_unmount, so the
    # metadata arm refuses first and the log cover is never attempted:
    # measured refused_meta=2, tail_refuse=2, P290-AUTH-REFUSED-LOG=0.  That is
    # the metadata arm doing its job, not the log arm failing to, so the log
    # assertion is made on the lap that actually asks it.  REFLOG is printed in
    # both cases either way.
    if [ "${META:-0}" = 1 ]; then
        ckge "a submission in the tail was REFUSED by the lease" "${TREF:-0}" 1
        echo "    (META arm: refused_log=$REFLOG refused_meta=$REFMETA — the metadata push precedes the log cover)"
    else
        ckge "the log write in the tail was REFUSED by the lease" "$REFLOG" 1
    fi
    ckge "the refusal is counted as a tail refusal" "${TREF:-0}" 1
    ck "the pre-fix gate was not in force" "${TBLD:-x}" 0
    ckge "the lease closed, and the submission is what found out" "$CLOSED" 1
    # The whole point of the metadata arm: the same write the blind arm sent
    # to the LUN is REFUSED here, by the mount's authority object rather than
    # by a pointer that teardown happens to have cleared.
    [ "${META:-0}" = 1 ] && ckge "the post-detach METADATA write was refused by the lease" "$REFMETA" 1
    ;;
esac

ck "B: zero BUG / Oops" "$(cnt "$OUT/B_journal.txt" 'BUG:\|Oops')" 0

# ---- 5. the peer is the other half of every arm
measure "$A" 60 "$OUT/A_live.txt" '^A_END$' "the peer is still serving" \
    "d=$MNT/authtail_peer_$LABEL; mkdir -p \$d && printf 'peer\n' > \$d/p && sync -f $MNT && echo A_OK; echo A_MOUNTED=\$(grep -c ' $MNT ' /proc/mounts); echo A_END"
ck "the peer still accepts work" "$(cnt "$OUT/A_live.txt" '^A_OK$')" 1
ck "the peer is still mounted" "$(field "$OUT/A_live.txt" A_MOUNTED)" 1
measure "$A" 60 "$OUT/A_journal.txt" '^JOURNAL_END$' "the peer's journal from the mark" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-700; echo JOURNAL_END"
ck "peer: zero BUG / Oops" "$(cnt "$OUT/A_journal.txt" 'BUG:\|Oops')" 0

# ---- 6. never leave an injection armed for the next lap
rs 20 "$B" "echo 0 > $PARM/dbg_auth_tail_blind 2>/dev/null; echo 0 > $PARM/dbg_unmount_tail_delay_ms 2>/dev/null; true" >/dev/null 2>&1

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
