#!/bin/bash
# d0932_retire_pending_takeover.sh — reach the platter revocation fallback by
# the RETIRE_PENDING branch, and find out whether that branch is SAFE.
#
# TWO QUESTIONS, ONE SHAPE.
#
# (1) D-0932's owed arm.  v5_holder_slot_state is the platter fallback that
#     proves a descriptor's holder incarnation revoked when the membership view
#     cannot.  It has never answered REVOKED in any lap.  The SOLO arm of
#     tests/d0932_fence_takeover_probe.sh cannot reach it (measured s578h): the
#     judge evaluates standing attempts BEFORE it publishes the dead prover's
#     recovery, so the prover's record is always still standing, and the lone
#     survivor is also the fencer so the view answers first anyway.
#     This shape reaches the OTHER positive branch instead — the one that needs
#     no death at all.  A prover that releases its slot CLEANLY publishes its
#     own final image as RETIRE_PENDING, and v5_holder_slot_state reads that as
#     "the holder released its slot: its own final image stands under its
#     tuple" -> REVOKED.  A peer that never watched the departure has no view
#     answer, so the platter is the only route left.
#
# (2) Whether that reading is SAFE.  RETIRE_PENDING is published by the
#     release path at clean teardown, before the PR key that still authorises
#     this initiator has been retired.  The worry was that a node could complete
#     that release while one of ITS OWN fencing workers was still parked after a
#     durable intent, letting a peer read RETIRE_PENDING, judge the incarnation
#     revoked, and take the attempt over while the original prover could still
#     act under it.
#
#     MEASURED s578j, AND THE WORRY IS REFUTED FOR THIS PATH: the unmount does
#     not complete while the attempt is outstanding.  It blocked for the whole
#     90 s bound the first version of this harness gave it (rc=124, still
#     mounted), RETIRE_PENDING was never published, and the platter still showed
#     the prover's slot ACTIVE with the FENCING descriptor standing.  The
#     release serialises against the node's own attempt.  That first bound was
#     simply wrong — it was shorter than the injected hold it had to outlast —
#     so the bound is now DERIVED from the hold, and the safety property is
#     asserted directly instead: no consumable slot on the platter while the
#     attempt is outstanding.
#
#     s578j also showed the in-node guard doing its job: five
#     "P304-FENCE-PROVE-BUSY ... not issuing a second PREEMPT AND ABORT under
#     this attempt" refusals, and the resumed worker then proved nothing
#     (KEY_ABSENT_UNPROVEN, proves_excl=0).  The cross-node guard is the term:
#     a takeover raises it, so a stale prover acting under the OLD term is the
#     violation worth counting — which is what the safety check now counts.
#
# Nothing is forged: the intent is written by a real prover in the ordinary
# way, and the release is an ordinary umount.  The only injection is the
# existing test-only knob that parks the prover in the window where its intent
# is durable and nothing has been issued under it.
#
# SHAPE
#   prep both -> arm the post-intent hold on A -> destroy B (A detects the
#   death, writes the intent, parks) -> WAIT for P236-FENCE-INTENT-HOLD (no
#   hold = nothing was set up, everything after is vacuous) -> sample the
#   platter WHILE PARKED and require no consumable slot -> umount A and let it
#   take as long as the hold needs -> require RETIRE_PENDING published AND the
#   attempt still standing -> only THEN restart B and mount it alone, so B
#   judges a prover that departed CLEANLY rather than one that merely looked
#   dead while blocked.
#
# the budget rule (derived): prep 50 s (bound 300); B's death detected in the
# 31 x 2 s dead window plus the intent, so the hold appears within ~120 s
# (bound 180); A's umount must outlast the injected hold, bound HOLD_MS + 120 s;
# B boot 150 s; B's lone mount bound 300; captures ~30 s.
#
# Usage: tests/d0932_retire_pending_takeover.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default /dev/sda),
#        MXFS_MODARGS, HOLD_MS (default 60000), JOIN_BOUND (default 300),
#        UMOUNT_BOUND (default: derived, HOLD_MS/1000 + 120).
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # the prover that parks mid-attempt, then leaves
B=${MXFS_NODE_LIST##*,}          # the victim, and later the lone judge
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
HOLD_MS=${HOLD_MS:-60000}
JOIN_BOUND=${JOIN_BOUND:-300}
# Derived from the injected hold, because the unmount MUST outlast it: the
# release path serialises against this node's own outstanding fence attempt
# (measured s578j), so a bound shorter than the hold is guaranteed to trip and
# says nothing.  Hold + 120 s covers the worker's own finish plus the ordinary
# unmount work.
UMOUNT_BOUND=${UMOUNT_BOUND:-$(( HOLD_MS / 1000 + 120 ))}
PARAM=/sys/module/mxfs/parameters/dl_fence_postintent_pause_ms
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0932rp_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# ckge: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/cnt (tests/lib/rig.sh): every capture a
# verdict is counted from crosses the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0932_retire_pending_takeover label=$LABEL A(prover)=$A B(victim,judge)=$B sv=$SV hold=${HOLD_MS}ms $(date -u +%FT%TZ) ==="

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
value_now_into rv1 "$A" 30 "$OUT/rv_rv1_1.txt" '^[0-9A-F]+$' "rv1 on $A" 'cat /sys/module/mxfs/srcversion'
ck "prep deployed the tree build" "$rv1" "$SV"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL wrong build evidence=$OUT"; exit 2; }

value_now_into armed "$A" 30 "$OUT/rv_armed_2.txt" '^-?[0-9]+$' "armed on $A" "echo $HOLD_MS > $PARAM 2>/dev/null; cat $PARAM"
ck "$A armed the post-intent hold" "$armed" "$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL could not arm evidence=$OUT"; exit 2; }

# ---- kill B; A must detect the death, write a durable intent, and park.
KMARK="D0932RP-MARK-$LABEL"
rsx 15 "$A" "echo $KMARK > /dev/kmsg" > /dev/null
AMARK=$(date +%s)
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(el)s — waiting for $A to park on its intent"
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after a kernel marker), so an ssh that never ran
# cannot read as "the line never appeared"
wait_for_into heldw "$A" 180 "$KMARK" "P236-FENCE-INTENT-HOLD"
held=$([ "$heldw" = timeout ] && echo 0 || echo 1); w=$heldw
rs 30 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | grep -a 'P236-FENCE-INTENT' | cut -c1-400" > "$OUT/A_intent.txt"
sed 's/^/    /' "$OUT/A_intent.txt" | cut -c1-190 | head -3
echo "STAGE A-parked=$held polls=$w wall=$(el)s"
if [ "$held" != 1 ]; then
    echo "  FAIL $A never reached P236-FENCE-INTENT-HOLD — no attempt was left standing"
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- A LEAVES CLEANLY.  The release is expected to WAIT for its own parked
#      fence worker; what must never happen is a consumable slot published
#      while the attempt is still outstanding.
# SAFETY SAMPLE, taken while the worker is still parked: a clean departure must
# NOT publish a consumable slot while one of this node's fencing attempts is
# still outstanding.  If RETIRE_PENDING is already on the platter here, a peer
# could read it as revoked and take the attempt over with the original prover
# still able to act.
rs 60 "$A" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$OUT/hb_while_parked.txt" 2>&1
rp_early=$(cnt "$OUT/hb_while_parked.txt" 'RETIRE_PENDING')
ck "no consumable slot is published while $A's fence attempt is still outstanding" "$rp_early" "0"

u0=$(date +%s)
rs $((UMOUNT_BOUND + 20)) "$A" "
    T0=\$(date +%s%N)
    timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?
    echo UMOUNT_MS=\$(( (\$(date +%s%N) - T0) / 1000000 ))
    grep -c ' mxfs ' /proc/mounts | sed 's/^/STILL_MOUNTED=/'
  " > "$OUT/A_umount.txt" 2>&1
uwall=$(( $(date +%s) - u0 ))
urc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/A_umount.txt" | head -1)
ums=$(sed -n 's/^UMOUNT_MS=//p' "$OUT/A_umount.txt" | head -1)
still=$(sed -n 's/^STILL_MOUNTED=//p' "$OUT/A_umount.txt" | head -1)
echo "STAGE $A umount rc=${urc:-?} ms=${ums:-?} still_mounted=${still:-?} wall=${uwall}s at +$(el)s"
ck "$A's unmount completed within its derived bound (hold + 120 s)" "${urc:-124}" "0"
ck "$A is no longer mounted" "${still:-1}" "0"

# ---- what the departure published, read straight off the platter.
rs 60 "$A" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$OUT/hb_after_umount.txt" 2>&1
echo "STAGE platter after $A's departure:"
grep -a 'flags=\|RETIRE\|desc ' "$OUT/hb_after_umount.txt" | cut -c1-190 | head -8 | sed 's/^/    /'
rp=$(cnt "$OUT/hb_after_umount.txt" 'RETIRE_PENDING')
ckge "$A's slot published RETIRE_PENDING once its attempt was no longer outstanding" "$rp" 1
fencing_left=$(cnt "$OUT/hb_after_umount.txt" 'stage=FENCING')
# A PRECONDITION, NOT AN ASSERTION (s53b, s70c): the release serialises
# against the node's own attempt (measured s578j, and the safety check above
# is the property that matters), so once the hold expires the prover finishes
# its fence and the departure publishes with nothing standing.  The lap is
# then VACUOUS by this harness's own verdict below; printing a FAIL line
# first made the capture gate score the vacuity as BROKEN.
echo "STAGE fencing attempts still standing after $A's departure: $fencing_left (the judge needs >= 1)"
if [ "${rp:-0}" -lt 1 ] || [ "${fencing_left:-0}" -lt 1 ]; then
    # CAPTURE BEFORE EXITING.  The first version bailed here without pulling
    # A's journal, and the journal was the only place that said WHY the slot
    # was still ACTIVE -- it had to be fetched by hand afterwards, off a node
    # that could have been rebooted by the next lap.  A vacuous exit is a
    # result about the system, not a reason to keep less evidence than a FAIL.
    rs 60 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_journal.txt"
    echo "  NOTE why the departure did not publish a consumable slot:"
    grep -ah 'P304-RETIRE\|P236-RELEASE\|P304-FENCE-RETRY\|P304-FENCE-PROVE-BUSY\|P236-FENCE-INTENT-RESUME' "$OUT/A_journal.txt" \
      | sed 's/.*kernel: /      /' | cut -c1-165 | tail -8
    echo "  VACUOUS the departed-prover state this lap needs was not reached; $B would judge an ordinary death instead"
    # sess53: this exit used to leave $B destroyed, and the next harness's
    # prep_cluster then aborted ("unusable after power cycle: test2") because
    # run.sh treats MXFS_NODE_LIST nodes as external and never powers them on.
    $VIRSH start "$B" > /dev/null 2>&1
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- B comes back ALONE and judges the standing attempt.  It never watched A
#      depart, so it has no membership answer for A's incarnation and the
#      platter is the only route to a verdict.
$VIRSH start "$B" > /dev/null 2>&1
w=0
until [ "$(rs 15 "$B" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
    w=$((w+1)); sleep 5
done
echo "STAGE $B booted polls=$w wall=$(el)s"
MD5=$(md5sum mxfs.ko | cut -c1-32)
value_now_into got "$B" 150 "$OUT/rv_got_3.txt" '^[0-9a-f]{32}$' "got on $B" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
ck "$B runs the tree build (md5)" "$got" "$MD5"

RMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/B_join.txt"
# the join list always ends in its mount state (a refused mount is a verdict);
# its absence is a failed acquisition
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $B"
echo "STAGE $B join rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/B_join.txt" | head -1) wall=$(sed -n 's/^WALL_MS=//p' "$OUT/B_join.txt" | head -1)ms total=$(el)s"
measure "$B" 60 "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B since the join mark" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
measure "$A" 60 "$OUT/A_journal.txt" '^JOURNAL_END$' "the kernel journal on $A since the arm mark" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"

# ---- 1. VACUITY before any outcome: did B evaluate the holder at all?
hslot=$(cnt "$OUT/B_journal.txt" 'P238-FENCE-HOLDER-SLOT')
echo "--- reach: P238-FENCE-HOLDER-SLOT=$hslot"
grep -ah 'P238-FENCE-HOLDER-SLOT' "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -3
if [ "$hslot" -lt 1 ]; then
    echo "  VACUOUS $B never evaluated a standing attempt's holder — this lap measured NOTHING"
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 2. D-0932: the platter fallback must itself have answered.
echo "--- outcome: verdict=REVOKED=$(cnt "$OUT/B_journal.txt" 'verdict=REVOKED') verdict=UNKNOWN=$(cnt "$OUT/B_journal.txt" 'verdict=UNKNOWN')"
ckge "v5_holder_slot_state proved the departed prover REVOKED from the platter" \
     "$(cnt "$OUT/B_journal.txt" 'verdict=REVOKED')" 1

# ---- 3. THE SAFETY QUESTION.  A's worker was parked with a durable intent when
#         its slot was published consumable.  If B took the attempt over AND A's
#         worker then resumed under it, two actors acted under one attempt.
tk=$(cnt "$OUT/B_journal.txt" 'P238-FENCE-TAKEOVER ')
res=$(cnt "$OUT/A_journal.txt" 'P236-FENCE-INTENT-RESUME')
# WAKING IS NOT ACTING.  The first version of this check scored
# "a takeover happened AND the parked worker resumed" as two actors under one
# attempt, and reported exactly that on s578j — where it was false twice over:
# RETIRE_PENDING was never published (so the takeover rested on a certified
# PREEMPT_ABORT_DONE, not on this branch at all), and the resumed worker issued
# NOTHING — it was refused five times by "P304-FENCE-PROVE-BUSY ... not issuing
# a second PREEMPT AND ABORT under this attempt" and then proved nothing
# (KEY_ABSENT_UNPROVEN, proves_excl=0).  A co-occurrence of two probes is not a
# race.  What would make it one is a second actor that actually PROVED
# exclusion under the SAME attempt term after the attempt was taken over, so
# that is what is counted: the takeover raises the term, and any later
# proves_excl=1 by the old prover under the OLD term is the violation.
oldterm=$(grep -aho 'P238-FENCE-TAKEOVER .*term=[0-9]*' "$OUT/B_journal.txt" | grep -ao 'term=[0-9]*' | tail -1 | cut -d= -f2)
aproved=$(grep -ac "P236-FENCEKIND .*proves_excl=1 .*term=${oldterm:-1}\]" "$OUT/A_journal.txt")
echo "--- safety: B takeovers=$tk (old term=${oldterm:-?}) ; A's worker woke=$res ; A proved exclusion under the old term=$aproved"
grep -ah 'P236-FENCE-INTENT-RESUME\|P304-FENCE-PROVE-BUSY\|P236-FENCEKIND' "$OUT/A_journal.txt" | sed 's/.*: /    /' | cut -c1-175 | tail -4
if [ "$tk" -ge 1 ] && [ "${aproved:-0}" -ge 1 ]; then
    echo "  FAIL TWO ACTORS UNDER ONE ATTEMPT: $B took the attempt over at term=$oldterm and $A still proved exclusion under that same term afterwards"
    fails=$((fails+1))
else
    echo "  PASS no second actor proved exclusion under the taken-over term (takeovers=$tk woke=$res proved_old_term=${aproved:-0})"
fi

# ---- 4. the judge must survive.
ck "$B completed its mount" "$(cnt "$OUT/B_join.txt" '^MOUNTED')" 1
ck "$B: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/B_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/B_journal.txt" 'BUG:\|Oops') ))" 0

rs 20 "$A" "echo 0 > $PARAM" >/dev/null 2>&1
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
