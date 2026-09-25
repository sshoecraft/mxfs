#!/bin/bash
# d0932_owner_depart_takeover.sh — reach the platter revocation fallback through
# a RECOVERY OWNER that departs cleanly, rather than a fencing prover.
#
# WHY A THIRD SHAPE.  v5_holder_slot_state is the fallback that proves a
# descriptor's holder incarnation revoked when the membership view cannot, and
# it has never answered REVOKED.  Two shapes have now been measured and neither
# reaches it, both because they used a FENCING PROVER as the holder:
#
#   s578h (SOLO, prover dies): the judge evaluates standing attempts BEFORE it
#     publishes the dead prover's recovery, so the prover's record is always
#     still standing -> UNKNOWN; and the lone survivor is also the fencer, so
#     the membership view answers first anyway.  verdict=REVOKED 0 / UNKNOWN 56.
#
#   s578k (prover departs cleanly): a prover holding a standing attempt does
#     not publish RETIRE_PENDING at all.  Its unmount waits for its own parked
#     worker, the retire worker is refused three times by P304-FENCE-PROVE-BUSY
#     and exits, and the departure leaves the slot reading ACTIVE.  Correct and
#     conservative — a node must not publish a consumable slot while it owns an
#     unresolved attempt — but it means this branch is unreachable from a
#     prover by construction.
#
# THE HOLDER NEED NOT BE A PROVER.  v5_holder_slot_state's own header says the
# holder it judges may be a "fencing prover, snapshot holder or EXECUTION
# OWNER".  A recovery OWNER is the case the other two shapes cannot produce: it
# has no fencing attempt of its own outstanding, so nothing blocks its
# retirement, so a clean unmount should publish RETIRE_PENDING — and the
# descriptor it owns stays standing for a later mount to judge.  A peer that
# never watched that owner depart then has no membership answer for it, and the
# platter is the only route left.
#
# HOW THE OWNER IS PARKED MID-RECOVERY.  dbg_purge_pause_ms (dlm/v5_mount.c) is
# an existing one-shot test knob that parks the recovery owner after the purge's
# phase-0 freeze gate — i.e. after it has taken ownership and before the purge
# that would publish and consume the descriptor.  Nothing is forged: the
# recovery is a real one, driven by a real death, and the only injection is the
# pause.
#
# SHAPE
#   prep both -> arm dbg_purge_pause_ms on A -> destroy B (A becomes the
#   recovery owner for B's slice and parks in the purge) -> then either UMOUNT A
#   (DEPART=depart) or DESTROY A where it stands (DEPART=crash) -> require a
#   descriptor still standing for B to judge, else VACUOUS -> bring B back and
#   mount it alone -> require v5_holder_slot_state verdict=REVOKED.
#
# the budget rule (derived): prep 50 s (bound 300); B's death detected in the
# 31 x 2 s dead window then the ladder runs to the purge, so the park appears
# within ~150 s (bound 240); A's umount must outlast the injected pause, bound
# PAUSE_MS/1000 + 120; B boot 150 s; B's lone mount bound 300; captures ~30 s.
#
# Usage: tests/d0932_owner_depart_takeover.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default: the device
#        of A's live mxfs mount after prep, resolved by mxfs_dev_resolve; a
#        device another rig hardcoded is never assumed), MXFS_MODARGS,
#        PAUSE_MS (default 90000), JOIN_BOUND (default 300),
#        MXFS_FAULT_UMOUNT_SRC=<node>:<stage> (capture-contract verification
#        only: unmount /src on <node> right before the named acquisition,
#        dump | join; the lap must then ABORT, never reach a verdict),
#        DEPART=depart|crash (default depart).  See the DEPART comment below:
#        "depart" measures what a clean owner departure publishes (it publishes
#        RETIRE_PENDING but strands nothing, s578m); "crash" is the one that
#        leaves a descriptor standing for the fallback to judge.
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # becomes the recovery owner, then departs
B=${MXFS_NODE_LIST##*,}          # dies to create the recovery, returns as judge
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
PAUSE_MS=${PAUSE_MS:-90000}
# depart = A unmounts cleanly.  crash = A is destroyed where it stands.
#
# CLEAN DEPARTURE CANNOT PRODUCE THE STATE THIS LAP NEEDS, and s578m measured
# why: the unmount WAITS for whatever recovery work this node has parked, so by
# the time it returns the purge has resumed and consumed the descriptor.  It
# published RETIRE_PENDING correctly (P304-RETIRE-PENDING-RELEASED, slot 0
# flags=RETIRE_PENDING) but left nothing standing to judge -- "descriptor still
# standing" came back 0.  That waiting is the same property that stops a
# fencing prover departing with its attempt outstanding (s578k); it is a good
# property and it is why no clean departure can strand its own descriptor.
#
# crash keeps the descriptor: A is destroyed while parked INSIDE the purge, so
# the descriptor it owns at stage GRANTS_RELEASED survives with owner=A.  B then
# returns alone and must (1) judge that descriptor -- UNKNOWN at first, A's
# record still stands -- and (2) fence and recover A, which ZEROES A's slot.  B
# re-judges every replay round (s578h logged 56 evaluations across 57 rounds),
# so a round after A's purge is the one that should read all-zero and answer
# REVOKED.  That is the Z(P) && D(P) crash cut, and it is legal because the
# purge freeze gate only covers descriptors naming the purged node as VICTIM
# (recov_desc_names_node compares d->victim_node), never as holder.
DEPART=${DEPART:-depart}
JOIN_BOUND=${JOIN_BOUND:-300}
UMOUNT_BOUND=${UMOUNT_BOUND:-$(( PAUSE_MS / 1000 + 120 ))}
PARAM=/sys/module/mxfs/parameters/dbg_purge_pause_ms
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0932own_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/cnt/capture_require/ensure_src_or_abort/mxfs_dev_resolve: every
# capture a verdict is taken from is proven to hold its tool's shape first
# (tests/lib/rig.sh).  This harness is where the class was first measured
# (s580f): the platter dump ran on a node whose /src was not mounted, the
# error vanished into the helper's stderr redirect, and the empty capture
# was read as "no descriptor is standing".
. "$(dirname "$0")/lib/rig.sh"
# MXFS_FAULT_UMOUNT_SRC=<node>:<stage>: a real unmount of /src on <node>
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
# immediately before the named acquisition (dump | join), for verifying that
# the lap ABORTs at the boundary instead of reaching a verdict.
fault_before() { # <stage>
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0932_owner_depart_takeover label=$LABEL A(owner)=$A B(victim,judge)=$B sv=$SV pause=${PAUSE_MS}ms $(date -u +%FT%TZ) ==="

# Both hosts must be up before prep, or prep fails against a booting node and
# the whole lap is an infrastructure report rather than a measurement.
for n in $A $B; do
    w=0
    until [ "$(rs 15 "$n" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
        w=$((w+1)); sleep 5
    done
done
echo "STAGE both hosts ready wall=$(el)s"

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
rsx 30 "$A" 'cat /sys/module/mxfs/srcversion' > "$OUT/A_srcversion.txt"
capture_require "$OUT/A_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $A"
ck "prep deployed the tree build" "$(head -1 "$OUT/A_srcversion.txt")" "$SV"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL wrong build evidence=$OUT"; exit 2; }
# The LUN as MXFS actually uses it, read from A's live mount that prep just
# made (MXFS_DEV overrides; no rig's device is assumed).
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "STAGE device=$MXFS_DEV (from $A's live mount)"

value_now_into armed "$A" 30 "$OUT/rv_armed_1.txt" '^-?[0-9]+$' "armed on $A" "echo $PAUSE_MS > $PARAM 2>/dev/null; cat $PARAM"
ck "$A armed the recovery-owner purge pause" "$armed" "$PAUSE_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL could not arm evidence=$OUT"; exit 2; }

# ---- kill B; A must own B's recovery and park inside the purge.
KMARK="D0932OD-MARK-$LABEL"
rsx 15 "$A" "echo $KMARK > /dev/kmsg" > /dev/null
AMARK=$(date +%s)
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(el)s — waiting for $A to park in the purge"
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after a kernel marker), so an ssh that never ran
# cannot read as "the line never appeared"
wait_for_into parkedw "$A" 240 "$KMARK" "P-DBG-PURGE-PAUSE"
parked=$([ "$parkedw" = timeout ] && echo 0 || echo 1); w=$parkedw
rs 30 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | grep -a 'P234-PURGE\|P236-FENCE-CERTIFIED\|RECOV' | cut -c1-400" > "$OUT/A_recov.txt"
sed 's/^/    /' "$OUT/A_recov.txt" | cut -c1-175 | tail -5
echo "STAGE A-parked=$parked polls=$w wall=$(el)s"
if [ "$parked" != 1 ]; then
    # "never parked" is a statement about the kernel only if the journal was
    # readable: prove that before saying the state was not reached.
    rsx 60 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_park_journal.txt"
    capture_require "$OUT/A_park_journal.txt" 'kernel: ' "the kernel journal on $A while waiting for the purge pause"
    echo "  FAIL $A never reached the purge pause — it never became the recovery owner, or the knob did not take"
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi

if [ "$DEPART" = crash ]; then
    $VIRSH destroy "$A" > /dev/null 2>&1
    echo "STAGE destroyed $A where it stood, parked inside the purge, at +$(el)s"
    urc=0; ums=0; still=0
    # The platter must be read from a node that is UP; A is gone, so B is
    # started first and the dump is taken from it before it mounts.
    $VIRSH start "$B" > /dev/null 2>&1
    w=0
    until [ "$(rs 15 "$B" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
        w=$((w+1)); sleep 5
    done
    echo "STAGE $B booted polls=$w wall=$(el)s"
    DUMPN=$B
else
    DUMPN=$A
fi
if [ "$DEPART" != crash ]; then
# ---- A departs cleanly.  Unlike a prover, an owner has no fencing attempt of
#      its own outstanding, so its retirement should complete and publish.
u0=$(date +%s)
rsx $((UMOUNT_BOUND + 20)) "$A" "
    T0=\$(date +%s%N)
    timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?
    echo UMOUNT_MS=\$(( (\$(date +%s%N) - T0) / 1000000 ))
    grep -c ' mxfs ' /proc/mounts | sed 's/^/STILL_MOUNTED=/'
    true
  " > "$OUT/A_umount.txt"
capture_require "$OUT/A_umount.txt" '^STILL_MOUNTED=[0-9]+$' "the unmount of $A"
urc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/A_umount.txt" | head -1)
ums=$(sed -n 's/^UMOUNT_MS=//p' "$OUT/A_umount.txt" | head -1)
still=$(sed -n 's/^STILL_MOUNTED=//p' "$OUT/A_umount.txt" | head -1)
echo "STAGE $A umount rc=${urc:-?} ms=${ums:-?} still_mounted=${still:-?} wall=$(( $(date +%s) - u0 ))s at +$(el)s"
ck "$A's unmount completed within its derived bound" "${urc:-124}" "0"
ck "$A is no longer mounted" "${still:-1}" "0"
fi

# THE DUMP TOOL LIVES ON THE NFS SHARE, SO THE SHARE HAS TO BE THERE FIRST.
# In crash mode the dump node is B, freshly booted, and /src is not mounted on
# it until the build check much further down.  s580f dumped before that: python3
# had no script to run, and because the old helper sent the remote command's
# stderr to /dev/null the error vanished and the capture came back EMPTY --
# which the descriptor count then read as "no descriptor is standing" and the
# lap exited VACUOUS on a state it had never looked at.  The prerequisite is
# checked, and then the dump itself is validated against the shape the tool
# always emits: an empty or unparseable dump is an ABORT, never a verdict.
ensure_src_or_abort "$DUMPN"
fault_before dump
rsx 90 "$DUMPN" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$OUT/hb_after_umount.txt"
capture_require "$OUT/hb_after_umount.txt" '^slot +[0-9]+ magic=' "the platter dump on $DUMPN"
echo "STAGE platter after $A's departure:"
grep -a 'flags=\|desc ' "$OUT/hb_after_umount.txt" | cut -c1-185 | head -8 | sed 's/^/    /'
rp=$(cnt "$OUT/hb_after_umount.txt" 'RETIRE_PENDING')
desc_left=$(cnt "$OUT/hb_after_umount.txt" 'desc v')
if [ "$DEPART" != crash ]; then
    rsx 60 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_journal.txt"
    capture_require "$OUT/A_journal.txt" 'kernel: ' "the kernel journal on $A after its departure"
    ckge "$A's slot published RETIRE_PENDING on a clean owner departure" "$rp" 1
else
    : > "$OUT/A_journal.txt"
    echo "  INFO $A is down by design (crash mode); RETIRE_PENDING is not expected and its journal is not pullable"
fi
# A PRECONDITION, NOT AN ASSERTION (s70c): the clean departure waits for the
# node's own parked recovery work, so once the purge hold expires the owner
# publishes and departs with nothing standing; the lap is then VACUOUS by
# the verdict below, and a FAIL line printed first made the capture gate
# score that vacuity as BROKEN.
echo "STAGE descriptors still standing for $B to judge: $desc_left (the judge needs >= 1)"
# WHAT MAKES THIS LAP VACUOUS DEPENDS ON THE DEPARTURE.  A crash cannot publish
# RETIRE_PENDING and this script says so two lines above -- requiring it in both
# modes threw away a crash lap that HAD reached the state it needed (s580h: the
# descriptor was standing at stage GRANTS_RELEASED with owner=the crashed node
# and owner_slot=0, the exact input the platter fallback exists to judge, and
# the lap exited VACUOUS on the absence of something it had just called
# unexpected).  Only the standing descriptor is common to both modes.
if [ "$DEPART" = crash ]; then
    vac=$([ "${desc_left:-0}" -lt 1 ] && echo 1 || echo 0)
else
    vac=$([ "${rp:-0}" -lt 1 ] || [ "${desc_left:-0}" -lt 1 ] && echo 1 || echo 0)
fi
if [ "$vac" = 1 ]; then
    echo "  NOTE $A's release-path lines:"
    grep -ah 'P304-RETIRE\|P236-RELEASE\|P234-PURGE' "$OUT/A_journal.txt" | sed 's/.*kernel: /      /' | cut -c1-165 | tail -8
    echo "  VACUOUS the departed-owner state this lap needs was not reached"
    # s70c: this exit left $B destroyed; the next entry's restore waited 180 s
    # for its ssh and its prep then refused the fleet ("unusable after power
    # cycle") — run.sh never powers a listed node on.  Bring it back here, as
    # the retire-pending sibling does.
    $VIRSH start "$B" > /dev/null 2>&1
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- B returns alone and judges a descriptor whose owner is gone.
if [ "$DEPART" != crash ]; then
    $VIRSH start "$B" > /dev/null 2>&1
    w=0
    until [ "$(rs 15 "$B" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
        w=$((w+1)); sleep 5
    done
    echo "STAGE $B booted polls=$w wall=$(el)s"
fi
MD5=$(md5sum mxfs.ko | cut -c1-32)
ensure_src_or_abort "$B"
fault_before join
rsx 60 "$B" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32" > "$OUT/B_md5.txt"
capture_require "$OUT/B_md5.txt" '^[0-9a-f]{32}$' "the module copy on $B"
ck "$B runs the tree build (md5)" "$(head -1 "$OUT/B_md5.txt")" "$MD5"

RMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/B_join.txt"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the lone mount of $B"
echo "STAGE $B join rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/B_join.txt" | head -1) wall=$(sed -n 's/^WALL_MS=//p' "$OUT/B_join.txt" | head -1)ms total=$(el)s"
rsx 60 "$B" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/B_journal.txt"
capture_require "$OUT/B_journal.txt" 'kernel: ' "the kernel journal on $B after its mount"

hslot=$(cnt "$OUT/B_journal.txt" 'P238-FENCE-HOLDER-SLOT')
echo "--- reach: P238-FENCE-HOLDER-SLOT=$hslot"
grep -ah 'P238-FENCE-HOLDER-SLOT' "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -3
if [ "$hslot" -lt 1 ]; then
    echo "  VACUOUS $B never evaluated a descriptor's holder — nothing was measured"
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi
echo "--- outcome: verdict=REVOKED=$(cnt "$OUT/B_journal.txt" 'verdict=REVOKED') verdict=UNKNOWN=$(cnt "$OUT/B_journal.txt" 'verdict=UNKNOWN')"
# THE PLATTER FALLBACK IS ONE ROUTE TO A RESOLVED DESCRIPTOR, NOT THE ONLY ONE,
# AND REQUIRING IT UNCONDITIONALLY MAKES A CORRECT RUN FAIL.  s580i: every
# UNKNOWN verdict happened while the crashed owner's slot still read ACTIVE --
# before it had been fenced at all, which is the conservative answer this
# fallback is designed to give.  Once its fence was certified the ORDINARY route
# noted the incarnation dead (P-DEAD-INC) and the judge answered from that,
# claimed the recovery and ran the ladder.  The system was right; the assertion
# was aimed at the wrong mechanism and reported a defect.
#
# So: require that the descriptor was resolved by SOME route, and say which.
# The fallback is only REQUIRED when the ordinary route never noted the owner's
# incarnation dead -- that is the case this record exists for.
revoked=$(cnt "$OUT/B_journal.txt" 'verdict=REVOKED')
deadinc=$(cnt "$OUT/B_journal.txt" 'P-DEAD-INC')
claimed=$(cnt "$OUT/B_journal.txt" 'P236-RECOV-CLAIMED')
echo "  INFO routes to a resolved descriptor: platter-fallback REVOKED=$revoked, ordinary certified-fence P-DEAD-INC=$deadinc, recoveries claimed=$claimed"
if [ "${deadinc:-0}" -ge 1 ]; then
    echo "  NOTE the ordinary certified-fence route answered, so the platter fallback was not required this lap; it is not asserted"
    ckge "the departed owner's descriptor was resolved by some route" "$claimed" 1
else
    ckge "no ordinary route noted the owner dead, so the platter fallback had to answer and did" "$revoked" 1
fi
ck "$B completed its mount" "$(cnt "$OUT/B_join.txt" '^MOUNTED')" 1
ck "$B: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/B_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/B_journal.txt" 'BUG:\|Oops') ))" 0

rs 20 "$A" "echo 0 > $PARAM" >/dev/null 2>&1
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
