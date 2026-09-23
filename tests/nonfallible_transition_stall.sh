#!/bin/bash
# tests/nonfallible_transition_stall.sh — does a page transition that will
# never advance end, for a caller the fallible oracle does not name?
#
# THE SUBJECT (ledger record: a stalled page transition is an unbounded wait
# for a non-fallible caller).  mxfs_dlm_lock_retries detects that the takeover
# a request is waiting on has stopped advancing — the progress counter has not
# moved for MXFS_DLM_TRANSITION_STALL_MS — and then asks ctx->acq_fallible_cb
# whether THIS caller may be failed.  For a caller it does not name the loop
# logs P960-AUTH-TRANSITION-STALLED fallible=0, resets the stall clock
# (dlm/dlm.c:8035) and waits again, and the retry budget is not spent either
# (dlm.c:8054 undoes the loop's own decrement).  So a transition that is
# refused FOREVER is a kernel wait with no exit but a fatal signal.
#
# The refusal used here is the one the code says is permanent by design.  A
# ledger page whose authority departed is taken over by dlm_takeover_page, and
# v5_recovery_judging_cb (dlm/v5_mount.c:2488) answers "still judging" — so the
# takeover is refused — for as long as a RECOVERY_GUARD naming that authority
# stands below IMAGES_REPLAYED, "at any owner, lease state or age".  The
# progress counter is published in exactly one place, on dlm_takeover_page's
# single success return, so every refusal is a RETRY_TRANSITION with a frozen
# counter.  0.89.44 closed one exit from that predicate (a terminal QUARANTINED
# verdict is now a completed judgement); the abandoned/parked descriptor is the
# same wait and is what this lap drives.
#
# THE NON-FALLIBLE CALLER is put_super's SB summary lock
# (mxfs_sb_summary_lock, xfs/xfs_mxfs_dlm.c:5009, called from
# mxfs_sb_summary_final_sync, pal/linux/xfs_super.c:1818).  It acquires an
# INODE-class resource on a geometry-reserved cluster-wide key and the calling
# task registers nothing in the XFS layer's per-task fallible registry, so
# v5_acq_fallible_cb answers 0 for it permanently.  It is also the caller the
# 0.89.43 measurement already witnessed parked on this path.
#
# THE VICTIM IS THE NODE THAT DOES NOT MASTER THE PAGE, AND IT IS FROZEN AND
# THAWED.  The summary key is ONE key for the whole cluster, so the ledger page
# carrying it has ONE authority: whoever last took the lock.  A freeze/thaw on
# a node runs xfs_log_quiesce -> mxfs_sb_summary_cover (xfs/xfs_log.c:2375),
# which takes that lock and logs 'P-SB-SUMMARY-LOCK ... master_self=<0|1>
# at=quiesce'.  That is what makes the node the page's authority, and it is
# REQUIRED evidence: without it the survivor's put_super would take over a page
# its own node already owns, no judgement would be consulted, and a clean
# unmount would be scored as a bounded wait.  A lap that cannot produce that
# line is VACUOUS and says so before anything is destroyed.
#
# The same line says which node MASTERS the page (0.89.66, master_self), and
# that decides the roles.  Mastership is page-aligned over the sorted active
# view (dlm_page_master_locked, dlm/dlm.c:1579), so which of the two nodes
# masters the summary page is decided by the node ids drawn at mount; and a
# dead member keeps its pages until its recovery completes, which this lap
# parks.  So the master must be the node that STAYS UP: the first freeze/thaw
# is run on the first node in the list and its line is read; if it masters the
# page the other node is the victim (and is frozen/thawed in turn so IT is the
# authority), otherwise it is the victim itself.  The prover is always the
# master, and it is alive throughout.
#
# WHY THE INJECTOR IS THE MANIFEST SNAPSHOT AND NOT THE COMPLETION LADDER.
# Two knobs park a descriptor below IMAGES_REPLAYED.  recov_complete_inject=1
# fails the IMAGES_REPLAYED advance until a 120 s deadline, and then WITHDRAWS
# the mount — and a withdrawn mount is shut down, so
# mxfs_sb_summary_final_sync takes its P-SB-SUMMARY-FINAL-SKIP branch
# (pal/linux/xfs_super.c:1789) and never acquires the lock at all.  That lap
# would measure nothing.  rman_inject=1 fails the prover's manifest snapshot
# before the manifest write: the attempt parks at SNAPSHOTTING, the guard
# stands, and the prover's mount stays HEALTHY — which is the only shape in
# which the non-fallible caller is reachable.
#
# WHY THE ROLES ARE READ AND NOT GUESSED, AND WHY THE TWO EARLIER SCHEDULES
# MEASURED NOTHING.  Lap s130c killed the first node and read
# transition-wait=0: its window holds exactly one line for the probe,
# 'P-SB-SUMMARY-LOCK slot=1 rc=-107 epoch=0 at=put_super', and -107 is
# -ENOTCONN — the acquire did not wait and did not transition, it was refused
# by the transport, because the dead victim was still the page's MASTER (a
# dead member stays in the view until its recovery completes, and the
# recovery is parked).  A request whose master is a dead-but-in-view node
# takes the remote path (dlm.c:6593) and fails fast: -EHOSTDOWN when the
# master's recovery reads as blocked, otherwise the send's own -ENOTCONN.
# Lap s133d then tried to bring the victim BACK as a new incarnation so the
# master would be alive again, and its remount was REFUSED at the claim
# ('P236-CLAIM-UNCERTIFIED ... the fence-time manifest is not sealed yet') —
# the very guard this lap parks is what refuses the returning node, so that
# route closes itself.
#
# What the wait needs is the two producers of MXFS_DLM_RETRY_TRANSITION, and
# both need a LIVE master:
#
#   (a) the master is someone else and answers MXFS_ERR_AUTH_TRANSITION
#       (P960-AUTH-TRANSITION-TX, dlm.c:10350) because its own
#       dlm_ledger_prepare parked with -EINPROGRESS;
#   (b) the master is this node, and dlm_page_acquire parks with
#       -EINPROGRESS itself — either its on-demand takeover of the dead
#       authority was refused (dlm.c:2779-2787) or the bootstrap node it
#       asked has not answered (dlm.c:2869).
#
# On a two-node cluster with one node dead, (a) has no live "someone else",
# so the reachable producer is (b): the prover must be the page's master and
# the page's durable authority must be the DEAD incarnation the standing
# RECOVERY_GUARD names below IMAGES_REPLAYED, which v5_recovery_judging_cb
# protects "at any owner, lease state or age".  Both are arranged from the
# master_self line: the master is the prover, the other node is made the
# authority and destroyed, and nothing is remounted.  A put_super that comes
# back -ENOTCONN or -EHOSTDOWN is still reported as the vacuity it is, naming
# the rc, because it means the roles were not what the line said.
#
# THE KILL BOUND IS THE INSTRUMENT, NOT A BUDGET.  Every other bound in this
# harness is a performance assertion and reaching one is a failure.  UMOUNT_MAX
# is different in kind: the thing being measured is a wait with no exit, so the
# lap must end it itself.  Reaching it is the DEFECT, recorded as such, and it
# is derived from the property being asserted rather than from patience — the
# stall detector fires at 30 s, the record requires the stall to be seen at
# least twice with the caller still parked, so 2 x 30 s plus the time to enter
# the acquire and one detector period of margin.
#
# VERDICT
#   PASS     the unmount finished (or failed cleanly) AND the transition path
#            was genuinely entered — the wait is bounded on this route.
#   FAIL     the unmount was still parked at UMOUNT_MAX with
#            P960-AUTH-TRANSITION-WAIT in the window: an unbounded wait at a
#            caller the fallible oracle does not name.
#   VACUOUS  no node's quiesce took the page, the master could not be read,
#            the guard did not stand below IMAGES_REPLAYED, or the unmount
#            never reached the transition path (including a put_super refused
#            -ENOTCONN/-EHOSTDOWN, which is the transport answering for a
#            master that is not there).  None of those measure the subject,
#            and none of them is a pass.
#
# THE BUDGET (derived; native XFS does none of this, so every term is MXFS's
# own measured infrastructure): boot wait <=200 s + prep <=300 s (measured
# 72-137 s) + identities 30 s + workload 30 s + up to two freeze/thaws 60 s +
# arm 15 s + the 62 s dead window + fence and snapshot attempt ~40 s + platter
# dump 40 s + UMOUNT_MAX 90 s + stack and window captures 60 s + cleanup 40 s
# = 937 s.  Caller bound 1000 s.  REMOUNT=1 adds a second platter dump 40 s +
# MOUNT_MAX 140 s + its stack samples and window 60 s + the fresh
# incarnation's unmount UMOUNT_MAX 90 s + its probe and window 60 s = 1327 s:
# caller bound 1350 s.
#
# REMOUNT=1 (0.89.69, after s133d, s146f).  On two nodes the unmount above
# cannot meet the wait: the prover masters the page it needs (s146f, rc=0 in
# 1 s), and the victim's pages are mastered by the victim, which stays in the
# view until its recovery completes and therefore answers nothing (s130c,
# -ENOTCONN).  The shape that reaches producer (b) is a FRESH MOUNT by the
# prover with the guard still standing: the new incarnation's view holds only
# itself, so it masters every page, and every page the victim mastered still
# names the victim's dead incarnation as its authority, which the judgement
# refuses to take over.  The mount task is a caller the fallible registry does
# not name.  So with REMOUNT=1 the unmount is the setup (it must return 0) and
# the mount is the measurement, under MOUNT_MAX as the instrument bound; the
# verdict reads the remount window and the mount task's sampled stacks, and a
# mount still parked at the bound with a transition wait in its window is the
# FAIL this record predicts.  A mount refused at the recovery barrier or the
# claim before any transition is VACUOUS and names the gate.
#
# Usage: tests/nonfallible_transition_stall.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2 — the roles are chosen from the
#        master_self line: the node that masters the summary page is the
#        prover, which stays up throughout and whose unmount is measured; the
#        other node is made the page's authority and destroyed), UMOUNT_MAX
#        (90), NFILES (32), REMOUNT (0; 1 = the fresh-mount arm above),
#        MOUNT_MAX (140).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
N1=${MXFS_NODE_LIST%%,*}
N2=${MXFS_NODE_LIST##*,}
V=                               # the victim: made the page's authority, destroyed (chosen in step 3)
P=                               # the prover: masters the page; its unmount is the subject
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
UMOUNT_MAX=${UMOUNT_MAX:-90}
MOUNT_MAX=${MOUNT_MAX:-140}      # REMOUNT=1 only; derived in step 8b
PARM=/sys/module/mxfs/parameters
DUMP=/src/mxfs/tools/disklock_hb_dump.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_nftstall_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="NFT-MARK-$LABEL"
echo "=== nonfallible_transition_stall label=$LABEL nodes=$N1,$N2 (roles read from the master line) umount_max=${UMOUNT_MAX}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
vac() { echo "  VACUOUS $1"; echo "RESULT: VACUOUS label=$LABEL reason=$2 evidence=$OUT wall=$(el)s"; exit 3; }

# The injector and the victim's domain are the only two things this lap changes
# outside the filesystem, and both are undone on every path out, including an
# abort: a lap that dies half way must not leave the next one arming a knob it
# did not set or waiting for a domain nobody started.
CLEANED=0
PWEDGED=0              # set when the prover's unmount had to be SIGKILLed
cleanup() {
    [ "$CLEANED" = 1 ] && return 0
    CLEANED=1
    [ -n "$P" ] || { echo "STAGE cleanup: the roles were never chosen; nothing was armed or destroyed"; return 0; }
    if [ "$PWEDGED" = 1 ]; then
        # A SIGKILLed umount leaves the mount half torn down with a DLM
        # acquire still parked underneath it; the next prep would fight that
        # rather than prepare a node.  Recycle the domain instead — it carries
        # no evidence (every capture is already on this host) and the caller's
        # prep then starts from a clean boot.
        $VIRSH destroy "$P" >/dev/null 2>&1
        sleep 3
        $VIRSH start "$P" >/dev/null 2>&1
        echo "STAGE cleanup: $P was recycled because its unmount had to be killed"
    else
        rs 20 "$P" "echo 0 > $PARM/rman_inject 2>/dev/null; cat $PARM/rman_inject" > "$OUT/P_inject_clear.txt" 2>/dev/null
    fi
    $VIRSH start "$V" >/dev/null 2>&1
    echo "STAGE cleanup: rman_inject on $P now '$(tail -1 "$OUT/P_inject_clear.txt" 2>/dev/null || echo 'cleared by the recycle')', $V started; the caller must prep_cluster before the next lap at +$(el)s"
}
trap cleanup EXIT

# ---- 0. the fleet on the tree build
if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
waitboot "$N1" "$N2"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$N1" "$N2"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$N1"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. identities
for n in "$N1" "$N2"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "SLOT1=\$slot_$N1; SLOT2=\$slot_$N2"
[ -n "$SLOT1" ] && [ -n "$SLOT2" ] && [ "$SLOT1" != "$SLOT2" ] || {
    echo "ABORT: could not read two distinct slots ($N1 '$SLOT1', $N2 '$SLOT2')"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }
echo "STAGE identities: $N1 slot $SLOT1, $N2 slot $SLOT2 at +$(el)s"

# ---- 2. both mounts do real work, so the prover's departure has something to
#         quiesce and the victim's slice is genuinely dirty when it dies.
for n in "$N1" "$N2"; do
    rs 120 "$n" "mkdir -p $MNT/nft_$n && for i in \$(seq 1 $NFILES); do dd if=/dev/urandom of=$MNT/nft_$n/f\$i bs=4096 count=8 status=none; done; sync -f $MNT/nft_$n; echo WORK_OK" > "$OUT/${n}_work.txt" 2>/dev/null &
done; wait
for n in "$N1" "$N2"; do
    grep -qa '^WORK_OK' "$OUT/${n}_work.txt" || {
        echo "ABORT: the workload on $n did not complete: [$(tr '\n' ' ' < "$OUT/${n}_work.txt" | cut -c1-200)]"
        echo "RESULT: ABORT label=$LABEL stage=workload evidence=$OUT"; exit 2; }
done
echo "STAGE workload: $NFILES files fsynced from each node at +$(el)s"

# ---- 3. choose the roles from the page's master, and make the VICTIM the
#         authority of the SB summary page.  The freeze's quiesce takes the
#         cluster-wide summary lock; the thaw puts the mount back.  Both rcs
#         are recorded, and the kernel's own lock line with rc=0 is what proves
#         the page moved — not the fsfreeze exit status, which is 0 for a
#         freeze whose clustered cover then failed.  The same line carries
#         master_self, and that is what chooses the victim.
# freeze_thaw <node> <slot> <tag>: run it, require the thaw, window the ring
# into $OUT/<tag>_quiesce.txt, and set qlock (rc=0 lock lines) and qmaster
# (the master_self value on the last such line, or 'none').
freeze_thaw() {
    local n=$1 slot=$2 tag=$3 thaw
    rs 120 "$n" "fsfreeze -f $MNT; echo FREEZE_RC=\$?; fsfreeze -u $MNT; echo THAW_RC=\$?" > "$OUT/${tag}_freeze.txt" 2>/dev/null
    echo "STAGE freeze/thaw on $n: $(tr '\n' ' ' < "$OUT/${tag}_freeze.txt" | cut -c1-160) at +$(el)s"
    # A filesystem left FROZEN would block every later I/O on it and the
    # unmount under measurement would park on the freeze rather than on the
    # transition — a FAIL this harness would have caused itself.
    thaw=$(grep -ao 'THAW_RC=[0-9]*' "$OUT/${tag}_freeze.txt" | head -1 | cut -d= -f2)
    [ "${thaw:-none}" = 0 ] || {
        echo "ABORT: the thaw on $n did not succeed (THAW_RC='${thaw:-none}'); the filesystem may still be frozen and nothing after this would measure the subject"
        echo "RESULT: ABORT label=$LABEL stage=thaw evidence=$OUT"; exit 2; }
    window_into "$OUT/${tag}_quiesce.txt" "$n" 40 "claimed heartbeat slot"
    count_file_into qlock "$OUT/${tag}_quiesce.txt" "P-SB-SUMMARY-LOCK slot=$slot rc=0 .*at=quiesce"
    qmaster=$(grep -a "P-SB-SUMMARY-LOCK slot=$slot rc=0 .*at=quiesce" "$OUT/${tag}_quiesce.txt" | tail -1 | sed -n 's/.*master_self=\(-\?[0-9]*\).*/\1/p')
    qmaster=${qmaster:-none}
}
freeze_thaw "$N1" "$SLOT1" N1
if [ "$qlock" -lt 1 ]; then
    echo "  $N1's quiesce did not take the summary lock cleanly: [$(grep -a 'P-SB-SUMMARY-LOCK' "$OUT/N1_quiesce.txt" | tail -2 | tr '\n' ' ' | cut -c1-240)]"
    vac "$N1's quiesce never took the SB summary page, so neither the master nor an authority move can be read" no-authority-move
fi
case $qmaster in
    1)  P=$N1; V=$N2; PSLOT=$SLOT1; VSLOT=$SLOT2
        echo "STAGE $N1 masters the summary page (master_self=1) and is the prover; $N2 is the victim at +$(el)s"
        # the victim must be the AUTHORITY: its own quiesce moves the page
        freeze_thaw "$N2" "$SLOT2" N2
        if [ "$qlock" -lt 1 ]; then
            echo "  the victim's quiesce did not take the summary lock cleanly: [$(grep -a 'P-SB-SUMMARY-LOCK' "$OUT/N2_quiesce.txt" | tail -2 | tr '\n' ' ' | cut -c1-240)]"
            vac "$V never became the SB summary page's authority, so the prover's put_super would take over a page it already owns and no judgement would be consulted" no-authority-move
        fi
        ck "the victim's own quiesce read the page as mastered elsewhere (master_self=0)" "$qmaster" 0
        ;;
    0)  V=$N1; P=$N2; VSLOT=$SLOT1; PSLOT=$SLOT2
        echo "STAGE $N1 does not master the summary page (master_self=0): it is the victim and already its authority; $N2 is the prover at +$(el)s"
        ;;
    *)  echo "ABORT: the summary lock line on $N1 carries no readable master_self (got '$qmaster'): [$(grep -a 'P-SB-SUMMARY-LOCK' "$OUT/N1_quiesce.txt" | tail -1 | cut -c1-200)] — the roles cannot be chosen on this build"
        echo "RESULT: ABORT label=$LABEL stage=master evidence=$OUT"; exit 2 ;;
esac
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=roles evidence=$OUT"; exit 2; }
# REMOUNT=1 inverts the roles.  The ledger page's authority is the node that
# MASTERS it (the master owns the page it decides on; a remote requester's
# quiesce moves nothing — s146f read the prover's own page at put_super), so
# for a fresh incarnation's put_super to meet a page the dead incarnation
# authored, the victim must be the node that mastered the summary page in
# the two-member view.  Mastership is not needed alive here: the fresh
# incarnation's view holds only itself and it masters every page.
if [ "${REMOUNT:-0}" = 1 ]; then
    t=$P; P=$V; V=$t; t=$PSLOT; PSLOT=$VSLOT; VSLOT=$t
    echo "STAGE REMOUNT arm: roles inverted — the summary page's master $V is the victim (its incarnation stays the page's authority), $P is the prover that will mount again"
fi
echo "STAGE roles: victim/authority $V (slot $VSLOT), prover/master $P (slot $PSLOT) at +$(el)s"

umount_measure() {   # <tag> — sets URC; the probe and rc files carry the tag
    local tag=$1
    rs $((UMOUNT_MAX + 40)) "$P" "rm -f /run/nft_umount.txt
setsid sh -c 'timeout -s KILL $UMOUNT_MAX umount $MNT; echo UMOUNT_RC=\$?' > /run/nft_umount.txt 2>&1 < /dev/null &
sleep 12
for i in 1 2 3; do
    pid=\$(ps -o pid= -C umount 2>/dev/null | head -1 | tr -d ' ')
    [ -n \"\$pid\" ] && break
    sleep 3
done
echo UMOUNT_PID=\${pid:-none}
[ -n \"\$pid\" ] && { echo STACK_BEGIN; cat /proc/\$pid/stack 2>/dev/null; echo STACK_END; }
echo PROBE_END" > "$OUT/${tag}_umount_probe.txt" 2>/dev/null
    echo "STAGE unmount probe on $P ($tag): $(grep -a 'UMOUNT_PID' "$OUT/${tag}_umount_probe.txt" | head -1) at +$(el)s"
    if grep -qa '^STACK_BEGIN' "$OUT/${tag}_umount_probe.txt"; then
        echo "  parked-task stack while the unmount was still running:"
        sed -n '/^STACK_BEGIN/,/^STACK_END/p' "$OUT/${tag}_umount_probe.txt" | grep -a 'mxfs\|dlm\|xfs\|umount\|schedule' | head -12 | sed 's/^/    /'
    fi
    # the unmount either returned inside its bound or was killed at it
    rs $((UMOUNT_MAX + 60)) "$P" "for i in \$(seq 1 $((UMOUNT_MAX + 30))); do grep -q UMOUNT_RC= /run/nft_umount.txt 2>/dev/null && break; sleep 1; done; cat /run/nft_umount.txt; echo READ_END" > "$OUT/${tag}_umount_rc.txt" 2>/dev/null
    capture_require "$OUT/${tag}_umount_rc.txt" '^READ_END$' "the unmount result on $P ($tag)"
    URC=$(grep -ao 'UMOUNT_RC=[0-9]*' "$OUT/${tag}_umount_rc.txt" | head -1 | cut -d= -f2)
    # set here, not in the verdict: a lap that exits VACUOUS below still left a
    # killed unmount behind, and the cleanup has to know that whatever the verdict
    [ "${URC:-none}" = 137 ] && PWEDGED=1
    echo "STAGE unmount on $P ($tag) returned rc='${URC:-none}' at +$(el)s  [$(grep -av '^READ_END$' "$OUT/${tag}_umount_rc.txt" | tr '\n' ' ' | cut -c1-160)]"
}

# ---- R. REMOUNT=1: the whole measurement, in the order that reaches the
#         wait on two nodes.  The prover unmounts CLEANLY while the victim is
#         alive (its summary lock goes to the live master, so the departure
#         is clean and a same-boot remount is not refused as dirty); the
#         injector is armed on the prover's still-loaded module; the victim
#         is destroyed; the prover mounts again as a fresh incarnation — a
#         sole member that masters every page, discovers the dead slot after
#         its own dead window, fences it, fails the injected snapshot and
#         parks the guard at SNAPSHOTTING; and every page the victim
#         mastered in the two-member view still names the victim's dead
#         incarnation as its authority, which the judgement refuses to take
#         over.  The mount task is unregistered in the fallible registry
#         except for its root inode lookup; the fresh incarnation's put_super
#         summary lock (the second unmount) is on the page the victim
#         authored.  MOUNT_MAX (200 s) is the instrument bound: mount 10 +
#         the fresh monitor's dead window 62 + fence and the injected
#         snapshot 30 + the stall detector twice 60 + one period of margin.
if [ "${REMOUNT:-0}" = 1 ]; then
    MOUNT_MAX=${MOUNT_MAX_REMOUNT:-200}
    for n in "$V" "$P"; do rs 15 "$n" "echo $MARK > /dev/kmsg" >/dev/null 2>&1; done
    umount_measure P
    if [ "${URC:-none}" != 0 ]; then
        vac "the prover's clean unmount (victim alive) returned rc=${URC:-none}; there is no clean departure to mount again after" remount-setup-umount-failed
    fi
    value_now_into inj "$P" 20 "$OUT/P_inject_set.txt" '^1$' "the rman_inject knob after arming on the unmounted $P" "echo 1 > $PARM/rman_inject; cat $PARM/rman_inject"
    echo "STAGE $P departed cleanly (rc=0) and rman_inject=$inj is armed on its loaded module at +$(el)s"
    $VIRSH destroy "$V" >/dev/null 2>&1 || {
        echo "ABORT: virsh destroy $V failed"
        echo "RESULT: ABORT label=$LABEL stage=destroy evidence=$OUT"; exit 2; }
    echo "STAGE destroyed $V at +$(el)s"
    rs 15 "$P" "echo $MARK-REMOUNT > /dev/kmsg" >/dev/null 2>&1
    echo "STAGE mounting $P again as a fresh incarnation with the victim dead and unrecovered (bound ${MOUNT_MAX}s) at +$(el)s"
    rs $((MOUNT_MAX + 40)) "$P" "rm -f /run/nft_mount.txt
setsid sh -c 'timeout -s KILL $MOUNT_MAX mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?' > /run/nft_mount.txt 2>&1 < /dev/null &
prev=0
for t in 45 100 150; do
    sleep \$(( t - prev )); prev=\$t
    grep -q MOUNT_RC= /run/nft_mount.txt 2>/dev/null && { echo SAMPLE t=\$t mount-returned; continue; }
    pid=\$(ps -o pid= -C mount 2>/dev/null | head -1 | tr -d ' ')
    echo SAMPLE t=\$t MOUNT_PID=\${pid:-none} state=\$(awk '{print \$3}' /proc/\${pid:-0}/stat 2>/dev/null) wchan=\$(cat /proc/\${pid:-0}/wchan 2>/dev/null)
    [ -n \"\$pid\" ] && { echo STACK_BEGIN t=\$t; cat /proc/\$pid/stack 2>/dev/null; echo STACK_END; }
    echo P960_SO_FAR t=\$t n=\$(dmesg | sed -n '/$MARK-REMOUNT/,\$p' | grep -ac 'P960-AUTH-TRANSITION') inject=\$(dmesg | sed -n '/$MARK-REMOUNT/,\$p' | grep -ac 'P-RMAN-INJECT')
done
echo PROBE_END" > "$OUT/P_mount_probe.txt" 2>/dev/null
    grep -a '^SAMPLE\|^P960_SO_FAR' "$OUT/P_mount_probe.txt" | cut -c1-200 | sed 's/^/  /'
    for t in 45 100 150; do
        st=$(sed -n "/^STACK_BEGIN t=$t/,/^STACK_END/p" "$OUT/P_mount_probe.txt" | grep -a 'mxfs\|dlm\|xfs\|mount\|schedule' | sed 's/^\[<[0-9a-fx]*>\] //' | head -10 | tr '\n' ' ' | cut -c1-360)
        [ -n "$st" ] && echo "  mount task stack at ${t}s: $st"
    done
    rs $((MOUNT_MAX + 60)) "$P" "for i in \$(seq 1 $((MOUNT_MAX + 30))); do grep -q MOUNT_RC= /run/nft_mount.txt 2>/dev/null && break; sleep 1; done; cat /run/nft_mount.txt; echo READ_END" > "$OUT/P_mount_rc.txt" 2>/dev/null
    capture_require "$OUT/P_mount_rc.txt" '^READ_END$' "the mount result on $P"
    MRC=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/P_mount_rc.txt" | head -1 | cut -d= -f2)
    [ "${MRC:-none}" = 137 ] && PWEDGED=1
    echo "STAGE mount on $P returned rc='${MRC:-none}' at +$(el)s  [$(grep -av '^READ_END$' "$OUT/P_mount_rc.txt" | tr '\n' ' ' | cut -c1-160)]"
    window_into "$OUT/P_window.txt" "$P" 60 "$MARK-REMOUNT"
    count_file_into twait  "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-WAIT'
    count_file_into tstall "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-STALLED'
    count_file_into tstf0  "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-STALLED.* fallible=0 '
    count_file_into tstf1  "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-STALLED.* fallible=1 '
    count_file_into judg   "$OUT/P_window.txt" 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT'
    count_file_into served "$OUT/P_window.txt" 'P960-ONDEMAND-SERVED'
    count_file_into parked "$OUT/P_window.txt" 'P-TAUTH-PAGE-PARKED\|P960-PARK-NOT-TRANSITION'
    count_file_into injn   "$OUT/P_window.txt" 'P-RMAN-INJECT'
    count_file_into refused "$OUT/P_window.txt" 'P236-CLAIM\|P-BARRIER\|MOUNT-REFUSED\|recovery barrier'
    count_file_into oops   "$OUT/P_window.txt" 'BUG:\|Oops\|kernel NULL pointer'
    echo "STAGE remount window on $P: transition-wait=$twait stalled=$tstall stalled(fallible=0)=$tstf0 stalled(fallible=1)=$tstf1 under-judgement=$judg ondemand-served=$served parked=$parked injected-snapshot-failures=$injn barrier/claim=$refused oops=$oops"
    grep -a 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT\|P960-AUTH-TRANSITION\|P236-\|P-RMAN-\|P238-\|P-TAUTH-PAGE-PARKED\|P960-PARK\|P163-' "$OUT/P_window.txt" | tail -10 | cut -c1-230 | sed 's/^/    /'
    ck "no BUG/Oops on the prover across the remount" "$oops" 0
    if [ "${MRC:-none}" = 137 ]; then
        if [ "$twait" -ge 1 ]; then
            echo "  FAIL the mount was STILL PARKED at the ${MOUNT_MAX}s instrument bound and only a SIGKILL ended it, with $twait transition wait(s) and $tstf0 stall(s) that named the caller non-fallible$( [ "$judg" -ge 1 ] && echo "; the refusal underneath it was the departed authority's open judgement ($judg x P-TAUTH-TAKEOVER-UNDER-JUDGEMENT)" || echo "; the refusal underneath it was NOT the judging one — read the window") — a node cannot mount after a peer's death while that peer's recovery stands parked, and the wait has no exit"
        else
            echo "  FAIL the mount was STILL PARKED at ${MOUNT_MAX}s with NO transition wait in its window — parked somewhere this lap did not predict; the sampled stacks above say where"
        fi
        fails=$((fails+1))
    elif [ -z "${MRC:-}" ]; then
        echo "ABORT: the mount produced no rc at all; nothing was measured"
        echo "RESULT: ABORT label=$LABEL stage=mount evidence=$OUT"; exit 2
    elif [ "$twait" -lt 1 ]; then
        echo "  INFO the fresh mount returned rc=$MRC without entering a transition wait ($refused barrier/claim line(s), $parked parked line(s), $served served on demand, $injn injected snapshot failure(s)) — the second unmount below is where the summary page is"
    else
        echo "  PASS the mount ended by itself (rc=$MRC) after entering the transition path $twait time(s), $tstall stall(s) observed; the wait is bounded on this route"
    fi
    U2RC=none; U2SBRC=none; u2wait=0; u2stall=0; u2fsb=0; u2skip=0; u2judg=0
    if [ "${MRC:-none}" = 0 ]; then
        # the guard must stand before the second unmount is worth anything:
        # the fresh monitor declares the victim dead 62 s after the mount and
        # the injected snapshot fails right after the fence
        wait_for_into wsnap "$P" 140 "$MARK-REMOUNT" "P-RMAN-INJECT slot=$VSLOT "
        if [ "$wsnap" = timeout ]; then
            vac "the fresh incarnation never failed the injected snapshot for slot $VSLOT within 140 s of its mount, so no guard was parked below IMAGES_REPLAYED for the second unmount to meet" remount-no-snapshot-attempt
        fi
        echo "STAGE the fresh incarnation failed the injected manifest snapshot for slot $VSLOT ${wsnap}s after its mount (+$(el)s)"
        measure "$P" 60 "$OUT/hb_guard.txt" '^slot +[0-9]+ magic=' "the disklock table after the parked snapshot" "python3 $DUMP $MXFS_DEV"
        gline=$(grep -aE "^slot +$VSLOT " "$OUT/hb_guard.txt" | head -1)
        dline=$(awk -v s="$VSLOT" '$1=="slot" && $2==s {f=1; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$OUT/hb_guard.txt")
        echo "  platter slot $VSLOT: $(echo "$gline" | cut -c1-140)"
        echo "  platter desc     : $(echo "$dline" | cut -c1-200)"
        case $gline in *RECOVERY_GUARD*) ;; *) vac "the victim's slot is not RECOVERY_GUARD after the parked snapshot, so v5_recovery_judging_cb has nothing to protect" no-guard ;; esac
        rs 15 "$P" "echo $MARK-UMOUNT2 > /dev/kmsg" >/dev/null 2>&1
        echo "STAGE unmounting the fresh incarnation of $P against the standing guard (bound ${UMOUNT_MAX}s) at +$(el)s"
        umount_measure P2
        U2RC=${URC:-none}
        window_into "$OUT/P2_window.txt" "$P" 60 "$MARK-UMOUNT2"
        count_file_into u2wait  "$OUT/P2_window.txt" 'P960-AUTH-TRANSITION-WAIT'
        count_file_into u2stall "$OUT/P2_window.txt" 'P960-AUTH-TRANSITION-STALLED'
        count_file_into u2fsb   "$OUT/P2_window.txt" 'P960-AUTH-TRANSITION-FAIL-SB'
        count_file_into u2skip  "$OUT/P2_window.txt" 'P-SB-SUMMARY-FINAL-SKIP'
        count_file_into u2judg  "$OUT/P2_window.txt" 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT'
        U2SBRC=$(grep -ao "P-SB-SUMMARY-LOCK slot=[0-9]* rc=-\?[0-9]*" "$OUT/P2_window.txt" | tail -1 | sed -n 's/.*rc=//p')
        echo "STAGE second-unmount window on $P: transition-wait=$u2wait stalled=$u2stall fail-sb=$u2fsb under-judgement=$u2judg sb-lock-rc='${U2SBRC:-none}' sb-skip=$u2skip"
        grep -a 'P960-AUTH-TRANSITION\|P-SB-SUMMARY-LOCK\|P-SB-SUMMARY-FINAL\|P-TAUTH-TAKEOVER-UNDER' "$OUT/P2_window.txt" | tail -6 | cut -c1-230 | sed 's/^/    /'
        if [ "$U2RC" = 137 ]; then
            echo "  FAIL the fresh incarnation's unmount was STILL PARKED at ${UMOUNT_MAX}s and only a SIGKILL ended it ($u2wait transition wait(s), $u2stall stall(s), $u2judg under-judgement refusal(s)) — put_super's SB summary lock on a page the dead incarnation authored has no exit"
            fails=$((fails+1))
        elif [ "$u2wait" -ge 1 ]; then
            echo "  PASS the fresh incarnation's unmount ended by itself (rc=$U2RC, summary lock rc=${U2SBRC:-none}, fail-sb=$u2fsb) after entering the transition path $u2wait time(s); the summary lock's wait is bounded"
        else
            echo "  INFO the fresh incarnation's unmount returned rc=$U2RC without meeting a transition (summary lock rc=${U2SBRC:-none}, sb-skip=$u2skip) — its summary page was not one the victim authored"
        fi
    fi
    if [ "$twait" -lt 1 ] && [ "$u2wait" -lt 1 ] && [ $fails -eq 0 ]; then
        vac "neither the fresh mount (rc=$MRC) nor its unmount (rc=$U2RC, summary lock rc=${U2SBRC:-none}, sb-skip=$u2skip) ever entered a transition wait — no page the fresh incarnation needed was under the victim's judgement; the windows above say which gate answered instead" remount-no-transition
    fi
    echo "=== nonfallible_transition_stall $LABEL (REMOUNT arm): fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
    if [ $fails -eq 0 ]; then
        echo "RESULT: PASS label=$LABEL arm=remount fails=0 twait=$twait tstall=$tstall mrc=$MRC u2rc=$U2RC u2wait=$u2wait u2fsb=$u2fsb evidence=$OUT"
    else
        echo "RESULT: FAIL label=$LABEL arm=remount fails=$fails twait=$twait tstall=$tstall stall_fallible0=$tstf0 mrc=$MRC u2rc=$U2RC u2wait=$u2wait u2fsb=$u2fsb evidence=$OUT"
    fi
    exit $(( fails == 0 ? 0 : 1 ))
fi

# ---- 4. arm the manifest-snapshot injector on the prover and mark both rings
value_now_into inj "$P" 20 "$OUT/P_inject_set.txt" '^1$' "the rman_inject knob after arming on $P" "echo 1 > $PARM/rman_inject; cat $PARM/rman_inject"
echo "STAGE rman_inject=$inj armed on $P at +$(el)s"
for n in "$V" "$P"; do rs 15 "$n" "echo $MARK > /dev/kmsg" >/dev/null 2>&1; done

# ---- 5. destroy the victim.  From here the prover must fence it, fail the
#         manifest snapshot and park the descriptor at SNAPSHOTTING.
$VIRSH destroy "$V" >/dev/null 2>&1 || {
    echo "ABORT: virsh destroy $V failed"
    echo "RESULT: ABORT label=$LABEL stage=destroy evidence=$OUT"; exit 2; }
echo "STAGE destroyed $V at +$(el)s"

# the dead window is 62 s and the fence follows it; the injected snapshot
# failure is logged by the prover itself
wait_for_into wsnap "$P" 140 "$MARK" "P-RMAN-INJECT slot=$VSLOT "
if [ "$wsnap" = timeout ]; then
    window_into "$OUT/P_nosnap.txt" "$P" 40 "$MARK"
    echo "  $P logged no injected snapshot failure for slot $VSLOT within 140 s: [$(grep -a 'P-RMAN\|P2[0-9][0-9]-\|fenc' "$OUT/P_nosnap.txt" | tail -4 | tr '\n' ' ' | cut -c1-300)]"
    vac "the prover never reached the manifest snapshot, so no guard was parked below IMAGES_REPLAYED" no-snapshot-attempt
fi
echo "STAGE $P failed the injected manifest snapshot for slot $VSLOT, ${wsnap}s after the kill (+$(el)s)"

# ---- 6. the platter must actually carry a standing guard BELOW
#         IMAGES_REPLAYED for the victim.  This is read from the disk, not
#         from the prover's opinion of it.
measure "$P" 60 "$OUT/hb_guard.txt" '^slot +[0-9]+ magic=' "the disklock table after the parked snapshot" "python3 $DUMP $MXFS_DEV"
gline=$(grep -aE "^slot +$VSLOT " "$OUT/hb_guard.txt" | head -1)
dline=$(awk -v s="$VSLOT" '$1=="slot" && $2==s {f=1; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$OUT/hb_guard.txt")
echo "  platter slot $VSLOT: $(echo "$gline" | cut -c1-140)"
echo "  platter desc     : $(echo "$dline" | cut -c1-200)"
case $gline in *RECOVERY_GUARD*) ;; *) vac "the victim's slot is not RECOVERY_GUARD, so v5_recovery_judging_cb has nothing to protect" no-guard ;; esac
stage=$(printf '%s' "$dline" | sed -n 's/.*stage=[A-Z_]*(\([0-9]*\)).*/\1/p')
[ -n "$stage" ] || vac "the guard slot carries no readable descriptor stage" no-desc
[ "$stage" -lt 4 ] || vac "the descriptor is at stage $stage, at or past IMAGES_REPLAYED — the judgement is complete and the page is releasable" guard-complete
echo "STAGE the guard stands at stage $stage (below IMAGES_REPLAYED) at +$(el)s"

# ---- 8. THE MEASUREMENT.  Unmount the prover.  put_super's SB summary lock is
#         a caller v5_acq_fallible_cb does not name; the page it needs is the
#         victim's, and the judgement above will not release it.
#
#         The unmount runs under an explicit SIGKILL bound because the wait it
#         may enter has no other exit; the rc distinguishes the two outcomes
#         (137 = still parked when the instrument ended it).  The kernel stack
#         of the parked task is captured WHILE it is parked — after the kill
#         there is nothing to read.
umount_measure P

# ---- 9. the window the verdict is read from
window_into "$OUT/P_window.txt" "$P" 60 "$MARK"
count_file_into twait  "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-WAIT'
count_file_into tstall "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-STALLED'
count_file_into tstf0  "$OUT/P_window.txt" 'P960-AUTH-TRANSITION-STALLED.* fallible=0 '
count_file_into sblock "$OUT/P_window.txt" "P-SB-SUMMARY-LOCK slot=$PSLOT .*at=put_super"
count_file_into sbskip "$OUT/P_window.txt" 'P-SB-SUMMARY-FINAL-SKIP'
count_file_into oops   "$OUT/P_window.txt" 'BUG:\|Oops\|kernel NULL pointer'
# dlm_takeover_page names the refusal it took.  This is the one the lap set out
# to produce; it is REPORTED rather than required, because a stall reached
# through any other refusal is the same defect in the retry loop and must not
# be scored VACUOUS just for arriving by a different door.
count_file_into judg  "$OUT/P_window.txt" 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT'
# the rc the non-fallible acquire actually returned.  s130c's whole window held
# one line for the probe and its rc was the verdict: -107 (-ENOTCONN) is the
# transport answering for a master that is not there, -112 (-EHOSTDOWN) is the
# pre-send deny for a dead master whose recovery reads as blocked
# (P-RBLK-DENY-DEAD-MASTER, dlm/dlm.c:6613-6620), and -32/-104 are the same
# send failing another way.  None of them is a transition, so none measures
# this record — and reporting them by name is what tells the next lap that the
# page's master was not alive.
SBRC=$(grep -ao "P-SB-SUMMARY-LOCK slot=$PSLOT rc=-\?[0-9]*" "$OUT/P_window.txt" | tail -1 | sed -n 's/.*rc=//p')
echo "STAGE window on $P: transition-wait=$twait stalled=$tstall stalled(fallible=0)=$tstf0 under-judgement=$judg sb-lock-at-put_super=$sblock sb-lock-rc='${SBRC:-none}' sb-skip=$sbskip oops=$oops"
grep -a 'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT\|P-RBLK-DENY-DEAD-MASTER\|P-SB-SUMMARY-LOCK' "$OUT/P_window.txt" | tail -3 | cut -c1-230 | sed 's/^/    /'
grep -a 'P960-AUTH-TRANSITION' "$OUT/P_window.txt" | tail -4 | cut -c1-230 | sed 's/^/    /'

# ---- 10. the verdict
if [ "$sbskip" -ge 1 ] && [ "$twait" -lt 1 ]; then
    vac "the prover's put_super skipped the SB summary write (shutdown or read-only mount), so the non-fallible caller never ran" sb-skipped
fi
if [ "$twait" -lt 1 ]; then
    case ${SBRC:-none} in
        -107|-112|-32|-104)
            vac "the prover's put_super was refused rc=$SBRC before any transition — the summary page's master was not a live node, so the acquire failed fast on the transport instead of entering a takeover; the roles were chosen from master_self, so read both quiesce windows for a mastership that moved after they were read" master-not-live
            ;;
    esac
fi
if [ "$twait" -lt 1 ]; then
    vac "put_super's SB summary lock never met a page in transition (rc='${SBRC:-none}') — the page it needed was not under a refused takeover, so nothing about a stalled transition was measured" no-transition
fi
ck "no BUG/Oops on the prover" "$oops" 0
if [ "${URC:-none}" = 137 ]; then
    echo "  FAIL the unmount was STILL PARKED at the ${UMOUNT_MAX}s instrument bound and only a SIGKILL ended it, with $twait transition wait(s) and $tstf0 stall(s) that named the caller non-fallible — the transition wait is unbounded for a caller the fallible oracle does not name$( [ "$judg" -ge 1 ] && echo "; the refusal underneath it was the departed authority's open judgement ($judg x P-TAUTH-TAKEOVER-UNDER-JUDGEMENT)" || echo "; the refusal underneath it was NOT the judging one — read the window for which dlm_takeover_page path returned")"
    fails=$((fails+1))
elif [ -z "${URC:-}" ]; then
    echo "ABORT: the unmount produced no rc at all; nothing was measured"
    echo "RESULT: ABORT label=$LABEL stage=umount evidence=$OUT"; exit 2
else
    echo "  PASS the unmount ended by itself (rc=$URC) after entering the transition path $twait time(s); the wait is bounded on this route"
fi
# the stall detector must at least have SEEN the frozen counter — if it never
# fired, a bounded unmount proves nothing about a permanently refused page
if [ "${URC:-none}" != 137 ] && [ "$tstall" -lt 1 ]; then
    vac "the unmount returned before the 30 s stall detector ever fired, so the refusal it met was not shown to be permanent" no-stall-observed
fi

echo "=== nonfallible_transition_stall $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ $fails -eq 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 twait=$twait tstall=$tstall urc=$URC evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails twait=$twait tstall=$tstall stall_fallible0=$tstf0 urc=$URC evidence=$OUT"
fi
[ $fails -eq 0 ]
