#!/bin/bash
# d_mount_window_death_verify.sh — D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE
# window arm + negative control, per the sess420 design-consult barrier ruling
# (docs/rulings/mount-barrier-items-3-4-6c-window-arm.md
# item 4: "use a deterministic hold/faultpoint ... PAUSE A after mphase is
# armed; kill B; hold until B is confirmed dead and P233 durable; release").
#
#   window   A=test3 is unmounted, arms mxfs.dbg_barrier_hold_ms (self-
#            clearing, fires once at the top of the admission barrier —
#            after DLM init armed the mount-phase death record) and mounts
#            DETACHED.  Once A logs P-DBG-BARRIER-HOLD start, B=test8 is
#            virsh-destroyed.  The hold outlasts B's 62 s confirm window, so
#            A's own monitor records P233-MPHASE-DEATH for B while A owns
#            the mount phase; on release the barrier drains that late death
#            and replays B's slice INLINE, before A goes live.
#            Assert on A: hold start/released, P233 for B's slot, barrier
#            complete line with late=<B bit> and replayed>=1, exactly one
#            P163-RECOVERY-COMPLETE for B's slot, mount rc=0, A writable.
#            Assert on C=test2 (and every other survivor): ZERO election /
#            replay-start / recovery-complete for B — the mounting node's
#            barrier resolved the death, nobody else raced it.
#   control  B killed while A is mounted and idle: P233-MPHASE-DEATH absent
#            fleet-wide, the ordinary live path elects a replayer (lowest
#            live slot) and publishes P163-RECOVERY-COMPLETE for B's slot.
#
# the budget rule (derived): umount ~5 s + hold 100 s + inline replay ~15 s +
# harvest ~25 s => ~145 s (window); 62 s confirm + 15 s + 25 s => ~105 s
# (control).  Caller bounds 220 s / 160 s.
#
# Usage: tests/d_mount_window_death_verify.sh <label> <window|control> [A] [B] [C]
set -u
LABEL=${1:?label}; ARM=${2:?arm}; A=${3:-test3}; B=${4:-test8}; C=${5:-test2}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
P=/sys/module/mxfs/parameters
HOLD_MS=100000
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_mwindow_$ARM
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
ge1() { [ "${1:-0}" -ge 1 ] && echo yes || echo no; }
# rs/rsx/measure/window_count_into (tests/lib/rig.sh): every count a verdict
# is taken from is acquired into its own file and validated in the parent
# shell first; a failed ssh is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
# cnt: POLLING ONLY (waitfor); never feeds a verdict
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }
waitfor() { # waitfor <node> <pattern> <max_s>
    local i=0; while [ $i -lt "$3" ]; do [ "$(cnt "$1" "$2")" -ge 1 ] 2>/dev/null && { echo $i; return 0; }; sleep 3; i=$((i+3)); done; echo timeout; return 1; }

echo "=== d_mount_window_death_verify label=$LABEL arm=$ARM A=$A B=$B C=$C out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B $C; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
done
rs 10 "$A" "test -e $P/dbg_barrier_hold_ms && echo ok" | grep -q ok || { echo "ABORT: $A lacks $P/dbg_barrier_hold_ms (build without the sess421 hold knob?)"; exit 2; }
tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$OUT/knobs.txt" > "$OUT/knobs.log" 2>&1 || { echo "ABORT: enforcement arming failed: $(tail -2 "$OUT/knobs.log" | tr '\n' ' ')"; exit 2; }
echo "  INFO enforcement armed fleet-wide ($OUT/knobs.txt)"
window_into "$OUT/rv_bslot_1.txt" "$B" 15; bslot=$(cat "$OUT/rv_bslot_1.txt" | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | grep -o '[0-9]*$' | tr -dc '0-9')
window_into "$OUT/rv_bid_1.txt" "$B" 15; bid=$(cat "$OUT/rv_bid_1.txt" | grep -ao 'MXFS-MEMBERSHIP local=[0-9]*' | tail -1 | tr -dc '0-9')
echo "  INFO B=$B slot=$bslot node=$bid"
[ -n "$bslot" ] || { echo "ABORT: could not read B's heartbeat slot"; exit 2; }
MARK="MWINDOW-$LABEL-$ARM-$$"
for n in $A $C; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
# sess423: the s421 run lost every kernel line of the failing arms (the harness
# only dumped dmesg on its success path; the timeout killed it first and the
# next prep power-cycled A).  Capture on EVERY exit, from every node the arm
# touched, before anything else can recycle them.
CAPTURE_NODES="$A $C"
capture_on_exit() {
    local n
    for n in $CAPTURE_NODES; do
        [ -s "$OUT/dmesg_$n.txt" ] && continue
        rs 25 "$n" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$n.txt" 2>/dev/null
    done
    echo "  INFO exit capture: $(for n in $CAPTURE_NODES; do echo -n "$n=$(wc -l < "$OUT/dmesg_$n.txt" 2>/dev/null || echo 0)l "; done)"
}
trap capture_on_exit EXIT
# a few durable files on B so its slice/manifest carry real records at death
rs 30 "$B" "mkdir -p $MNT/.mwindow_$LABEL && for i in 1 2 3 4; do dd if=/dev/urandom of=$MNT/.mwindow_$LABEL/b\$i bs=4096 count=2 2>/dev/null; done; sync; sleep 1; echo ok" | grep -q ok || { echo "ABORT: B setup failed"; exit 2; }

case "$ARM" in
  window|window_lone)
    # sess434 window_lone (D-MOUNT-WINDOW record item 3): B is the ONLY other
    # member — every survivor is unmounted first — so nobody can resolve B's
    # death for A; A's barrier must fold the late death and replay B's slice
    # INLINE (late=<B bit> replayed>=1 published=<B bit>, A publishes once).
    if [ "$ARM" = window_lone ]; then
        D0=$(mktemp -d)
        for i in $(seq 1 32); do
            n=test$i; { [ "$n" = "$B" ] || [ "$n" = "$A" ]; } && continue   # A is unmounted by the arm itself below
            ( timeout 60 $SSH "$n" "umount $MNT 2>/dev/null; mount -t mxfs | grep -c shared" 2>/dev/null | filt | tr -dc '0-9' > "$D0/$n" ) &
        done; wait
        still=$(cat "$D0"/test* 2>/dev/null | grep -c '^1')
        ck "every survivor unmounted (B alone stays mounted)" "$still" "0"
        [ "$still" = 0 ] || { echo "ABORT: $still survivor(s) still mounted"; exit 2; }
        sleep 3
    fi
    value_now_into rv2 "$A" 90 "$OUT/rv_rv2_2.txt" '^rc=' "rv2 on $A" "timeout 60 umount $MNT; echo rc=\$?"; rv2=$(printf '%s\n' "$rv2" | sed -n 's/^rc=//p')
    ck "A unmounted" "$rv2" "0"
    rs 10 "$A" "echo $HOLD_MS > $P/dbg_barrier_hold_ms; cat $P/dbg_barrier_hold_ms" | grep -q "^$HOLD_MS" || { echo "ABORT: could not arm the barrier hold on $A"; exit 2; }
    rs 15 "$A" "setsid nohup sh -c 'timeout 240 mount -t mxfs $DEV $MNT; echo rc=\$? > /tmp/mwindow_mount.rc' >/tmp/mwindow_mount.log 2>&1 & echo LAUNCHED" | grep -q LAUNCHED || { echo "ABORT: could not launch A's mount"; exit 2; }
    wait_for_into t "$A" 60 "$MARK" "P-DBG-BARRIER-HOLD start"; ck "A's barrier paused with the mphase record armed (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    T0=$(date -u '+%F %T')   # sess434: journal window for the cluster-wide count (nodes are UTC)
    $VIRSH destroy "$B" >/dev/null 2>&1; echo "  INFO virsh destroy $B rc=$? at $(date -u +%T)"
    wait_for_into t "$A" 95 "$MARK" "P233-MPHASE-DEATH slot=$bslot "; ck "A recorded B's death in the mount phase (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    wait_for_into t "$A" 110 "$MARK" "P-DBG-BARRIER-HOLD released"; ck "hold released (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    wait_for_into t "$A" 120 "$MARK" "mount recovery barrier complete"; ck "barrier completed (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    bl=$(rs 20 "$A" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'mount recovery barrier complete' | tail -1"); echo "  INFO $bl"
    late=$(echo "$bl" | grep -ao 'late=0x[0-9a-f]*' | cut -d= -f2); rep=$(echo "$bl" | grep -ao 'replayed=[0-9]*' | tr -dc '0-9'); pub=$(echo "$bl" | grep -ao 'published=0x[0-9a-f]*' | cut -d= -f2)
    # sess434: the late-mask check lives in the A-replayed branch below — under
    # RESOLVED-ELSEWHERE the barrier retires B's bit from `drained` by design
    # (xfs_mxfs_dlm.c `drained &= ~elsewhere`), so late= cannot carry it.
    # sess424 (design-consult ruling ccloop-c7ee71c6-sess424-GPT-ruling-barrier-
    # resolved-elsewhere): survivor recovery is NOT suppressed during a
    # mount — the live path's elected replayer may complete B first.  The
    # invariant is "completion by EITHER retires the cut bit and A is
    # admitted only after durable completion", so exactly ONE of the two
    # resolvers must have published B, and A's barrier must have accepted
    # it.  The s423 run (0.34.0) aborted A's mount over the survivor's
    # completion — that is the defect this arm now catches.
    sleep 5
    window_count_into apub "$A" 20 "$MARK" "P163-RECOVERY-COMPLETE slot=$bslot " "apub"; window_count_into aelse "$A" 20 "$MARK" "P233-MPHASE-RESOLVED-ELSEWHERE slot=$bslot " "aelse"
    echo "  INFO A published=$apub resolved-elsewhere=$aelse replayed=${rep:-?} published_mask=${pub:-?}"
    if [ "${apub:-0}" = 1 ]; then
        ck "late mask carries B's slot bit" "$(python3 -c "print('yes' if (int('${late:-0}',16)>>$bslot)&1 else 'no')")" "yes"
        ck "A replayed inline: barrier replayed >=1 and published mask carries B" "$([ "$(ge1 "$rep")" = yes ] && [ "$(python3 -c "print('yes' if (int('${pub:-0}',16)>>$bslot)&1 else 'no')")" = yes ] && echo yes || echo no)" "yes"
    else
        ck "A did not publish B itself: it accepted the survivor's completion (RESOLVED-ELSEWHERE)" "$(ge1 "$aelse")" "yes"
    fi
    window_count_into wc1 "$A" 20 "$MARK" 'MXFS mount ABORTED: slot mask' "A never aborted the mount over B s slot"
    ck "A never aborted the mount over B's slot" "$wc1" "0"
    # ordering: P233 line number < barrier-complete line number < RECOVERY-COMPLETE? (publication happens inside the barrier, before its summary line)
    measure "$A" 25 "$OUT/dmesg_$A.txt" '^DMESG_END$' "the kernel log on $A from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
    l233=$(grep -an "P233-MPHASE-DEATH slot=$bslot " "$OUT/dmesg_$A.txt" | head -1 | cut -d: -f1)
    lrel=$(grep -an 'P-DBG-BARRIER-HOLD released' "$OUT/dmesg_$A.txt" | head -1 | cut -d: -f1)
    lpub=$(grep -an "P163-RECOVERY-COMPLETE slot=$bslot " "$OUT/dmesg_$A.txt" | head -1 | cut -d: -f1)
    lbar=$(grep -an 'mount recovery barrier complete' "$OUT/dmesg_$A.txt" | head -1 | cut -d: -f1)
    if [ "${apub:-0}" = 1 ]; then
        ck "order: P233 < hold released < publication < barrier complete" "$([ -n "$l233" ] && [ -n "$lrel" ] && [ -n "$lpub" ] && [ -n "$lbar" ] && [ "$l233" -lt "$lrel" ] && [ "$lrel" -lt "$lpub" ] && [ "$lpub" -lt "$lbar" ] && echo yes || echo no)" "yes"
        ck "zero purge/zero before the hold released (no P163 above the release line)" "$(sed -n "1,${lrel:-1}p" "$OUT/dmesg_$A.txt" | grep -ac "P163-RECOVERY-COMPLETE slot=$bslot ")" "0"
    else
        lres=$(grep -an "P233-MPHASE-RESOLVED-ELSEWHERE slot=$bslot " "$OUT/dmesg_$A.txt" | head -1 | cut -d: -f1)
        ck "order: P233 < hold released < resolved-elsewhere < barrier complete" "$([ -n "$l233" ] && [ -n "$lrel" ] && [ -n "$lres" ] && [ -n "$lbar" ] && [ "$l233" -lt "$lrel" ] && [ "$lrel" -lt "$lres" ] && [ "$lres" -lt "$lbar" ] && echo yes || echo no)" "yes"
    fi
    value_now_into rv3 "$A" 15 "$OUT/rv_rv3_3.txt" '^rc=' "rv3 on $A" "cat /tmp/mwindow_mount.rc"; rv3=$(printf '%s\n' "$rv3" | sed -n 's/^rc=//p')
    ck "A's mount returned 0" "$rv3" "0"
    measure "$A" 20 "$OUT/rv_rv4_4.txt" '^WOK$' "rv4 on $A" "echo x > $MNT/.mwindow_$LABEL.$A && rm -f $MNT/.mwindow_$LABEL.$A && echo WOK"; rv4=$(cat "$OUT/rv_rv4_4.txt" | grep -c WOK)
    ck "A writable after admission" "$rv4" "1"
    # exactly ONE resolver cluster-wide: count every node's publication of B
    # (A included); survivors electing is allowed, a second publication is not.
    # sess434: the window is journalctl --since the destroy time, NOT the kmsg
    # MARK — only A and C ever received the MARK, so the other 30 nodes' sweep
    # read an empty range and the survivor's publication counted as 0 (s433e).
    D=$(mktemp -d)
    for i in $(seq 1 32); do
        n=test$i; [ "$n" = "$B" ] && continue
        ( timeout 15 $SSH "$n" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -ac 'P163-RECOVERY-COMPLETE slot=$bslot '" 2>/dev/null | filt | tr -dc '0-9' > "$D/$n" ) &
    done; wait
    tot=0; for f in "$D"/test*; do v=$(cat "$f"); [ "${v:-0}" != 0 ] && { tot=$((tot+v)); echo "  INFO $(basename "$f") published B: $v line(s)"; }; done
    ck "B published exactly once cluster-wide (one replayer per incarnation)" "$tot" "1"
    window_count_into wc2 "$C" 20 "$MARK" 'P233-MPHASE-DEATH' "C zero P233 (only the mounting node holds the mount phase)"
    ck "C zero P233 (only the mounting node holds the mount phase)" "$wc2" "0"
    ;;
  control)
    # the live path: the LOWEST LIVE SLOT elects (slots are random per mount —
    # sess421 polled the literal test1 while 21 nodes logged "not elected
    # (lowest live slot 0)"; the replayer was whichever node held slot 0).
    # Map every node's slot in parallel and pick the lowest that is not B.
    SM=$(mktemp -d)
    for i in $(seq 1 32); do
        ( rs 15 "test$i" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | grep -o '[0-9]*\$'" | tr -dc '0-9' > "$SM/test$i" ) &
    done; wait
    R=""; rslot=999
    for i in $(seq 1 32); do
        n=test$i; [ "$n" = "$B" ] && continue
        sl=$(cat "$SM/$n"); [ -n "$sl" ] || continue
        [ "$sl" -lt "$rslot" ] && { rslot=$sl; R=$n; }
    done
    echo "  INFO expected replayer R=$R slot=$rslot (lowest live slot; B=$B slot=$bslot excluded)"
    [ -n "$R" ] || { echo "ABORT: could not map heartbeat slots"; exit 2; }
    CAPTURE_NODES="$CAPTURE_NODES $R"
    rs 12 "$R" "echo '$MARK' > /dev/kmsg" >/dev/null
    $VIRSH destroy "$B" >/dev/null 2>&1; echo "  INFO virsh destroy $B rc=$? at $(date -u +%T)"
    wait_for_into t "$R" 110 "$MARK" "elected (slot $rslot) to replay dead node $bid"; ck "$R (slot $rslot) elected to replay B's slice on the live path (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    wait_for_into t "$R" 90 "$MARK" "P163-RECOVERY-COMPLETE slot=$bslot "; ck "live path published B on $R (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    window_count_into wc3 "$A" 20 "$MARK" 'P233-MPHASE-DEATH' "A zero P233-MPHASE-DEATH (not mounting)"
    ck "A zero P233-MPHASE-DEATH (not mounting)" "$wc3" "0"
    window_count_into wc4 "$C" 20 "$MARK" 'P233-MPHASE-DEATH' "C zero P233-MPHASE-DEATH"
    ck "C zero P233-MPHASE-DEATH" "$wc4" "0"
    measure "$A" 25 "$OUT/dmesg_$A.txt" '^DMESG_END$' "the kernel log on $A from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
    ;;
  *) echo "ABORT: unknown arm $ARM"; exit 2 ;;
esac
measure "$C" 25 "$OUT/dmesg_$C.txt" '^DMESG_END$' "the kernel log on $C from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
# both captures by name, whichever arm ran, before the per-node verdicts
capture_require "$OUT/dmesg_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_$C.txt" '^DMESG_END$' "the kernel log on $C"
for n in $A $C; do ck "zero splats on $n" "$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$n.txt")" "0"; done
$VIRSH start "$B" >/dev/null 2>&1; echo "  INFO virsh start $B rc=$?"
echo "=== d_mount_window_death_verify $LABEL $ARM: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
echo "NOTE: $B was destroyed+restarted — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
