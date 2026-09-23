#!/bin/bash
# auth_lease_unmount.sh — can a node whose AUTHORITY LEASE has closed still be
# unmounted, and can the module still be removed?
#
# WHY THIS EXISTS.  The authority lease refuses every mutation once this node's
# own heartbeat has gone stale, and that deliberately includes the journal: an
# "essential log write" exemption would reopen the hazard the lease was built
# to close.  The direct consequence is that a withdrawn mount cannot write its
# own unmount record, and the question that raises is not academic — the
# release bar refuses anything that hangs or shuts down a node, so a mount that
# can be contained but not taken down would trade one release blocker for
# another.
#
# WHAT IT SEPARATES.  tests/fence_late_detection.sh leaves the victim with BOTH
# a closed lease AND a heartbeat thread parked inside a multi-minute injected
# sleep, and after lap s87i the next prep could not get the module out of that
# node.  Those are two different suspects and the interesting one is the lease.
# So here the park is SHORT: long enough for the lease to expire, and over well
# before the unmount is attempted.  Anything that hangs afterwards hangs
# because authority is closed, which is the thing under test.
#
# SHAPE:
#   1. prep 2 nodes.  B is healthy and mounted.
#   2. park B's heartbeat for a little longer than the lease, and nothing else
#      — the PR detectors stay live, because this lap is not about how B finds
#      out, only about what it can still do afterwards.
#   3. wait for P290-AUTH-CLOSED.  Without it the lap is VACUOUS: it would be
#      grading an ordinary unmount.
#   4. wait out the rest of the park so the heartbeat thread is back in its own
#      loop and cannot be blamed.
#   5. bounded umount, then bounded module removal.  Both must finish.
#   6. the node must still be usable: mount its local root, write, read back.
#
# the budget rule (derived): prep <= 300 (measured 48-69) + the park, which is
# lease 30 + 10 = 40 + closure observation 30 + umount, a native unmount of an
# idle mxfs mount measures 2-4 s and a shut-down one has nothing to flush, so
# bound 60 + module removal, same shape, bound 60 + liveness 20 = 510.
# Caller bound 540 s.
#
# Usage: tests/auth_lease_unmount.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), PARK_MS (40000)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}          # the node whose lease is allowed to expire
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
PARK_MS=${PARK_MS:-40000}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_authum_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="AUTHUM-MARK-$LABEL"
echo "=== auth_lease_unmount label=$LABEL A=$A B(lease expires)=$B $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

if [ "$(strings -a mxfs.ko | grep -c 'P290-AUTH-CLOSED')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no authority lease, so there is nothing here to measure"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
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

# ---- 1. B is healthy: prove it, so a later refusal means something
measure "$B" 60 "$OUT/B_pre.txt" '^PRE_END$' "B mounted and writable before the lease expires" \
    "echo $MARK > /dev/kmsg; d=$MNT/authum_$LABEL; mkdir -p \$d && printf 'pre\n' > \$d/f && sync -f $MNT && echo PRE_OK; echo PRE_END"
ck "B accepts work while its lease is live" "$(cnt "$OUT/B_pre.txt" '^PRE_OK$')" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=pre evidence=$OUT"; exit 2; }

# ---- 2. let the lease lapse, and nothing else
measure "$B" 30 "$OUT/B_park.txt" '^PARKED=[0-9]+$' "the heartbeat park on $B" \
    "echo $PARK_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo PARKED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing')"
ck "B's heartbeat is parked, so its lease will lapse" "$(field "$OUT/B_park.txt" PARKED)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=park evidence=$OUT"; exit 2; }

# ---- 3. the lease must actually close, or this lap grades an ordinary unmount
w=0
while [ $w -lt 60 ]; do
    measure "$B" 30 "$OUT/B_closed.txt" '^CLOSED=[0-9]+$' "whether B's lease has closed yet" \
        "echo CLOSED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P290-AUTH-CLOSED')"
    [ "$(field "$OUT/B_closed.txt" CLOSED)" != 0 ] && break
    sleep 5; w=$((w+5))
done
echo "STAGE B's lease closed=$(field "$OUT/B_closed.txt" CLOSED) after ${w}s at +$(el)s"
if [ "$(field "$OUT/B_closed.txt" CLOSED)" = 0 ]; then
    echo "  the lease never closed, so there is no closed-authority unmount to measure"
    echo "RESULT: VACUOUS label=$LABEL stage=no-close wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 4. give the park back before measuring, so a sleeping thread cannot be
#         mistaken for the lease.  PARK_MS from the arm, plus its 4 s settle.
echo "STAGE waiting out the rest of the ${PARK_MS}ms park at +$(el)s"
sleep $(( PARK_MS / 1000 ))
measure "$B" 30 "$OUT/B_resumed.txt" '^RESUMED=[0-9]+$' "the heartbeat park has ended on $B" \
    "echo RESUMED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*resumed')"
ck "the heartbeat thread is out of its injected sleep before the unmount" "$(field "$OUT/B_resumed.txt" RESUMED)" 1

# ---- 5. THE MEASUREMENT.  Both must finish inside their own bound, and the
#         bound is the assertion: a refused log write must not become a hang.
measure "$B" 90 "$OUT/B_umount.txt" '^UMOUNT rc=' "the unmount of a closed-authority mount on $B" \
    "s=\$(date +%s); timeout 60 umount $MNT; rc=\$?; echo UMOUNT rc=\$rc secs=\$(( \$(date +%s) - s )); grep -c ' $MNT ' /proc/mounts | sed 's/^/STILL_MOUNTED=/'"
URC=$(field "$OUT/B_umount.txt" rc); USEC=$(field "$OUT/B_umount.txt" secs)
echo "STAGE umount rc=$URC secs=$USEC still_mounted=$(field "$OUT/B_umount.txt" STILL_MOUNTED)"
ck "the unmount COMPLETED rather than hanging" "$([ -n "$URC" ] && [ "$URC" != 124 ] && echo completed || echo hung)" completed
ck "the mount is gone from /proc/mounts" "$(field "$OUT/B_umount.txt" STILL_MOUNTED)" 0

measure "$B" 90 "$OUT/B_rmmod.txt" '^RMMOD rc=' "the module removal on $B" \
    "s=\$(date +%s); timeout 60 rmmod mxfs; rc=\$?; echo RMMOD rc=\$rc secs=\$(( \$(date +%s) - s )); echo LOADED=\$(grep -c '^mxfs ' /proc/modules)"
RRC=$(field "$OUT/B_rmmod.txt" rc); RSEC=$(field "$OUT/B_rmmod.txt" secs)
echo "STAGE rmmod rc=$RRC secs=$RSEC loaded=$(field "$OUT/B_rmmod.txt" LOADED)"
ck "the module removal COMPLETED rather than hanging" "$([ -n "$RRC" ] && [ "$RRC" != 124 ] && echo completed || echo hung)" completed
ck "the module is out" "$(field "$OUT/B_rmmod.txt" LOADED)" 0

# ---- 6. the node itself must still be a working machine
measure "$B" 40 "$OUT/B_live.txt" '^LIVE_END$' "B is still a usable node afterwards" \
    "printf 'alive\n' > /run/authum_$LABEL && cat /run/authum_$LABEL && uptime | tr -s ' '; echo LIVE_END"
ck "B is still serving after the closed-authority unmount" "$(cnt "$OUT/B_live.txt" '^alive$')" 1

measure "$B" 60 "$OUT/B_final.txt" '^JOURNAL_END$' "B's journal for the record" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
echo "    $(grep -a 'P290-AUTH-CLOSED' "$OUT/B_final.txt" | head -1 | sed 's/.*mxfs: //' | cut -c1-190)"
grep -a 'P290-AUTH-REFUSED' "$OUT/B_final.txt" | sed 's/.*: /    /' | cut -c1-160 | head -3
ck "B: zero BUG / Oops" "$(cnt "$OUT/B_final.txt" 'BUG:\|Oops')" 0

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
