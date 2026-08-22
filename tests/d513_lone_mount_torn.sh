#!/bin/bash
# d513_lone_mount_torn.sh — D-513 pre-rig check A5 (sess333 Q7 plan):
# a LONE mounting node whose mount-time cohort recovery hits a genuinely
# torn (shape-4 injected) dead peer slice must:
#
#   1. refuse the replay INSIDE the mount admission barrier,
#   2. durably publish the TERMINAL_REFUSED outcome under the barrier's
#      recovery lease (outcome=1 reason=2 PHYSICALLY_TORN domain=1 FSWIDE),
#   3. abort the mount with -EIO ("mount ABORTED: a terminal recovery
#      refusal quarantines the WHOLE filesystem"),
#   4. leave the mounter NOT mounted and NOT shut down / withdrawn.
#
# Topology: fleet must be freshly prepped and mounted (post prep_cluster).
# The script unmounts every node except the victim, starts an inode-mode
# dirty load on the victim (touch+sync over preexisting files — the only
# txn shape that decrements the shape-4 countdown, proven sess341), kills
# the victim mid-loop, arms shape 4 on the mounter, and attempts the mount.
#
# Usage: tests/d513_lone_mount_torn.sh [N] [victim] [mounter]
#   N       fleet size currently prepped (default 32)
#   victim  node killed dirty (default test2)
#   mounter lone node that attempts the mount (default test1)
# Env: TORN_ITEMS (default 3) — shape-4 pass-2 countdown.
#
# Leaves a durable FSWIDE quarantine on the LUN — re-prep before any other
# board test.  Exit 0 = all assertions PASS.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:-32}"
VICTIM="${2:-test2}"
MOUNTER="${3:-test1}"
MNT=/mnt/shared
TORN_ITEMS="${TORN_ITEMS:-3}"
# Mount pays the dead-peer confirm window (~62s) + fence + replay + publish.
MOUNT_TIMEOUT="${MOUNT_TIMEOUT:-240}"

[ "$VICTIM" = "$MOUNTER" ] && { echo "FAIL: victim == mounter"; exit 1; }

T0=$(date -u +%FT%TZ)
echo "=== d513_lone_mount_torn: N=$N victim=$VICTIM mounter=$MOUNTER torn_items=$TORN_ITEMS @ $T0 ==="

# 0. Device path, read from the victim while it is still mounted.
DEV=$("$SSH" "$VICTIM" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -n "$DEV" ] || { echo "FAIL: victim $VICTIM has no mxfs mount (fleet not prepped?)"; exit 1; }
echo "shared device: $DEV"

# 1. Unmount every node except the victim (parallel, bounded per RULE 2c).
echo "--- unmounting all nodes except $VICTIM"
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] && continue
    "$SSH" "$h" "timeout 60 umount $MNT" >/dev/null 2>&1 &
done
wait
still=0
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] && continue
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] && { echo "FAIL: $h still mounted after umount"; still=$((still+1)); }
done
[ "$still" -eq 0 ] || exit 1
echo "all non-victim nodes unmounted; $VICTIM is the lone member"

# 2. Inode-mode dirty load on the victim (see d513_refusal_containment.sh
#    MODE=inode rationale: create/rename txns are ATOMIC-SKIP'd at foreign
#    replay; only XFS_LI_INODE items genuinely apply and decrement the
#    shape-4 countdown).
echo "--- starting inode-mode load on $VICTIM"
"$SSH" "$VICTIM" "D=$MNT/.d513lone; mkdir -p \$D;
    for i in \$(seq 1 64); do echo seed > \$D/t\$i; done; sync" >/dev/null 2>&1
"$SSH" "$VICTIM" "nohup bash -c '
    D=$MNT/.d513lone
    end=\$((SECONDS + 60))
    while [ \$SECONDS -lt \$end ]; do
        touch \$D/t{1..64}
        sync
    done
' >/tmp/d513lone.log 2>&1 &" >/dev/null 2>&1
sleep 10

# 3. Kill the victim mid-loop.
date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

# 4. Arm shape 4 on the mounter (one-shot; consumed by the barrier replay).
echo "--- arming shape-4 on $MOUNTER"
"$SSH" "$MOUNTER" "echo 4 > /sys/module/mxfs/parameters/freplay_force_refusal;
    echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
    echo $TORN_ITEMS > /sys/module/mxfs/parameters/freplay_force_torn_items;
    dmesg --clear" >/dev/null 2>&1
v=$("$SSH" "$MOUNTER" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "$v" = "4" ] || { echo "FAIL: knob not armed on $MOUNTER (got '$v')"; exit 1; }

# 5. The lone mount attempt.  Must FAIL with -EIO after the barrier
#    refuses + publishes.  (timeout exit 124 would mean the barrier hung —
#    that is its own failure.)
echo "--- lone mount attempt on $MOUNTER (timeout ${MOUNT_TIMEOUT}s)"
mout=$("$SSH" "$MOUNTER" "timeout $MOUNT_TIMEOUT mount -t mxfs $DEV $MNT 2>&1; echo mount_rc=\$?" 2>/dev/null)
echo "$mout" | sed 's/^/  | /'
mrc=$(echo "$mout" | sed -n 's/^mount_rc=//p' | tail -1)

pass=1
echo "--- assertions"
if [ "${mrc:-0}" = "0" ]; then
    echo "FAIL: mount SUCCEEDED — FSWIDE torn refusal did not abort the mount"
    pass=0
elif [ "${mrc:-0}" = "124" ]; then
    echo "FAIL: mount TIMED OUT (${MOUNT_TIMEOUT}s) — barrier hung instead of aborting"
    pass=0
else
    echo "mount failed rc=$mrc (want nonzero, not 124): OK"
fi

D=$(mktemp -d)
"$SSH" "$MOUNTER" "dmesg" > "$D/mounter.dmesg" 2>/dev/null

chk() {  # $1 = label, $2 = pattern
    if grep -q "$2" "$D/mounter.dmesg"; then
        echo "$1: OK"
    else
        echo "FAIL: $1 — pattern '$2' not in mounter dmesg"
        pass=0
    fi
}
chk "shape-4 knob consumed"      "P227-FR-INJECT-ARMED.*shape=4"
chk "genuine mid-replay TORN"    "P227-FR-FORCED-TORN"
chk "terminal outcome published" "terminal outcome PUBLISHED"
chk "FSWIDE mount abort"         "mount ABORTED: a terminal recovery refusal quarantines"

if grep -qE "Filesystem has been shut down|forced shutdown|MXFS.*withdraw" "$D/mounter.dmesg"; then
    echo "FAIL: mounter shut down / withdrew — abort must be a clean mount failure"
    pass=0
else
    echo "mounter clean (no shutdown/withdraw): OK"
fi

m=$("$SSH" "$MOUNTER" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
if [ "$m" = "Y" ]; then
    echo "FAIL: $MOUNTER ended up mounted"
    pass=0
else
    echo "mounter not mounted: OK"
fi

# 6. On-platter verdict: the victim slot's outcome record must be a valid
#    RVCO TERMINAL_REFUSED / PHYSICALLY_TORN / FSWIDE.
vslot=$(grep -o "foreign replay of dead slot [0-9]*" "$D/mounter.dmesg" | head -1 | awk '{print $NF}')
echo "victim slot (from replay line): ${vslot:-UNKNOWN}"
dump=$("$SSH" "$MOUNTER" "/src/mxfs/tools/caw_slotdump $DEV --recov" 2>/dev/null)
if [ -n "${vslot:-}" ]; then
    oline=$(echo "$dump" | awk -v s="hb\\[0?$vslot\\]" '$0 ~ s {f=1; next} f && /outcome/ {print; exit} f && /^hb\[/ {exit}')
    echo "  | $oline"
    if echo "$oline" | grep -q "(RVCO)" &&
       echo "$oline" | grep -q "outcome=1 reason=2 domain=1"; then
        echo "durable TORN/FSWIDE verdict on victim slot: OK"
    else
        echo "FAIL: victim slot outcome is not RVCO outcome=1 reason=2 domain=1"
        pass=0
    fi
else
    echo "FAIL: could not determine victim slot from dmesg"
    pass=0
fi

# 7. Disarm (one-shot should already be consumed; belt and suspenders).
"$SSH" "$MOUNTER" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
    echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1

echo "--- refusal detail"
grep -E "P227-FR-FORCED-TORN|terminal outcome PUBLISHED|mount ABORTED" "$D/mounter.dmesg" | head -6
echo "dmesg harvest kept in $D"

if [ "$pass" -eq 1 ]; then
    echo "=== d513_lone_mount_torn PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== d513_lone_mount_torn FAIL @ $(date -u +%FT%TZ) ==="
exit 1
