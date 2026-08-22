#!/bin/bash
# d513_fswide_abort_preserves_death.sh — sess333 pre-disposition CHECK 4 for
# D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513:
#
#   "an FSWIDE abort preserves an unrelated late death"
#
# sess333 stop-ship A: every barrier exit taken after `drained` has accumulated
# must hand the un-replayed deaths back to the mount-phase record
# (mxfs_v5_dlm_mount_defer_late_deaths(drained & ~replayed & ~terminal)).  An
# FSWIDE abort that returns without doing so DROPS a real peer death on the
# floor: nothing on this node will ever elect a replayer for it again, and the
# victim's slice stays unreplayed while looking resolved.
#
# The proof this test uses is behavioural, not a log line: after the aborted
# mount, REMOVE the FSWIDE cause and mount again.  If the death was preserved,
# the second mount recovers the victim's slice.  If it was dropped, the second
# mount comes up clean with the slice still dirty on the platter.
#
# Staging (requires a TWO-node cluster: ./run.sh 2 caw prep_cluster) — a small
# cluster is required, not a convenience: on the 32-node rig 30 other survivors
# would recover the victim before our mount ever sees it, so "an unrelated late
# death" could not be staged at all.
#
# Usage: tests/d513_fswide_abort_preserves_death.sh [survivor] [victim] [slot]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
FORGE=/src/mxfs/tools/recov_forge
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

SURV="${1:-test1}"
VICTIM="${2:-test2}"
SLOT="${3:-40}"
LOAD="${LOAD:-15}"
SAVE="/tmp/d513_abort_slot${SLOT}.bin"

# RULE 0: both mounts pay the ~62 s dead-confirm window for the frozen peer.
# The first also aborts FSWIDE (fast, once classification runs); the second
# additionally replays the victim's slice.
MOUNT_BUDGET="${MOUNT_BUDGET:-150}"

say() { echo "[$(date -u +%T)] $*"; }
node() { timeout 90 "$SSH" "$1" "$2" 2>/dev/null | grep -v '^Warning:\|Unauthorized access\|disconnect immediately'; }

# Is the filesystem mounted?  Read /proc/mounts — NEVER `mountpoint -q`.
# `mountpoint` stats the mount root, which is inode 128 in AG 0, and an
# AG-scoped quarantine covering AG 0 makes that stat fail with EIO exactly as
# designed.  A shape that quarantines AG 0 therefore made `mountpoint -q`
# report "not mounted" on a perfectly mounted filesystem (measured sess383),
# so the harness skipped its own umount, the remount hit "already mounted",
# and five later shapes refused to run against the wreckage.  /proc/mounts is
# answered by the VFS and never touches the filesystem.
is_mounted() { node "$1" "grep -qs ' $MNT mxfs ' /proc/mounts && echo YES || echo NO" | tail -1 | tr -d '[:space:]'; }


# Identify the victim's heartbeat slot WITHOUT any node_id -> host mapping:
# sample the slot table twice, one heartbeat interval apart, and take the
# ACTIVE slot whose sector did NOT change.  A live node rewrites its record
# every MXFS_DISKLOCK_HB_INTERVAL_MS (2000 ms) so its sector crc moves; a dead
# one is frozen.  This is the same two-sample liveness test tests/hb_slots.sh
# uses, and it is the ONLY correct one here: `head -1` of the ACTIVE list picks
# whichever slot sorts first, which is the SURVIVOR half the time, and a clean
# release does not always zero the survivor's slot immediately (Arm C late
# release), so "the only ACTIVE slot left" is not reliable either.
find_dead_slot() {
    local probe="$1" a b s
    a=$(node "$probe" "$FORGE $DEV dump" | grep "flags=ACTIVE" |
        sed -n 's/^slot=\([0-9]*\) .*sector_crc32c=\(0x[0-9a-f]*\).*/\1:\2/p')
    sleep 6
    b=$(node "$probe" "$FORGE $DEV dump" | grep "flags=ACTIVE" |
        sed -n 's/^slot=\([0-9]*\) .*sector_crc32c=\(0x[0-9a-f]*\).*/\1:\2/p')
    for s in $a; do
        if echo "$b" | grep -qx "$s"; then
            echo "${s%%:*}"
            return 0
        fi
    done
    return 1
}

do_mount() {
    timeout "$MOUNT_BUDGET" "$SSH" "$1" \
        "mount -t mxfs $DEV $MNT >/tmp/d513abort.log 2>&1; echo MOUNT_RC=\$?" 2>/dev/null \
        | grep -o 'MOUNT_RC=[0-9]*' | cut -d= -f2
}

say "=== d513_fswide_abort_preserves_death survivor=$SURV victim=$VICTIM slot=$SLOT ==="

pre=$(node "$SURV" "$FORGE $DEV dump $SLOT")
echo "$pre" | head -2
echo "$pre" | grep -q "flags=ACTIVE" && { echo "FAIL: slot $SLOT is live"; exit 1; }
node "$SURV" "$FORGE $DEV save $SLOT $SAVE" || { echo "FAIL: save"; exit 1; }

say "--- dirtying $VICTIM's slice for ${LOAD}s"
node "$VICTIM" "mkdir -p $MNT/.d513abort; for i in \$(seq 1 64); do : > $MNT/.d513abort/t\$i; done; sync"
"$SSH" "$VICTIM" "nohup bash -c '
    D=$MNT/.d513abort
    end=\$((SECONDS + $LOAD + 60))
    while [ \$SECONDS -lt \$end ]; do touch \$D/t{1..64}; sync; done
' >/tmp/d513abortload.log 2>&1 &" >/dev/null 2>&1
sleep "$LOAD"

say "--- killing $VICTIM, then unmounting $SURV before it can recover the slice"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }
# While the survivor is still mounted and beating — see find_dead_slot.
vslot=$(find_dead_slot "$SURV")
[ -n "$vslot" ] || { echo "FAIL: victim's frozen ACTIVE slot not found"; exit 1; }
say "victim heartbeat slot = $vslot (unrelated to the forged slot $SLOT)"

node "$SURV" "dmesg --clear; umount $MNT; grep -qs ' $MNT mxfs ' /proc/mounts && echo STILL_MOUNTED || echo UNMOUNTED"

say "--- forging an FSWIDE terminal refusal into slot $SLOT"
node "$SURV" "$FORGE $DEV mkguard $SLOT --oc fswide" | tail -4

say "--- mount 1: must ABORT FSWIDE (budget ${MOUNT_BUDGET}s)"
mrc1=$(do_mount "$SURV"); : "${mrc1:=TIMEOUT}"
say "mount 1 rc=$mrc1"
dm1=$(node "$SURV" "dmesg")
echo "$dm1" | grep -E "P240-QUAR|mount ABORTED|P163-RECOVERED|slice recovery complete" | tail -10

pass=1
if [ "$mrc1" = "0" ]; then
    echo "FAIL: mount 1 admitted despite an FSWIDE terminal refusal"
    pass=0
else
    echo "OK: mount 1 refused (rc=$mrc1)"
fi
if echo "$dm1" | grep -qE "P163-RECOVERED|slice recovery complete"; then
    echo "NOTE: mount 1 completed the victim's slice before aborting — the"
    echo "      preservation assertion below cannot distinguish anything, rerun"
fi

say "--- removing the FSWIDE cause and mounting again"
node "$SURV" "dmesg --clear; $FORGE $DEV restore $SLOT $SAVE"
mrc2=$(do_mount "$SURV"); : "${mrc2:=TIMEOUT}"
say "mount 2 rc=$mrc2"
dm2=$(node "$SURV" "dmesg")
echo "$dm2" | grep -E "P233-MPHASE|P163-RECOVERED|slice recovery complete|mount recovery|slot=$vslot" | tail -15

if [ "$mrc2" != "0" ]; then
    echo "FAIL: mount 2 did not admit after the FSWIDE cause was removed (rc=$mrc2)"
    pass=0
else
    echo "OK: mount 2 admitted"
fi

# THE assertion: the death survived the abort and was acted on afterwards.
if echo "$dm2" | grep -qE "P163-RECOVERED slot=$vslot|slice recovery complete|P233-MPHASE-DISPATCH slot=$vslot|mount recovery: slot mask"; then
    echo "OK: the unrelated peer death survived the FSWIDE abort and was"
    echo "    recovered by the next mount"
else
    echo "FAIL: after the FSWIDE abort, nothing ever recovered slot $vslot —"
    echo "      the death was dropped on the abort path (sess333 stop-ship A)"
    pass=0
fi

echo "NOTE: $VICTIM is still down; re-prep before any other test."
if [ "$pass" -eq 1 ]; then
    say "=== d513_fswide_abort_preserves_death PASS ==="
    exit 0
fi
say "=== d513_fswide_abort_preserves_death FAIL ==="
exit 1
