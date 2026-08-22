#!/bin/bash
# d513_lone_mount_refusal.sh — sess333 pre-disposition CHECK 5 for
# D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513:
#
#   "a lone-node torn mount publishes TERMINAL_REFUSED and returns -EIO"
#
# This is the case sess333 stop-ship D was written for.  The reap path publishes
# refusals; the MOUNT path did not.  A lone survivor cold-starting over a dirty
# victim slice would refuse the replay, publish NOTHING, fail -EBUSY and restart
# forever, with no operator-facing quarantine ever reaching the platter — the
# D-513 shape, reached from the other direction.
#
# Staging (requires a TWO-node cluster: ./run.sh 2 caw prep_cluster):
#   1. dirty the victim's journal slice with pure inode-item churn
#   2. kill the victim
#   3. unmount the survivor IMMEDIATELY, before its ~62 s dead-confirm window
#      elapses — so nobody recovers the slice and the next mount is a genuine
#      cold start over unreplayed foreign state
#   4. arm the forced-refusal knob and mount the survivor alone
#   5. assert: the mount REFUSES (rc != 0), a TERMINAL_REFUSED outcome record
#      is DURABLE in the victim's heartbeat sector, and the slice was never
#      published as recovered
#
# The filesystem is left carrying a durable quarantine — re-prep before any
# other test.
#
# Usage: tests/d513_lone_mount_refusal.sh [survivor] [victim] [shape]
#   shape 4 = genuine mid-replay TORN (default), 3 = forged post-success TORN,
#         1 = POLICY ag0, 2 = POLICY fswide
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
FORGE=/src/mxfs/tools/recov_forge
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

SURV="${1:-test1}"
VICTIM="${2:-test2}"
SHAPE="${3:-4}"
LOAD="${LOAD:-20}"
TORN_ITEMS="${TORN_ITEMS:-3}"

# RULE 0 budget for the lone mount: the barrier pays the full dead-confirm
# window for a peer that was already frozen when we mounted (dead_threshold x
# hb interval ~= 62 s, TIMEOUT_BUDGETS.md), plus fence, plus the replay it is
# about to refuse, plus the publish.  Measured clean mounts are 5-7 s; this one
# is dominated by the 62 s confirm.  150 s covers it with margin; beyond that
# it is a wedge, not a slow success.
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


say "=== d513_lone_mount_refusal survivor=$SURV victim=$VICTIM shape=$SHAPE ==="

active_before=$(node "$SURV" "$FORGE $DEV dump" | grep "flags=ACTIVE" | sed -n 's/^slot=\([0-9]*\) .*/\1/p' | tr '\n' ' ')
say "ACTIVE slots before: $active_before"

say "--- dirtying $VICTIM's slice for ${LOAD}s (pure inode-item churn)"
node "$VICTIM" "mkdir -p $MNT/.d513lone; for i in \$(seq 1 64); do : > $MNT/.d513lone/t\$i; done; sync"
"$SSH" "$VICTIM" "nohup bash -c '
    D=$MNT/.d513lone
    end=\$((SECONDS + $LOAD + 60))
    while [ \$SECONDS -lt \$end ]; do touch \$D/t{1..64}; sync; done
' >/tmp/d513lone.log 2>&1 &" >/dev/null 2>&1
sleep "$LOAD"
seen=$(node "$SURV" "ls $MNT/.d513lone 2>/dev/null | wc -l" | tail -1 | tr -d '[:space:]')
say "victim load visible from $SURV: ${seen:-0} files"
[ "${seen:-0}" -gt 0 ] || { echo "FAIL: victim load never landed"; exit 1; }

say "--- killing $VICTIM"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy"; exit 1; }

# Identify the victim's slot NOW, while the survivor is still mounted and
# heartbeating: that is what makes the two-sample test discriminating.  After
# the survivor unmounts, BOTH records are frozen and "unchanged" no longer
# means "dead".
vslot=$(find_dead_slot "$SURV")
if [ -z "$vslot" ]; then
    echo "FAIL: could not identify a frozen ACTIVE slot after the kill — the"
    echo "      victim's slot should still carry its stale ACTIVE heartbeat"
    node "$SURV" "$FORGE $DEV dump" | grep "flags=ACTIVE"
    exit 1
fi
say "victim heartbeat slot = $vslot"

say "--- unmounting $SURV immediately (no survivor may recover the slice)"
node "$SURV" "dmesg --clear; umount $MNT; echo umount_rc=\$?; grep -qs ' $MNT mxfs ' /proc/mounts && echo STILL_MOUNTED || echo UNMOUNTED"

say "--- arming freplay_force_refusal=$SHAPE on $SURV and mounting it ALONE"
node "$SURV" "echo $SHAPE > /sys/module/mxfs/parameters/freplay_force_refusal;
              echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
              echo $TORN_ITEMS > /sys/module/mxfs/parameters/freplay_force_torn_items;
              cat /sys/module/mxfs/parameters/freplay_force_refusal"

t0=$(date +%s)
mrc=$(timeout "$MOUNT_BUDGET" "$SSH" "$SURV" \
        "mount -t mxfs $DEV $MNT >/tmp/d513lonemount.log 2>&1; echo MOUNT_RC=\$?" 2>/dev/null \
        | grep -o 'MOUNT_RC=[0-9]*' | cut -d= -f2)
t1=$(date +%s)
: "${mrc:=TIMEOUT}"
say "lone mount rc=$mrc wall=$((t1 - t0))s"

say "--- victim slot $vslot on the platter"
dumpout=$(node "$SURV" "$FORGE $DEV dump $vslot")
echo "$dumpout"

say "--- survivor dmesg"
dm=$(node "$SURV" "dmesg")
echo "$dm" | grep -E "P227-FR|P241-RECOV|P240-QUAR|slice replay refused|terminal outcome PUBLISHED|mount ABORTED|published as recovered|slice recovery complete" | tail -25

pass=1

# (a) the mount must refuse
if [ "$mrc" = "0" ]; then
    echo "FAIL: the lone mount ADMITTED over a slice whose replay was refused"
    pass=0
else
    echo "OK: lone mount refused (rc=$mrc)"
fi

# (b) the verdict must be DURABLE on the platter, not just logged
if echo "$dumpout" | grep -q "outcome=1 "; then
    echo "OK: TERMINAL_REFUSED outcome record is durable in slot $vslot"
else
    echo "FAIL: no durable TERMINAL_REFUSED record — the mount path refused"
    echo "      the replay without publishing anything (the sess333 item D shape)"
    pass=0
fi
if echo "$dumpout" | grep -q "crc=BAD"; then
    echo "FAIL: the published record does not validate"
    pass=0
fi

# (c) the refused slice must never be announced as recovered
if echo "$dm" | grep -qE "published as recovered|slice recovery complete"; then
    echo "FAIL: a refused slice was published as recovered"
    pass=0
else
    echo "OK: refused slice was not published as recovered"
fi

say "--- disarming the knob"
node "$SURV" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
              echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null

echo "NOTE: the filesystem now carries a durable quarantine and $VICTIM is down."
echo "      Re-prep (./run.sh <N> caw prep_cluster) before any other test."
if [ "$pass" -eq 1 ]; then
    say "=== d513_lone_mount_refusal PASS (shape=$SHAPE) ==="
    exit 0
fi
say "=== d513_lone_mount_refusal FAIL (shape=$SHAPE) ==="
exit 1
