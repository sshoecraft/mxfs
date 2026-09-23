#!/bin/bash
# tests/lazytime_timestamp_durability.sh — does a timestamp this filesystem
# ACCEPTED, on a lazytime mount, survive to the platter?
# (ledger D-LAZYTIME-TIMESTAMPS-ARE-DEFERRED-AND-THEN-NEVER-WRITTEN-BELOW-6-19)
#
# WHY IT EXISTS.  On a lazytime mount xfs_vn_update_time (pal/linux/xfs_iops.c)
# deliberately does NOT log the timestamp: it marks the inode I_DIRTY_TIME and
# returns 0, leaving the durability to a hook that runs later.  Which hook the
# VFS calls for that moved in 6.19 — inode_operations->sync_lazytime replaced
# super_operations->dirty_inode — and this fork carried only the newer one,
# gated behind `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`.  Below
# 6.19 the deferral therefore had no completion path at ALL, and the compiler
# said so: 'xfs_vn_sync_lazytime defined but not used', in a file holding four
# initialisers for it.
#
# WHY fsync IS THE SUBJECT AND NOT unmount.  vfs_fsync_range() does this before
# it calls the filesystem:
#
#     if (!datasync && (inode->i_state & I_DIRTY_TIME))
#             mark_inode_dirty_sync(inode);
#
# and mark_inode_dirty_sync is what reaches ->dirty_inode.  With no hook that
# call does nothing, XFS's own fsync then finds no dirty inode item to log, and
# fsync RETURNS 0.  So the defect is not "a timestamp is lost at unmount", it is
# "fsync reported success and did not persist what it was asked to persist" —
# an acknowledged durability violation, which is a far sharper subject and needs
# no crash to expose.
#
# WHAT THE WORKLOAD HAS TO BE, AND WHY THE OBVIOUS ONE IS WRONG.  `touch` sets
# times through utimensat -> ->setattr -> notify_change, which logs the inode
# immediately and never reaches the lazytime branch; a lap built on touch would
# pass on both builds and prove nothing.  Lazytime governs IMPLICIT updates, so
# the workload is a real write(2).  It must also be an IN-PLACE overwrite of
# already-allocated blocks: a write that extends the file or allocates changes
# the inode core for other reasons and gets the timestamp onto the platter as a
# side effect, which would hide the defect behind a passing assertion.
#
# THE ASSERTION IS READ AFTER A REMOUNT, NEVER FROM THE LIVE MOUNT.  The in-core
# timestamp is updated on both builds — that is the whole point of the deferral
# — so a stat against the live mount PASSES whether or not anything was written.
# Only a fresh read from disk distinguishes them.
#
# ARMS.  Both run; neither means anything alone.
#   control   no lazytime.  The timestamp is logged inline by the same function,
#             so it MUST survive on every build.  A control that fails means the
#             workload or the remount is wrong and the subject arm is unreadable.
#   subject   -o lazytime.  Before the fix the remounted mtime is the OLD one;
#             after it, the new one.
#
# BOUND, derived rather than chosen, and every term is a number this lap
# actually spends:
#   prep_cluster            300 s  (measured 53-137 s on this rig; the bound the
#                                  other laps in this directory give it)
#   workload                 20 s  one create, one 4 KiB in-place overwrite, two
#                                  fsyncs and one 2 s sleep to cross a whole-
#                                  second boundary.  Native XFS does the I/O in
#                                  well under a second; 20 s is past 2x with the
#                                  sleep counted.
#   2 unmount/remount       120 s  one per arm, each under the 60 s ssh bound the
#                                  code below sets
#   1 remount-with-option    30 s  the subject arm's `mount -o remount,lazytime`
#   probe/stat reads         30 s
#                          ------
#                            500 s
#
# Usage: tests/lazytime_timestamp_durability.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the node under test; the peer just stays up
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lazyts_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== lazytime_timestamp_durability label=$LABEL node=$A sv=$SV $(date -u +%FT%TZ) ==="

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ "$prc" = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

# The device under the mount, read from the node rather than assumed.
rsx 20 "$A" "grep -a ' $MNT mxfs ' /proc/mounts | awk '{print \$1}'" > "$OUT/dev.txt"
capture_require "$OUT/dev.txt" '^/dev/' "the device under $MNT on $A"
DEV=$(grep -a '^/dev/' "$OUT/dev.txt" | head -1)
echo "DEVICE node=$A dev=$DEV mnt=$MNT"

# mtime as a raw epoch-second, read from a FRESH mount every time it is used
# for a verdict.  %Y is seconds; the workload sleeps past a second boundary so
# an unchanged value cannot be mistaken for a changed one at this resolution.
remount_and_stat() {   # <arm> <file> <extra mount opts>  -> prints mtime=<n>
    local arm=$1 f=$2 opts=$3 o=""
    # The rig mounts with no options at all (`mount -t mxfs $DEV /mnt/shared`),
    # so the ONLY option this lap ever adds is the one under test, and it needs
    # its own -o.  Concatenating a bare word here would hand mount a third
    # positional argument instead of an option.
    [ -n "$opts" ] && o="-o $opts"
    rsx 60 "$A" "umount $MNT && mount -t mxfs $o $DEV $MNT && stat -c 'mtime=%Y' $f" \
        > "$OUT/${arm}_remount.txt" 2>&1
    capture_require "$OUT/${arm}_remount.txt" '^mtime=[0-9]+$' "the remount+stat for arm $arm"
    grep -ao '^mtime=[0-9]*' "$OUT/${arm}_remount.txt" | head -1
}

run_arm() {            # <arm> <mount opts for the subject remount>
    # Two statements on purpose: every word of one `local` is expanded before
    # any of its assignments lands, so a $arm in the same statement that sets
    # it reads the caller's (unset) arm and dies under set -u.
    local arm=$1 opts=$2
    local f=$MNT/lazyts_${LABEL}_${arm}
    echo "--- arm $arm (opts='${opts:-none}') at +$(el)s"

    # A 4 KiB file, allocated and durable, so the later write is an in-place
    # overwrite and changes nothing about the inode except its timestamps.
    rsx 60 "$A" "dd if=/dev/zero of=$f bs=4096 count=1 conv=fsync status=none && sync && stat -c 'base=%Y' $f" \
        > "$OUT/${arm}_base.txt" 2>&1
    capture_require "$OUT/${arm}_base.txt" '^base=[0-9]+$' "the base file for arm $arm"
    local base; base=$(grep -ao '^base=[0-9]*' "$OUT/${arm}_base.txt" | head -1 | cut -d= -f2)

    # Put the mount into the state under test.  A remount is how SB_LAZYTIME is
    # set without disturbing anything else, and /proc/mounts is asked to confirm
    # it rather than the mount command's exit status — the flag is the entire
    # precondition of this arm and an arm that silently did not get it would
    # report the control's answer under the subject's name.
    if [ -n "$opts" ]; then
        rsx 30 "$A" "mount -o remount,$opts $MNT && grep -a ' $MNT mxfs ' /proc/mounts" \
            > "$OUT/${arm}_optset.txt" 2>&1
        capture_require "$OUT/${arm}_optset.txt" " $MNT mxfs " "the remount that sets '$opts' on $A"
        if grep -aq 'lazytime' "$OUT/${arm}_optset.txt"; then
            echo "  PASS /proc/mounts confirms the mount carries lazytime"
        else
            echo "ABORT: the remount returned success but /proc/mounts does not show lazytime — this arm cannot measure its subject"
            sed 's/^/    /' "$OUT/${arm}_optset.txt" | cut -c1-200
            echo "RESULT: ABORT label=$LABEL stage=arm-$arm evidence=$OUT"; exit 2
        fi
    fi

    # Cross a whole-second boundary so a %Y that did not move is unambiguous,
    # then overwrite in place and fsync.  fsync's return code is itself one of
    # the findings: the defect is that it reports success.
    # THE WRITE RUNS DETACHED AND IS WAITED FOR, BECAUSE ON s140a IT DID NOT
    # COME BACK.  A 4 KiB in-place overwrite plus fsync is a millisecond on
    # native XFS; the subject arm's took more than 60 s and the ssh that carried
    # it was killed at its bound, leaving only "rc=124" and nothing about WHERE
    # the task was.  So the dd is started on the node with its pid recorded and
    # polled for up to 30 s (a 4 KiB write+fsync at 2x native is nowhere near
    # it; 30 s is the ssh/poll grain); if it is still there, its kernel stack
    # and the tail of the ring are captured and the arm is a FAIL for a hang —
    # a stability finding of this record, not an abort of the lap.
    rsx 60 "$A" "sleep 2; rm -f /run/lazyts.out; (dd if=/dev/urandom of=$f bs=4096 count=1 conv=notrunc,fsync status=none; echo fsync_rc=\$? > /run/lazyts.out) </dev/null >/dev/null 2>&1 &
p=\$!
for i in \$(seq 1 30); do [ -s /run/lazyts.out ] && break; sleep 1; done
if [ -s /run/lazyts.out ]; then
    cat /run/lazyts.out; stat -c 'incore=%Y' $f
else
    echo HUNG_AFTER_S=\$i
    for t in /proc/\$p /proc/\$p/task/* \$(ls -d /proc/[0-9]* | head -0); do :; done
    for c in \$(ls /proc/[0-9]*/comm 2>/dev/null); do d=\${c%/comm}; [ \"\$(cat \$c 2>/dev/null)\" = dd ] && { echo \"STACK pid=\${d#/proc/} state=\$(awk '{print \$3}' \$d/stat)\"; cat \$d/stack; }; done
    dmesg | tail -30
fi" > "$OUT/${arm}_write.txt" 2>&1
    if grep -aq '^HUNG_AFTER_S=' "$OUT/${arm}_write.txt"; then
        echo "  FAIL arm $arm: the 4 KiB in-place overwrite + fsync did not return within 30 s (native XFS: milliseconds) — a hang on ${opts:-a plain} mount; the task's kernel stack and the ring's tail are in $OUT/${arm}_write.txt"
        sed -n '/^STACK /,$p' "$OUT/${arm}_write.txt" | grep -a '^STACK \|^\[<' | head -14 | sed 's/^/      /'
        fails=$((fails+1))
        echo "RESULT: FAIL label=$LABEL stage=arm-$arm-hang fails=$fails wall=$(el)s evidence=$OUT"; exit 1
    fi
    capture_require "$OUT/${arm}_write.txt" '^incore=[0-9]+$' "the in-place overwrite for arm $arm"
    local frc; frc=$(grep -ao 'fsync_rc=[0-9]*' "$OUT/${arm}_write.txt" | head -1 | cut -d= -f2)
    local incore; incore=$(grep -ao '^incore=[0-9]*' "$OUT/${arm}_write.txt" | head -1 | cut -d= -f2)
    ck "arm $arm: the write and its fsync reported success" "${frc:-x}" 0

    # The control that makes the verdict readable: the in-core timestamp DID
    # move.  If it did not, the workload never updated a timestamp at all and
    # whatever the platter says afterwards is not about durability.
    if [ "${incore:-0}" -gt "${base:-0}" ]; then
        echo "  PASS arm $arm: the in-core mtime advanced across the write ($base -> $incore)"
    else
        echo "ABORT: arm $arm: the in-core mtime did not move across the write ($base -> $incore); the workload did not update a timestamp and this arm measures nothing"
        echo "RESULT: ABORT label=$LABEL stage=arm-$arm evidence=$OUT"; exit 2
    fi

    local after; after=$(remount_and_stat "$arm" "$f" "$opts")
    after=${after#mtime=}
    echo "STAGE arm $arm: base=$base incore=$incore after_remount=$after"

    if [ "$after" = "$incore" ]; then
        echo "  PASS arm $arm: the fsynced timestamp survived the remount"
    elif [ "$after" = "$base" ]; then
        echo "  FAIL arm $arm: fsync returned 0 and the timestamp was NOT persisted — the remounted inode still carries the pre-write mtime ($base); the update was acknowledged and lost"
        fails=$((fails+1))
    else
        echo "  FAIL arm $arm: the remounted mtime ($after) is neither the pre-write value ($base) nor the acknowledged one ($incore) — unexplained, and not a pass"
        fails=$((fails+1))
    fi
}

# The control goes first: an arm whose control has not passed cannot be read.
run_arm control ""
run_arm subject "lazytime"

# The module's own statement that the hook exists at all.  It is one-shot per
# load and belongs to the mapping-revalidation work, not here, so it is recorded
# as corroboration and never asserted.
rsx 20 "$A" "dmesg | grep -ac 'P312-IOMAP-REVALIDATED' || true" > "$OUT/probe.txt" 2>&1

echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
fi
exit $(( fails > 0 ))
