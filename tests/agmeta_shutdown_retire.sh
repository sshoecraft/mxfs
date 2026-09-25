#!/bin/bash
# agmeta_shutdown_retire.sh — the AG-meta track hold must be returned on the
# ONE retirement route that no completion and no reclaim covers.  Two-node TCP.
#
# Every AG-metadata buffer logged on a node takes a one-shot token, an extra
# buffer reference and a per-AG pending count (mxfs_ag_meta_track), and exactly
# one of the write completion or a reclaim gives them back.  xfs_buf_item_free
# has a single caller, xfs_buf_item_relse, so that funnel's call sites are the
# complete list of ways a tracked log item can retire.  Three of them cannot
# leave the token outstanding: the completion route consumes it in the next
# call, the stale route reclaims first, and the clean route only ever sees an
# item that was never dirtied and so was never tracked.
#
# xfs_buf_item_put is the fourth, and nothing on it returns the hold.  It frees
# a DIRTY log item that is not in the AIL, which is reachable only once the log
# has shut down and a checkpoint aborted the item instead of inserting it —
# typically where a btree cursor still held a clean reference and dropped it
# through xfs_trans_brelse.  The leaked reference pins the buffer for the life
# of the module; a pinned buffer leaves the buftarg LRU when it is staled but
# stays hashed in its AG cache, and the unmount drain walks only the LRU, so it
# is invisible until the slab shutdown counts it at rmmod.
#
# A healthy mount CANNOT reach that route — three clean laps of
# agmeta_stale_leak_2node.sh on 0.75.95 fired the probe zero times, which is
# what the code says must happen.  So this harness makes the shutdown happen:
# it grows and collapses one AG's free-space btrees, then fails the next log
# write completions with -EIO (mxfs.log_inject_ioerr) while those buffers are
# dirty.  The verdict is NON-VACUITY FIRST — if the put route is not taken, the
# run proves nothing about the fix and says so rather than passing.
#
# Scored, in order: the injected shutdown actually happened; the put route was
# actually taken (P-AGMETA-RELSE-OUTSTANDING why=put); every one of those was
# reclaimed (P-AGMETA-RECLAIM why=put); the mxfs_ag_meta_track tripwire stayed
# silent; and rmmod left no objects in the mxfs_buf slab, which is the symptom
# the whole record is about.
#
# the budget rule (derived, from the s596a-c laps): the churn is now DURATION-bounded at
# 8 s by construction (s596c did 1024 ops in 707 ms, which is exactly why a
# fixed count could not be armed against); withdrawal settle bounded at 20 s and
# observed at 20 s; four dmesg captures ~6 s; umount measured 5.6 s and rmmod
# ~2 s; A's rejoin mount behind a live peer measured at ~3 s.  Healthy wall
# ~70 s (s596b/c ran 60 s with a 0.5 s churn).  Per-step bounds below are each
# derived from that step, not from a round number.
#
# Usage: tests/agmeta_shutdown_retire.sh <label> [PUNCHES=1024]
# Env:   MXFS_NODE_LIST (default test1,test2; A is shut down, B stays mounted),
#        MXFS_DEV, MNT=/mnt/shared, KO=/src/mxfs/mxfs.ko (A's module for the
#        rejoin, seen over NFS), WORKERS, DURATION, ARM_AFTER, SYNC_EVERY.
set -u
LABEL=${1:?label}
PUNCHES=${2:-1024}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
# The nodes see the source tree over NFS and prep insmods the tree's .ko from
# there (tools/prep_node.sh MODULE=/src/mxfs/mxfs.ko).  /tmp/mxfs.ko does NOT
# exist on these nodes -- s596b/c/d all failed their rejoin with mount_rc=32
# ("unknown filesystem type") because the insmod before it had silently failed.
KO=${KO:-/src/mxfs/mxfs.ko}
# Worker counters must NOT live on the filesystem under test.  s596d wrote them
# to $D and read back ops=0 from all eight workers: the mount had shut down by
# then, so every counter write failed and the run reported "no operations" for a
# churn that had in fact run its full 8 s (wall_ms=7735).  An instrument stored
# inside the fault it is measuring records nothing.
CNT=/tmp/agshut_$LABEL
D=$MNT/agshut_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_agshut_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')

echo "=== agmeta_shutdown_retire label=$LABEL A=$A B=$B punches=$PUNCHES tree_sv=$SV $(date -u +%FT%TZ) ==="
s=$(date +%s)
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')"
done
ck "both nodes mounted with the tree build" \
   "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion"; done | tr -d '\n')" \
   "1${SV}1${SV}"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }

# A's module parameters have to be replayed on the rejoin insmod or A comes
# back on a different transport than the cluster it is joining.
PARAMS=$(rs 20 "$A" "for p in force_transport target_cache_protected; do v=\$(cat /sys/module/mxfs/parameters/\$p 2>/dev/null); [ -n \"\$v\" ] && echo -n \"\$p=\$v \"; done")
# A KNOB UNDER TEST MUST SURVIVE THE REJOIN'S INSMOD, OR THE LAP DOES NOT TEST IT.
# MXFS_PRECHURN_KNOBS sets sysfs on the LIVE mount, which is right for anything
# the CHURN must observe — but this harness rmmods and insmods A between the
# churn and the end of the lap, and insmod resets every parameter to its
# compiled default.  Any operation AFTER the rejoin (notably the closing
# `rm -rf $D`, which is the free whose durability D-0946 turns on) therefore runs
# with the knob back at its default.  A ten-lap run was lost to exactly that:
# every lap reported the knob read back as 1, and every lap's free ran at 0.
# MXFS_EXTRA_INSMOD_PARAMS is appended to the rejoin insmod line so a knob can
# span the reload.  Set BOTH when a knob must hold for the whole lap.
if [ -n "${MXFS_EXTRA_INSMOD_PARAMS:-}" ]; then
    PARAMS="$PARAMS $MXFS_EXTRA_INSMOD_PARAMS"
fi
echo "  INFO $A insmod params for the rejoin: ${PARAMS:-none}"

MK="AGSHUT-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

# Stage 1+2 (A), ONE remote script: the shutdown has to land INSIDE the btree
# churn, not after it.
#
# The first cut armed the injection and then ran `rm`, and it did shut the
# filesystem down -- but on the SYNC, long after every free-extent transaction
# had committed, so no btree cursor held a clean reference to a tracked buffer
# and the put route was never taken (s596a: put_probe=0).  The unlink itself
# returned in 12 ms because the extent freeing is deferred; there was nothing
# in flight to abort.
#
# The window is narrower than "shut down during btree work", and reading
# xfs_buf_item_put's own comment says why.  It needs a buffer logged and
# committed by one transaction, a checkpoint that ABORTS that item instead of
# inserting it into the AIL, and a DIFFERENT transaction holding a clean
# reference to the same buffer which then drops it through xfs_trans_brelse --
# brelse early-returns on XFS_LI_DIRTY, so the transaction that logged the
# buffer can never be the one that puts it.  A single-threaded loop cannot
# produce that: there is no second transaction in flight when the abort lands.
#
# So punch from CONCURRENT workers over interleaved strides of the same file,
# contending on one AG's bnobt/cntbt, and arm the injection from the parent
# shell once they are all running.  The abort then lands with several
# transactions mid-flight holding clean references to buffers their siblings
# logged.  Punches failing after the shutdown are EXPECTED -- that is the arm
# working, not a harness fault.
# AND the workers must FORCE THE LOG as they go.  s596b armed the injection
# 0.4 s into the churn and still shut down on the closing sync: punch_errs=0,
# i.e. all 1024 punches succeeded.  fallocate -p lands its transaction in the
# CIL and forces no iclog write, and the injection lives at iclog write
# COMPLETION -- so with nothing forcing the log there was no write to fail
# until the final sync, which is the same too-late shutdown s596a had.  Each
# worker now syncs every SYNC_EVERY punches, so iclog writes are continuous
# and the failure lands inside the churn.
#
# The workers also COLLAPSE the trees, not just split them.  The first cut got
# its merges from the `rm` that the restructure dropped, which is why s596b
# logged zero P-AGMETA-RECLAIM of any kind: the trees only ever grew.  Half the
# workers punch (split) and half re-fill their stride with a write (merge), so
# blocks are being freed and invalidated while the log is dying.
# AND the churn must still be RUNNING when the injection is armed.  s596c added
# the log forces and still shut down on the closing sync: op_errs=0, left=3,
# P-LOG-INJECT-IOERR fired exactly once.  The parent's `sleep 0.4` runs
# CONCURRENTLY with the backgrounded workers, and 1024 ops across 8 workers
# finish in well under 400 ms -- so by the time the knob was written the churn
# was over, `wait` returned at once, and the only iclog write left to fail was
# the final sync.  All three laps died in the same place for this reason.
#
# A fixed op count cannot be made reliable here: the arm has to win a race
# against a workload whose duration is not controlled.  So the workers run to a
# DEADLINE instead, and the parent arms well inside it.  Overlap is then
# structural rather than a timing bet.
# RUNTIME KNOBS, SET AFTER THE MOUNT AND BEFORE THE CHURN.
# A knob passed as an insmod modarg does not survive this harness's own
# rmmod/insmod rejoin, and a knob set by a separate prep does not survive into
# the run that follows it -- both have silently turned a knob-off arm into a
# knob-on one on this rig before.  These are 0644 parameters, so setting them
# here, on the live mount, immediately before the workload that must observe
# them, is the only placement that cannot be undone by a reload in between.
# The value read BACK is what gets reported, never the value requested.
# Usage: MXFS_PRECHURN_KNOBS="ifree_eager_durable=1 foo=0" tests/agmeta_...
if [ -n "${MXFS_PRECHURN_KNOBS:-}" ]; then
    kset=$(rs 30 "$A" "for kv in $MXFS_PRECHURN_KNOBS; do k=\${kv%%=*}; v=\${kv#*=}; echo \$v > /sys/module/mxfs/parameters/\$k 2>/dev/null; echo -n \"\$k=\$(cat /sys/module/mxfs/parameters/\$k 2>/dev/null || echo MISSING) \"; done")
    echo "  INFO prechurn knobs on $A (read back): $kset"
    for kv in $MXFS_PRECHURN_KNOBS; do
        case "$kset" in
            *"$kv"*) ;;
            *) echo "  FAIL prechurn knob '$kv' did not take (read back: $kset)"; fails=$((fails+1)) ;;
        esac
    done
fi

WORKERS=${WORKERS:-8}
SYNC_EVERY=${SYNC_EVERY:-8}
DURATION=${DURATION:-8}
ARM_AFTER=${ARM_AFTER:-2}
rs 180 "$A" "mkdir -p $D && fallocate -l 8M $D/f && sync -f $MNT && s=\$(date +%s%N); deadline=\$(( \$(date +%s) + $DURATION )); for k in \$(seq 0 $(( WORKERS - 1 ))); do ( i=\$k; e=0; n=0; while [ \$(date +%s) -lt \$deadline ]; do if [ \$(( k % 2 )) = 0 ]; then fallocate -p -o \$(( i * 8192 )) -l 4096 $D/f 2>/dev/null || e=\$((e+1)); else dd if=/dev/zero of=$D/f bs=4096 count=1 seek=\$(( i * 2 )) conv=notrunc status=none 2>/dev/null || e=\$((e+1)); fi; n=\$((n+1)); [ \$(( n % $SYNC_EVERY )) = 0 ] && { sync -f $MNT 2>/dev/null || e=\$((e+1)); }; i=\$(( i + $WORKERS )); [ \$i -ge $PUNCHES ] && i=\$k; done; echo \"\$n \$e\" > $CNT.perr\$k ) & done; sleep $ARM_AFTER; armed_at=\$(( \$(date +%s%N) / 1000000 )); echo 4 > /sys/module/mxfs/parameters/log_inject_ioerr; armrc=\$?; wait; ops=0; perr=0; for k in \$(seq 0 $(( WORKERS - 1 ))); do set -- \$(cat $CNT.perr\$k 2>/dev/null || echo '0 0'); ops=\$(( ops + \$1 )); perr=\$(( perr + \$2 )); done; sync -f $MNT 2>/dev/null; syncrc=\$?; ee=\$(date +%s%N); echo A_CHURN workers=$WORKERS duration=${DURATION}s arm_after=${ARM_AFTER}s sync_every=$SYNC_EVERY arm_rc=\$armrc ops=\$ops op_errs=\$perr sync_rc=\$syncrc wall_ms=\$(( (ee - s) / 1000000 )) left=\$(cat /sys/module/mxfs/parameters/log_inject_ioerr)" > "$OUT/churn_$A.txt"
echo "  INFO $(tr '\n' ' ' < "$OUT/churn_$A.txt")"
# The withdrawal declares voluntary death and freezes grants until the peer has
# replayed the slice; unmounting into that window is what returned EBUSY in 3 ms
# on s596a.  Wait for the withdrawal to finish before tearing the mount down.
rs 60 "$A" "for i in \$(seq 1 20); do dmesg | grep -aq 'P-WITHDRAW-DONE\|P163-RECOVERY-COMPLETE\|withdrawal complete' && break; sleep 1; done; echo SETTLED after=\${i}s" > "$OUT/settle_$A.txt"
echo "  INFO $(tr '\n' ' ' < "$OUT/settle_$A.txt")"
rs 45 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -av '$NOISE'" > "$OUT/dmesg_shut_$A.txt"

shut=$(grep -ac 'P-LOG-INJECT-IOERR\|shut down due to log error\|Log I/O Error\|log I/O error' "$OUT/dmesg_shut_$A.txt")
put_probe=$(grep -a 'P-AGMETA-RELSE-OUTSTANDING' "$OUT/dmesg_shut_$A.txt" | grep -ac 'why=put')
put_recl=$(grep -a 'P-AGMETA-RECLAIM' "$OUT/dmesg_shut_$A.txt" | grep -ac 'why=put')
oth_probe=$(grep -a 'P-AGMETA-RELSE-OUTSTANDING' "$OUT/dmesg_shut_$A.txt" | grep -avc 'why=put')
trip=$(grep -ac 'mxfs_ag_meta_track+' "$OUT/dmesg_shut_$A.txt")
echo "  AGSHUT-MEASURE $LABEL shutdown_lines=$shut put_probe=$put_probe put_reclaim=$put_recl other_route_probe=$oth_probe tripwire=$trip"
grep -a 'P-AGMETA-RELSE-OUTSTANDING' "$OUT/dmesg_shut_$A.txt" | head -3 | cut -c1-190 | sed 's/^/      /'

ops=$(grep -ao 'ops=[0-9]*' "$OUT/churn_$A.txt" | head -1 | cut -d= -f2)
operr=$(grep -ao 'op_errs=[0-9]*' "$OUT/churn_$A.txt" | head -1 | cut -d= -f2)
# A SHUTDOWN BY AN UNEXPECTED ROUTE IS A FINDING, NOT A VACUITY.  Scoring this
# purely on the log-error text made two D-0946 laps (the filesystem died of an
# EFSCORRUPTED dirty trans_cancel in xfs_create before the injection could fire)
# read as "no shutdown", i.e. as laps that had failed to do anything -- which is
# the opposite of what happened and buried a critical defect for a session.
# Name the other route explicitly so it cannot hide inside a vacuity again.
othershut=$(grep -ac 'P-CR3-CANCEL\|Internal error xfs_trans_cancel\|Corruption of in-memory data' "$OUT/dmesg_shut_$A.txt")
if [ "$shut" -lt 1 ] && [ "$othershut" -ge 1 ]; then
    echo "  FAIL A's filesystem shut down by an UNEXPECTED route before the injected error fired ($othershut line(s)) — this lap is not vacuous, it found something"
    grep -a 'P-CR3-CANCEL\|P-CR62 \|P-RECYCLE-GATE \|Internal error' "$OUT/dmesg_shut_$A.txt" \
         | head -5 | cut -c1-190 | sed 's/^/      /'
    fails=$((fails+1))
fi
ck "the injected log error shut A's filesystem down" "$( [ "$shut" -ge 1 ] && echo 1 || echo 0)" "1"
# Three laps (s596a/b/c) shut the filesystem down on the CLOSING SYNC, after the
# churn had finished -- which is precisely the state that cannot reach the put
# route, because nothing was in flight to abort.  op_errs is how that is caught:
# if the shutdown lands mid-churn, the workers' own operations start failing.
# op_errs=0 with a shutdown present means the arm fired too late, and the run
# must say so rather than quietly reporting put_probe=0 as a result.
ck "the shutdown landed INSIDE the churn (workers' ops failed), not on the closing sync" \
   "$( [ "${operr:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
echo "  INFO churn ops=${ops:-?} op_errs=${operr:-?} — op_errs=0 with a shutdown present means the injection was armed after the workers finished"
# NON-VACUITY: without this the rest of the run says nothing about the fix.
# A shutdown that landed inside the churn and still did not abort a committed
# item through xfs_buf_item_put is the trigger not reached: the run proves
# nothing about the route, and says so as VACUOUS (exit 3), not as a FAIL
# about MXFS — the s59h gate lap scored this as a defect with nothing
# measured (ops=6893 op_errs=6547 put_probe=0).
vacuous=0
if [ "$put_probe" -ge 1 ]; then
    echo "  PASS NON-VACUOUS: the xfs_buf_item_put retirement route was actually taken ($put_probe)"
else
    echo "  VACUOUS: the xfs_buf_item_put retirement route was not taken (put_probe=0) — the injected shutdown aborted no committed AG-meta item; nothing about the route was measured"
    vacuous=1
fi
ck "every put-route retirement returned its AG-meta track hold" "$( [ "$put_probe" = "$put_recl" ] && echo 1 || echo 0)" "1"
ck "the mxfs_ag_meta_track tripwire stayed silent on A" "$trip" "0"

# D-0945: the inode FREE path is the one release primitive that released a
# durable TCP grant while the session was POISONED.  P945-INO-FREE-RELEASE is
# emitted by that path in BOTH arms of the poison_gate_ino_free knob, so
# "gated=0" is a line the control arm PRINTS rather than a line the fix arm
# merely lacks -- without it, no-refusal and no-free-at-all read the same.
inofree=$(grep -ac 'P945-INO-FREE-RELEASE ' "$OUT/dmesg_shut_$A.txt")
inofree_gated=$(grep -a 'P945-INO-FREE-RELEASE ' "$OUT/dmesg_shut_$A.txt" | grep -ac 'gated=1')
inofree_ungated=$(grep -a 'P945-INO-FREE-RELEASE ' "$OUT/dmesg_shut_$A.txt" | grep -ac 'gated=0')
inofree_refused=$(grep -ac 'P-TCP-RELEASE-POISONED ino-free=' "$OUT/dmesg_shut_$A.txt")
echo "  INOFREE-MEASURE $LABEL poisoned_frees=$inofree gated=$inofree_gated ungated=$inofree_ungated refusals=$inofree_refused"
grep -a 'P945-INO-FREE-RELEASE \|P-TCP-RELEASE-POISONED ino-free=' "$OUT/dmesg_shut_$A.txt" \
     | head -4 | cut -c1-190 | sed 's/^/      /'
{ echo "poisoned_frees=$inofree gated=$inofree_gated ungated=$inofree_ungated refusals=$inofree_refused"
  grep -a 'P945-INO-FREE-RELEASE \|P-TCP-RELEASE-POISONED ino-free=' "$OUT/dmesg_shut_$A.txt"
} > "$OUT/inofree_$A.txt"
# Only assertable when the route was actually taken.  A lap that froze no inode
# after the shutdown says nothing about this defect and must not claim to.
if [ "$inofree" -ge 1 ]; then
    ck "every poisoned free-path release was refused (D-0945)" \
       "$inofree_gated=$inofree_refused" "$inofree=$inofree"
else
    echo "  INFO D-0945 not exercised this lap: no inode was freed while the session was poisoned"
fi

# Stage 3: the symptom itself.  Unload A and count what the slab still holds.
# umount's error text is the diagnosis when it refuses, so capture it rather
# than discarding it -- s596a returned rc=1 in 3 ms with the reason thrown away.
rs 200 "$A" "t0=\$(date +%s%N); uerr=\$(mountpoint -q $MNT && timeout 90 umount -f $MNT 2>&1); urc=\$?; if [ \$urc != 0 ]; then sleep 5; uerr2=\$(timeout 90 umount -f $MNT 2>&1); urc=\$?; uerr=\"\$uerr | retry: \$uerr2\"; fi; t1=\$(date +%s%N); lsmod | grep -q '^mxfs ' && { rerr=\$(timeout 40 rmmod mxfs 2>&1); rrc=\$?; }; sleep 2; echo UNLOAD umount_rc=\$urc umount_ms=\$(( (t1 - t0) / 1000000 )) rmmod_rc=\$rrc loaded=\$(lsmod | grep -c '^mxfs '); echo UNLOAD-ERR umount=[\$uerr] rmmod=[\${rerr:-}]; dmesg | sed -n '/$MK/,\$p' | grep -av '$NOISE'" > "$OUT/unload_$A.txt"
echo "  INFO $(grep -a '^UNLOAD ' "$OUT/unload_$A.txt" | head -1)"
echo "  INFO $(grep -a '^UNLOAD-ERR ' "$OUT/unload_$A.txt" | head -1 | cut -c1-200)"
slab=$(grep -ac 'Objects remaining\|Slab cache still has objects\|kmem_cache_destroy\|BUG mxfs_buf' "$OUT/unload_$A.txt")
bcache=$(grep -ac 'P-BCACHE-LEFT' "$OUT/unload_$A.txt")
warn=$(grep -ac 'WARNING:\|BUG:\|Oops\|Internal error\|Corruption\|xg_ref\|use-after-free\|KASAN' "$OUT/unload_$A.txt")
echo "  UNLOAD-MEASURE $LABEL slab_leak_lines=$slab bcache_left=$bcache warn_lines=$warn"
[ "$slab$bcache$warn" != "000" ] && grep -a -B2 -A14 'Objects remaining\|Slab cache\|P-BCACHE-LEFT\|WARNING:\|Internal error' "$OUT/unload_$A.txt" | cut -c1-180 | head -40 | sed 's/^/      /'
ck "$A: unmounted and unloaded" "$(grep -ao 'umount_rc=[0-9]*' "$OUT/unload_$A.txt" | head -1)_$(grep -ao 'loaded=[0-9]*' "$OUT/unload_$A.txt" | head -1)" "umount_rc=0_loaded=0"
ck "$A: no object left in the mxfs_buf slab at unload" "$slab" "0"
ck "$A: no buffer left in an AG buffer cache at teardown" "$bcache" "0"
ck "$A: no kernel warning or corruption line in the unload window" "$warn" "0"

# Stage 4: restore.  B held the filesystem throughout; A rejoins behind it.
rs 200 "$A" "modprobe libcrc32c 2>/dev/null; insmod $KO dyndbg=+p $PARAMS && echo INSMOD_OK sv=\$(cat /sys/module/mxfs/srcversion); mkdir -p $MNT; t0=\$(date +%s%N); timeout 150 mount -t mxfs $MXFS_DEV $MNT; mrc=\$?; t1=\$(date +%s%N); echo REJOIN mount_rc=\$mrc mount_ms=\$(( (t1 - t0) / 1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)" > "$OUT/rejoin_$A.txt"
echo "  INFO $(grep -a 'INSMOD_OK\|^REJOIN ' "$OUT/rejoin_$A.txt" | tr '\n' ' ')"
# sess567: CAPTURE THE REJOIN WINDOW.  This assertion had no evidence behind it
# — only the exit code — so when it failed (round 1 of the s568alt alternating
# run: mount_rc=32 after 3163 ms, while round 2 rejoined clean) there was
# nothing to diagnose it from and the lap had to be thrown away.  A refused
# mount fails FAST, so the reason is in the node's own log and in the peer's;
# pull both, and the platter that decides admission.
rs 60 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -av '$NOISE' | tail -160" > "$OUT/rejoin_dmesg_$A.txt" 2>/dev/null
rs 60 "$B" "dmesg | tail -80" > "$OUT/rejoin_dmesg_$B.txt" 2>/dev/null
rs 60 "$B" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV 2>&1 | head -20" > "$OUT/rejoin_hb.txt" 2>/dev/null
ck "$A rejoined the cluster with no operator action" "$(grep -ao 'mount_rc=[0-9]* ' "$OUT/rejoin_$A.txt" | head -1 | tr -d ' ')" "mount_rc=0"
if ! grep -aq 'mount_rc=0 ' "$OUT/rejoin_$A.txt"; then
    echo "    REJOIN-REFUSED — the reason, from $A's own log:"
    grep -aE 'P-ADMIT|P236|P238|P163|REFUS|refus|EPERM|NOT replayed|quarantin|cannot|failed' \
         "$OUT/rejoin_dmesg_$A.txt" 2>/dev/null | tail -10 | cut -c1-190 | sed 's/^/      /'
fi
value_now_into rv1 "$B" 20 "$OUT/rv_rv1_1.txt" '^[0-9]+$' "rv1 on $B" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
ck "$B never lost its mount" "$rv1" "1"
rs 30 "$B" "dmesg | sed -n '/$MK/,\$p' | grep -av '$NOISE'" > "$OUT/dmesg_$B.txt"
ck "$B stayed healthy while A was shut down and away" \
   "$(grep -aic 'corruption\|BUG:\|Oops\|Internal error\|shutting down' "$OUT/dmesg_$B.txt")" "0"
# THE CLOSING FREE IS EVIDENCE, NOT CLEANUP.
# This rm frees the churn file, and the NEXT lap recycles that inode number --
# so whether this free's dinode reaches home is exactly what D-0946 turns on.
# Every dmesg capture above closes before this point, so without its own window
# the free is invisible and any claim about its durability is unfalsifiable.
# P9-INSTR fires unconditionally when the eager chain runs; its ABSENCE is how
# a lap says the eager path was not in force, which is what void'd a whole
# ten-lap run once already.
FMK="AGSHUT-FREE-$LABEL-$(date +%s%N)"
rs 60 "$A" "echo '$FMK' > /dev/kmsg 2>/dev/null; rm -rf $D; sync -f $MNT 2>/dev/null; sleep 1; dmesg | sed -n '/$FMK/,\$p'" > "$OUT/closingfree_$A.txt" 2>/dev/null
fr_eager=$(grep -ac 'P9-INSTR ifree DONE' "$OUT/closingfree_$A.txt")
fr_bound=$(grep -ac 'P-IFREE-DRAIN-BOUND' "$OUT/closingfree_$A.txt")
fr_defer=$(grep -ac 'P128-INACT-DEFER' "$OUT/closingfree_$A.txt")
fr_knob=$(rs 20 "$A" "cat /sys/module/mxfs/parameters/ifree_eager_durable 2>/dev/null || echo x")
echo "  CLOSINGFREE-MEASURE $LABEL eager_done=$fr_eager drain_bound=$fr_bound inact_defer=$fr_defer ifree_eager_durable=$fr_knob"

wall=$(( $(date +%s) - s ))
if [ $fails != 0 ]; then echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; exit 1; fi
if [ $vacuous != 0 ]; then echo "RESULT: VACUOUS label=$LABEL put_probe=0 wall=${wall}s evidence=$OUT"; exit 3; fi
echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"
exit 0
