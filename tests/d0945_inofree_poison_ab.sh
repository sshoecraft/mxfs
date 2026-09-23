#!/bin/bash
# d0945_inofree_poison_ab.sh — an inode FREE must not release its durable grant
# while the session is poisoned.  Two-node TCP.
#
# D-0945.  A grant is the evidence that lets a survivor replay a dead node's
# journal slice: the fence-time manifest is sealed from the grants the victim
# still held, and an image whose token names a resource the manifest does not
# hold is refused even when the token itself is VALID.  So an incarnation may
# release an on-disk grant only while no replay-eligible image of that
# incarnation can still require it, and POISONED — the log shut down, the slot
# WITHDRAWN, the key retained — means that can no longer be proven for any
# grant.  dlm/v5_mount.c gates every release on that, on both transports, except
# that mxfs_v5_dlm_inode_unlock_free gated only its CAW arm.  On TCP, freeing an
# inode after a log shutdown therefore destroyed the evidence.
#
# WHY THE EXISTING DEATH HARNESS CANNOT SEE IT.  agmeta_shutdown_retire.sh
# churns ONE pre-created file with punches and overwrites; it never frees an
# inode, so the free path is never taken and its laps report poisongate
# ino-free=0 whatever the code does.  This harness churns CREATE and UNLINK, so
# inodes are being freed at the instant the log dies.
#
# THE VERDICT IS THE GATE FIRING, NOT THE REJOIN RATE.  A rejoin failure needs
# the quarantined domain to contain AG 0, which is a lottery on top of the
# defect; the direct proof is that the release is refused
# (P-TCP-RELEASE-POISONED ino-free=<ino>) and that the survivor's replay carries
# notheld=0 with no ATOMIC-SKIP.  Both arms are reported so a difference in
# either can be attributed.
#
# ARM: poison_gate_ino_free=1 is the gate, 0 is the pre-fix behaviour.
#
# derived time budget, derived from the measured agmeta_shutdown_retire steps: prep
# 50 s (bounded 300), churn 8 s by construction (bounded 90), withdrawal settle
# 20 s (bounded 40), unload measured 8 s (bounded 60), rejoin measured 3 s
# (bounded 150 by the harness's own mount timeout), four dmesg captures ~6 s.
# Healthy wall ~110 s with a prep, ~60 s without.
#
# Usage: tests/d0945_inofree_poison_ab.sh <label> <0|1> [LAPS=3]
set -u
LABEL=${1:?label}
ARM=${2:?arm: 0 = pre-fix, 1 = gate}
LAPS=${3:-3}
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
MNT=/mnt/shared
KO=${KO:-/src/mxfs/mxfs.ko}
DURATION=${DURATION:-8}
ARM_AFTER=${ARM_AFTER:-3}
WORKERS=${WORKERS:-6}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0945_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0945_inofree_poison_ab label=$LABEL arm=$ARM laps=$LAPS sv=$SV $(date -u +%FT%TZ) ==="
ok=0; bad=0; vac=0; s=$(date +%s)

for i in $(seq 1 "$LAPS"); do
    D=$MNT/d0945_${LABEL}l$i
    MK="D0945-${LABEL}l$i"
    mounted=$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')
    knob=$(rs 20 "$A" "cat /sys/module/mxfs/parameters/poison_gate_ino_free 2>/dev/null || echo x")
    nodesv=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null || echo none"; done | sort -u | tr -d '\n')
    prepped=no
    # Every lap gets a fresh filesystem: laps 2 and 3 of an unprepped run
    # never consumed the injection at all (left=4, shut=0) because the
    # previous lap had left the mount in a state that does no fresh log I/O.
    if true || [ "$mounted" != "11" ] || [ "$knob" != "$ARM" ] || [ "$nodesv" != "$SV" ]; then
        p0=$(date +%s)
        MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS="poison_gate_ino_free=$ARM" \
            timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_$i.log" 2>&1
        prc=$?
        prepped="rc=$prc/$(( $(date +%s) - p0 ))s"
        [ $prc != 0 ] && { echo "LAP $i PREP-FAIL $prepped"; bad=$((bad+1)); continue; }
    fi
    knob=$(for n in $A $B; do rs 20 "$n" "cat /sys/module/mxfs/parameters/poison_gate_ino_free"; done | tr -d '\n')
    [ "$knob" = "$ARM$ARM" ] || { echo "LAP $i KNOB-FAIL got=$knob want=$ARM$ARM"; bad=$((bad+1)); continue; }
    PARAMS=$(rs 20 "$A" "for p in force_transport poison_gate_ino_free unpub_publish_owned_meta target_cache_protected; do v=\$(cat /sys/module/mxfs/parameters/\$p 2>/dev/null); [ -n \"\$v\" ] && printf '%s=%s ' \$p \$v; done")
    for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

    # FRAGMENT, THEN FREE.  Freeing a small file is not enough: its only logged
    # metadata is the AG's (AGI, inobt, the inode cluster), all of which is
    # authorized by the AG grant, and the AG grant is already retained on a
    # poisoned session.  The image that needs the INODE's grant is one the
    # inode itself owns — a bmap btree block — so each cycle grows a file past
    # inline extent format with hole punches and then unlinks it, and the
    # injected log error is armed while that is running.  Measured on the arm-0
    # lap with plain 8 KiB files: 2 grant frees, zero refusals, because no image
    # in flight named an inode.
    rs 90 "$A" "mkdir -p $D; for k in \$(seq 0 $(( WORKERS - 1 ))); do ( mkdir -p $D/w\$k; n=0; e=0; deadline=\$(( \$(date +%s) + $DURATION )); while [ \$(date +%s) -lt \$deadline ]; do f=$D/w\$k/f\$(( n % 8 )); fallocate -l 1M \$f 2>/dev/null || e=\$((e+1)); j=0; while [ \$j -lt 96 ]; do fallocate -p -o \$(( j * 8192 )) -l 4096 \$f 2>/dev/null || e=\$((e+1)); j=\$((j+1)); done; rm -f \$f 2>/dev/null || e=\$((e+1)); n=\$((n+1)); done; echo \"\$n \$e\" > /tmp/d0945.\$k ) & done; sleep $ARM_AFTER; echo 4 > /sys/module/mxfs/parameters/log_inject_ioerr; armrc=\$?; wait; ops=0; er=0; for k in \$(seq 0 $(( WORKERS - 1 ))); do set -- \$(cat /tmp/d0945.\$k 2>/dev/null || echo '0 0'); ops=\$(( ops + \$1 )); er=\$(( er + \$2 )); done; sync -f $MNT 2>/dev/null; echo CHURN cycles=\$ops op_errs=\$er arm_rc=\$armrc left=\$(cat /sys/module/mxfs/parameters/log_inject_ioerr)" > "$OUT/churn_${i}.txt"
    echo "  LAP $i CHURN $(tr '\n' ' ' < "$OUT/churn_${i}.txt")"

    # DRIVE THE RECLAIM.  mxfs_v5_dlm_inode_unlock_free is reached from exactly
    # two callers, and after a log shutdown only one of them can run: XFS
    # disables inodegc on shutdown, so the inactivation caller is dead, and what
    # is left is mxfs_dlm_evict on an inode whose ifree had already COMMITTED —
    # i.e. a file the churn unlinked just before the log died, now reclaimed.
    # Nothing in the ordinary teardown forces that reclaim promptly, which is
    # why three laps of this harness took the free path zero times while the one
    # lap that ever produced the defect got there by accident (a failed create
    # freeing its inode under a kworker).  Ask for it.
    sleep 5
    rs 60 "$A" "sync 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; echo drop_caches_rc=\$?" > "$OUT/reclaim_$i.txt" 2>&1
    sleep 15
    shut=$(rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'Filesystem has been shut down\|Log I/O Error\|Log I/O error'")
    ifg=$(rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'RELEASE-POISONED ino-free'")
    agg=$(rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'RELEASE-POISONED ag='")
    freed=$(rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'P52-GRANT-FREE'")
    rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -a 'RELEASE-POISONED\|P220-EPOCH-LEDGER-OPEN\|P52-GRANT-FREE' | tail -20" > "$OUT/gate_$i.txt"

    rs 90 "$A" "umount $MNT 2>&1 | tail -2; echo umount_rc=\$?; rmmod mxfs 2>&1 | tail -2; echo loaded=\$(grep -c '^mxfs ' /proc/modules)" > "$OUT/unload_$i.txt"
    rs 200 "$A" "modprobe libcrc32c 2>/dev/null; insmod $KO $PARAMS && echo INSMOD_OK sv=\$(cat /sys/module/mxfs/srcversion); mkdir -p $MNT; timeout 150 mount -t mxfs $MXFS_DEV $MNT; mrc=\$?; echo REJOIN mount_rc=\$mrc mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)" > "$OUT/rejoin_$i.txt"
    mrc=$(sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p' "$OUT/rejoin_$i.txt" | head -1)

    rs 40 "$B" "dmesg | sed -n '/$MK/,\$p' | grep -a 'P273-SHADOW-EVAL' | tail -1" > "$OUT/shadow_$i.txt"
    skip=$(rs 30 "$B" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'ATOMIC-SKIP'" | tr -dc '0-9')
    torn=$(rs 30 "$B" "dmesg | sed -n '/$MK/,\$p' | grep -a 'P227-FR-TORN-UNPUBLISHED' | tail -1" | grep -ao 'refused [0-9]* committed' | head -1)
    vec=$(sed 's/^.*P273-SHADOW-EVAL/P273/' "$OUT/shadow_$i.txt" | grep -ao 'buf=[0-9]*\|classless=[0-9]*\|badst=[0-9]*\|notheld=[0-9]*\|staleep=[0-9]*\|WOULD_APPLY=[0-9]*' | tr '\n' ' ')

    # VALIDITY IS THE DEATH, NOT THE FREE.  Whether an inode was freed is
    # exactly what the two arms differ about — in the pre-fix arm the release
    # succeeds and leaves no probe line at all — so making the free a validity
    # condition would silently discard every arm-0 lap that reproduced.  The
    # lap is valid if the injected error shut the filesystem down; the free is
    # then reported, never used to gate.
    if [ "${shut:-0}" -ge 1 ]; then
        valid=yes
        if [ "${mrc:-x}" = 0 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi
    else
        valid="NO-DEATH(injection not consumed)"; vac=$((vac+1))
    fi
    echo "  LAP $i arm=$ARM prep=$prepped valid=$valid mount_rc=${mrc:-none} grant_frees=$freed poisongate[ino-free=$ifg ag=$agg] atomic_skips=${skip:-?} ${torn:-no-refusal}"
    echo "       $vec"
done
echo "D0945-AB label=$LABEL arm=$ARM laps=$LAPS valid=$((ok+bad)) rejoin_ok=$ok rejoin_bad=$bad vacuous=$vac wall=$(( $(date +%s) - s ))s evidence=$OUT"
