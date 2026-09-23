#!/bin/bash
# authtail_mount_unwind.sh — does the mount-FAILURE unwind write metadata to the
# shared LUN after it has detached its DLM, and is that write now decided by the
# mount's authority lease?
#
# WHAT THIS IS ABOUT.  The metadata arm of the authority gate
# (pal/linux/xfs_buf.c) used to ask bp->b_mount->m_mxfs_dlm and take NO branch
# when that pointer was NULL.  The other four mutating producers — the log,
# direct I/O, zoned direct I/O and data writeback — were converted to the
# mount's authority object, which outlives the detach on purpose; this one was
# not.  Every metadata write issued while the DLM was detached therefore went to
# the shared LUN with no lease consulted at all.  0.89.26 routes it through
# mxfs_mount_write_admitted() like its four siblings.  This lap measures the
# before and the after ON ONE BUILD.
#
# WHERE THE DETACHED STATE COMES FROM, and why it is not put_super.  Two arms of
# the unmount tail were measured and BOTH counted zero, and the path says why:
# put_super forces the log, pushes the AIL, waits on the buftarg and runs the
# full per-AG drain ALL BEFORE it detaches at xfs_super.c:2406, and the clustered
# path hoists the SB summary sync in front of it too — so by the time the DLM is
# gone that tail has no metadata left to write.  The MOUNT unwind is the
# opposite shape: out_unmount (xfs_super.c:5203) detaches at :5207, shuts the
# DLM down at :5222 and only THEN calls xfs_unmountfs at :5234, which pushes
# whatever log recovery and unlinked-inode processing left in the AIL.  The
# unwind's own comment says so: "the log may already carry this mount's writes
# (unlinked-inode processing at minimum)".
#
# WHAT THE EARLIER STAGINGS GOT WRONG, MEASURED.
#
# s92/s94: the lap forged an FSWIDE terminal refusal onto the platter and
# asserted the refusal was the admission commit's from a count of
# P240-QUAR-ADMIT-DENY.  That line is a PREDICTION, not the refusal: the
# quarantine import emits it for ANY import taken while the mount is still
# being admitted, including one inside the recovery barrier.  s92's journal
# carries "MXFS mount recovery barrier failed" and never the admission commit's
# own text, so the goto taken was :5109 to out_filestream_unmount — which never
# calls xfs_unmountfs.  A forged record already on the platter is ALWAYS caught
# by the barrier first, so out_unmount could never be reached that way.
#
# s95 live arm: out_unmount was reached for the first time (injected=1,
# barrier_failed=0, mount rc=32 in 12 s) and the unwind DID submit after
# detaching — P291-AUTH-TAIL-ADMIT site=log comm=mount.  But it recovered
# nothing, because THE NODE HAD BEEN MADE TO DIRTY ITS OWN LOG and MXFS does
# not recover its own log inline: the remount claimed a different heartbeat
# slot and printed "adopted log slice (fresh disklock claim) — image records in
# prior dirty content will not be re-applied", while its previous incarnation's
# slice was recovered by the SURVIVING PEER ("slice slot=0 is being recovered
# by another survivor", P233-MPHASE-RESOLVED-ELSEWHERE).  The mount then said
# "Ending clean mount" with an empty AIL.
#
# SO THE DIRT HAS TO BE FOREIGN, AND THIS MOUNT HAS TO BE THE ONE THAT REPLAYS
# IT.  The peer is staged dirty and then stops beating with its slot ACTIVE; the
# measured node is unmounted first, so no survivor exists to take the recovery
# away from it.  Its mount then pays the dead-confirmation window, fences the
# peer, replays the peer's slice, and runs the deferred unlinked-inode sweep the
# barrier recorded but could not run (mxfs_dlm_mount_recovery_settle,
# xfs_super.c:5121 — iget plus transactions).  THAT is the metadata the unwind
# pushes, and it is the exact integrity case this record is about: a mount
# writes what it recovered from a dead peer, after its own DLM is gone.
#
# HOW THE UNWIND IS REACHED NOW.  mxfs.dbg_admission_refuse discards a
# SUCCESSFUL admission commit, one-shot, which is the :5131 goto and nothing
# else.  The production trigger is an FSWIDE quarantine that only the
# registration-time scan discovers — a window of about half a second that cannot
# be aimed at from outside the kernel.  Nothing downstream of the goto is
# changed by the knob, so the unwind under measurement is the production unwind.
#
# THE THREE ARMS, and why each is needed.  Each stages the SAME dirty log and
# differs only in the knobs:
#
#   live   admission refused, no park.  The node is still heartbeating, so the
#          lease is live and the fixed gate must ADMIT — and the admission must
#          be attributed to the lease (P291-AUTH-TAIL-ADMIT site=meta), not to
#          an absent reference.  This is the REACHABILITY arm: a non-zero
#          P291-AUTH-META-DETACHED here is the population the old branch could
#          not see.
#   blind  admission refused, unwind parked past the lease, and
#          mxfs.dbg_auth_tail_blind restoring the PRE-FIX answer for exactly
#          this case.  The metadata must be admitted WITHOUT the lease being
#          consulted (P291-AUTH-TAIL-BLIND site=meta) — this is the defect,
#          reproduced on the same build.
#   fixed  admission refused, unwind parked past the lease, blind knob clear.
#          The same metadata must now be REFUSED (P290-AUTH-REFUSED-META).
#
# Two builds would leave every other difference between them as an alternative
# explanation, which is why blind/fixed are one build and one knob apart.
#
# THE PARK.  mxfs.dbg_mount_unwind_park_ms parks out_unmount between the DLM
# shutdown (which joins the heartbeat thread) and xfs_unmountfs, so the
# authority lease — 30 s from its issue instant — runs out before the unwind
# submits anything.  45 s is past the lease and short of the 62 s peer-death
# window, so the peer does not fence mid-lap.
#
# VACUOUS IF the mount is ADMITTED (rc=0): no unwind ran.  Vacuous if the
# refusal is not the injected one — a mount refused by the recovery barrier
# takes :5109 and never calls xfs_unmountfs.  Vacuous if the refused mount did
# no log recovery, because then its AIL was empty and a zero says nothing.
#
# THE BUDGET (derived, a timeout is a failure):
#   boot-wait 200 (VM boot, infra) + prep 300 (measured 216 on a node that
#   needed a power-cycle) + per arm [ unmount A 25 + mount B 110 (it may pay a
#   confirm window for its own previous stale slot) + dirty staging 60 (48
#   opens, a sync, 2000 creates; a native small-file batch is under a second) +
#   forced shutdown 15 + unmount B 25 + the measured mount 62 (the printed
#   dead-confirm window) + 25 (fence, replay, sweep) + PARK + 15 (the unwind) +
#   captures 40 ] = 377 + PARK.  ONE ARM PER INVOCATION unless the caller says
#   otherwise: 200+300+377+90 = 967 s for a park-less arm, +45 for a parked
#   one.  Caller bound 1020 s for one arm, 1440 s for two.
#
# Usage: tests/authtail_mount_unwind.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2) — the FIRST is the node whose mount is
#        refused and measured, the SECOND is the peer that is staged dirty and
#        left with an ACTIVE slot that has stopped beating; ARMS
#        ("live blind fixed"), PARK_MS (45000), CHURN (2000), HOLD (48),
#        MXFS_TRANSPORT (tcp).  NO VM IS EVER DESTROYED BY THIS LAP.
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# NOTHING IS FORGED AND NOTHING IS LEFT ON THE PLATTER: no slot is written by
# this lap, so there is no restore to get wrong and no way for it to wedge the
# next prep.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the MEASURED node: its refused mount is the lap
B=${MXFS_NODE_LIST##*,}          # the DIRTY peer: staged dirty, then stops beating
ARMS=${ARMS:-"live blind fixed"}
PARK_MS=${PARK_MS:-45000}
CHURN=${CHURN:-2000}
HOLD=${HOLD:-48}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_authunwind_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
echo "=== authtail_mount_unwind label=$LABEL victim=$A peer=$B arms='$ARMS' park=${PARK_MS}ms $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# Multi-field lines are the norm here, so the match must not be anchored at ^:
# an anchored reader returns "" for every field after the first.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# XFS_IOC_GOINGDOWN is _IOR('X', 125, uint32_t) = 0x8004587d
# (xfs/libxfs/xfs_fs.h:1265), and the flag word is
# XFS_FSOP_GOING_FLAGS_NOLOGFLUSH = 0x2 (:695) — flush neither the log nor the
# data, which is the whole point: the log must be left dirty for the next
# mount to recover.
#
# TWO REASONS IT IS THE RAW IOCTL.  xfs_io cannot send it to an mxfs mount at
# all: it probes the fd with XFS_IOC_FSGEOMETRY first, which mxfs does not
# answer, so xfs_io exits before the shutdown is ever issued and every scripted
# "shutdown -f" against mxfs was a silent no-op (tests/mxfs_shutdown.sh:4-9).
# And THE IOCTL NUMBER IS SHARED WITH EXT4_IOC_SHUTDOWN, so pointing it at a
# path that is not an mxfs mount shuts down whatever IS mounted there — on
# these nodes that is the root filesystem.  /proc/mounts must therefore say
# "mxfs" for this exact mount point before the ioctl is sent, and the refusal
# is loud rather than silent.
GODOWN="python3 -c \"import fcntl,os,struct,sys
ok=any(len(f)>=3 and f[1]=='$MNT' and f[2]=='mxfs'
       for f in (l.split() for l in open('/proc/mounts')))
if not ok:
    print('GODOWN rc=90 why=not-an-mxfs-mount — refusing, the ioctl is shared with EXT4_IOC_SHUTDOWN')
    sys.exit(0)
fd=os.open('$MNT', os.O_RDONLY)
fcntl.ioctl(fd, 0x8004587d, struct.pack('I', 2))
os.close(fd)
print('GODOWN rc=0')\" 2>&1 || echo GODOWN rc=\$?"

# ---- 0. the build must carry every knob and every probe this lap reads
for sym in P291-AUTH-META-DETACHED P291-AUTH-TAIL-ADMIT P291-AUTH-TAIL-BLIND \
           P290-AUTH-REFUSED-META P291-ADMISSION-REFUSE-INJECTED \
           P291-AUTH-UNWIND-PARK; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done

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

# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node and by the node's live
# mxfs mount.  Resolved while A is still MOUNTED, because that is the strongest
# identity the resolver has; it ABORTs on anything that is not this rig's LUN.
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
echo "STAGE device resolved $DEV at +$(el)s"

KNOB=/sys/module/mxfs/parameters

# ---------------------------------------------------------------- one arm ----
# Returns non-zero on an infra/staging failure; sets ARM_* for the caller.
run_arm() {
    local arm=$1 blind=0 park=0
    case $arm in
        live)  blind=0; park=0 ;;
        blind) blind=1; park=$PARK_MS ;;
        fixed) blind=0; park=$PARK_MS ;;
        *) echo "  ABORT unknown arm '$arm'"; return 2 ;;
    esac
    local M=$OUT/$arm
    mkdir -p "$M"
    local MARK="AUTHUNWIND-$LABEL-$arm"

    # --- a. NO SURVIVOR MAY EXIST FOR THE DIRT THIS ARM IS ABOUT TO MAKE.
    #        A mounted peer's monitor recovers a stale slice within the death
    #        window and prints "being recovered by another survivor"; the
    #        measured mount then replays nothing and arrives at the admission
    #        commit with an empty AIL (s95 live).  So A comes down FIRST, while
    #        B is still healthy, which is also the cheap ordering: unmounting a
    #        survivor INSIDE a peer-death window costs the whole window.
    measure "$A" 150 "$M/a_down.txt" '^ADOWN rc=' "taking the measured node $A offline first" \
        "rc=0
         if grep -q ' $MNT ' /proc/mounts; then timeout 120 umount $MNT || rc=\$?; fi
         echo ADOWN rc=\$rc still=\$(grep -c ' $MNT ' /proc/mounts)"
    ck "[$arm] $A is unmounted before the peer is staged" "$(field "$M/a_down.txt" still)" 0
    [ "$(field "$M/a_down.txt" still)" = 0 ] || return 2

    # --- b. bring the DIRTY PEER up.  It may pay a confirm window for its own
    #        previous stale slot, which is why this is generous.
    measure "$B" 200 "$M/b_up.txt" '^BUP rc=' "the peer mount on $B for arm $arm" \
        "rc=0
         grep -q ' $MNT ' /proc/mounts || timeout 170 mount -t mxfs $DEV $MNT || rc=\$?
         echo BUP rc=\$rc mounted=\$(grep -c ' $MNT ' /proc/mounts)"
    ck "[$arm] the dirty peer $B is mounted before the staging" "$(field "$M/b_up.txt" mounted)" 1
    [ "$(field "$M/b_up.txt" mounted)" = 1 ] || return 2

    # --- c. leave B's slice DIRTY, with an unlinked list on disk.
    #
    #   $HOLD inodes are opened, written and unlinked while still open, then
    #   sync'd: the unlink transactions become durable and the inodes stay on
    #   the on-disk unlinked list because the files are still held.  A churn of
    #   $CHURN creates then runs with NO sync, so the log carries work the
    #   metadata has not caught up with at the instant of the shutdown.  The
    #   unlinked list is the point: it is what the measured mount's deferred
    #   sweep has to iget and free in a transaction, and that is the metadata
    #   the unwind then pushes.
    #
    #   THE HOLDER GETS ITS OWN PROCESS GROUP.  Measured s93: killing the
    #   holding bash by pidfile left its `sleep` child holding all $HOLD
    #   inherited descriptors, the unmount was "target is busy", and the check
    #   that asked [ -d /proc/$pid ] passed anyway because the PID it named
    #   really had gone.  setsid makes the holder a group leader so the whole
    #   group can be signalled, and the check below asks the MOUNT whether it
    #   is still busy rather than asking about a PID.
    local HELDF=/tmp/authunwind_held_${LABEL}_$arm
    local PIDF=/tmp/authunwind_pid_${LABEL}_$arm
    local DIR=$MNT/authunwind_${LABEL}_$arm
    rs 20 "$B" "rm -f $HELDF $PIDF; dmesg --clear; echo $MARK-STAGE > /dev/kmsg" >/dev/null
    measure "$B" 150 "$M/dirty.txt" '^DIRTY_END$' "the dirty-slice staging on $B for arm $arm" \
        "mkdir -p $DIR || { echo DIRTY rc=1 why=mkdir; echo DIRTY_END; exit 0; }
         setsid nohup bash -c '
            d=\"\$0\"
            for i in \$(seq 1 $HOLD); do
                exec {fd}> \"\$d/u\$i\" || break
                printf \"unlinked-holder-%s\\n\" \"\$i\" >&\$fd
                unlink \"\$d/u\$i\"
            done
            sync
            echo \$\$ > $PIDF
            touch $HELDF
            sleep 900
         ' \"$DIR\" >/tmp/authunwind_hold_${LABEL}_$arm.log 2>&1 &
         for t in \$(seq 1 60); do [ -e $HELDF ] && break; sleep 1; done
         echo HELD held=\$([ -e $HELDF ] && echo 1 || echo 0) pid=\$(cat $PIDF 2>/dev/null)
         n=0; while [ \$n -lt $CHURN ]; do : > $DIR/c\$n; n=\$((n+1)); done
         echo CHURN n=\$n
         echo DIRTY_END"
    ck "[$arm] the unlinked-inode holder reached its hold point on the peer" "$(field "$M/dirty.txt" held)" 1
    [ "$(field "$M/dirty.txt" held)" = 1 ] || return 2
    echo "  STAGE [$arm] dirty staging on $B held=1 pid=$(field "$M/dirty.txt" pid) churn=$(field "$M/dirty.txt" n) at +$(el)s"

    # --- d. the forced shutdown flushes NEITHER the log nor the data, so the
    #        unmount below cannot cover the log: B's departure is DIRTY, its
    #        slot stays ACTIVE over an unreplayed slice, and its heartbeat
    #        stops with it.  No VM is destroyed and no node is power-cycled.
    measure "$B" 60 "$M/godown.txt" '^GODOWN rc=' "the forced shutdown on $B for arm $arm" "$GODOWN"
    ck "[$arm] the forced shutdown was accepted on the peer" "$(field "$M/godown.txt" rc)" 0
    [ "$(field "$M/godown.txt" rc)" = 0 ] || { sed 's/^/    /' "$M/godown.txt" | cut -c1-200 | head -4; return 2; }
    measure "$B" 60 "$M/shutlog.txt" '^SHUT_END$' "the shutdown's own kernel record on $B" \
        "dmesg | sed -n '/$MARK-STAGE/,\$p' | grep -a 'Shutting down\|shutdown\|I/O error' | tail -4; echo SHUT_END"
    ck "[$arm] the kernel recorded the forced shutdown on the peer" \
       "$([ "$(cnt "$M/shutlog.txt" 'Shutting down')" -ge 1 ] && echo recorded || echo absent)" recorded

    # THE PRODUCER SIDE OF THE REFUSAL.  When the measured node's replay
    # refuses this slice, the token it complains about was stamped HERE, and
    # the victim's journal does not survive the death that makes the token
    # matter — so it is captured now, while the node is still up.  The daddrs
    # in P239-DINO-NOAUTH are the ones the replayer's P227-TOKEN lines name.
    measure "$B" 90 "$M/producer.txt" '^PRODUCER_END$' "the token-producer record on $B" \
        "dmesg | sed -n '/$MARK-STAGE/,\$p' | grep -a 'P239-DINO-NOAUTH\|P239-OWNAUTH-NONDUR\|P-IUNLINK-AGCLASS' | cut -c1-400 | tail -40
         echo PRODUCER_END"
    echo "  STAGE [$arm] producer dino_noauth=$(cnt "$M/producer.txt" 'P239-DINO-NOAUTH') ownauth_nondur=$(cnt "$M/producer.txt" 'P239-OWNAUTH-NONDUR') iunlink_agclass=$(cnt "$M/producer.txt" 'P-IUNLINK-AGCLASS')"

    # Release the holders and unmount B.  Releasing the descriptors AFTER the
    # shutdown is the point: a shut-down filesystem does not inactivate an
    # unlinked inode, so the on-disk unlinked list survives the close and the
    # MEASURED node's replay is what has to process it.  By process group from
    # the pidfile, never by pattern.
    measure "$B" 60 "$M/holder.txt" '^HOLDER ' "the release of the unlinked holders on $B" \
        "p=\$(cat $PIDF 2>/dev/null)
         [ -n \"\$p\" ] && { kill -TERM -\"\$p\" 2>/dev/null || kill -TERM \"\$p\" 2>/dev/null; }
         sleep 2
         [ -n \"\$p\" ] && kill -KILL -\"\$p\" 2>/dev/null
         sleep 1
         echo HOLDER pid=\$p alive=\$([ -d /proc/\$p ] && echo 1 || echo 0) busy=\$(timeout 20 fuser -m $MNT 2>/dev/null | wc -w)"
    measure "$B" 120 "$M/umount.txt" '^UMOUNT rc=' "the shutdown filesystem's unmount on $B" \
        "rc=0; timeout 90 umount $MNT || rc=\$?
         echo UMOUNT rc=\$rc still=\$(grep -c ' $MNT ' /proc/mounts)"
    local urc; urc=$(field "$M/umount.txt" rc)
    echo "  STAGE [$arm] peer unmounted rc=$urc still=$(field "$M/umount.txt" still) busy=$(field "$M/holder.txt" busy) at +$(el)s"
    ck "[$arm] the peer's unmount completed rather than hitting its bound" \
       "$([ "$urc" = 124 ] && echo bound || echo completed)" completed
    ck "[$arm] the peer released $MNT" "$(field "$M/umount.txt" still)" 0
    [ "$(field "$M/umount.txt" still)" = 0 ] || return 2

    # --- e. THE MEASUREMENT.  Arm the knobs, then mount: the mount recovers its
    #        own dirty log inside xfs_mountfs, the injected refusal discards the
    #        successful admission commit, and the :5131 goto runs out_unmount —
    #        which detaches, shuts the DLM down, optionally parks past the lease,
    #        and calls xfs_unmountfs to push what recovery left.
    local mb; mb=$(( PARK_MS / 1000 + 200 ))   # 62 s confirm window + fence/replay/sweep + the unwind
    rs 20 "$A" "dmesg --clear; echo $MARK-MOUNT > /dev/kmsg" >/dev/null
    measure "$A" 40 "$M/knobs.txt" '^KNOBS ' "the knob arming on $A for arm $arm" \
        "echo $blind > $KNOB/dbg_auth_tail_blind
         echo $park  > $KNOB/dbg_mount_unwind_park_ms
         echo 1      > $KNOB/dbg_admission_refuse
         echo KNOBS blind=\$(cat $KNOB/dbg_auth_tail_blind) park=\$(cat $KNOB/dbg_mount_unwind_park_ms) refuse=\$(cat $KNOB/dbg_admission_refuse)"
    ck "[$arm] the blind knob reads back what the arm asked for" "$(field "$M/knobs.txt" blind)" "$blind"
    ck "[$arm] the park knob reads back what the arm asked for" "$(field "$M/knobs.txt" park)" "$park"
    ck "[$arm] the admission refusal is armed" "$(field "$M/knobs.txt" refuse)" 1
    [ "$(field "$M/knobs.txt" refuse)" = 1 ] || return 2

    measure "$A" $((mb + 40)) "$M/mount.txt" '^MOUNT rc=' "the refused mount on $A for arm $arm" \
        "s=\$(date +%s); rc=0; timeout $mb mount -t mxfs $DEV $MNT || rc=\$?
         echo MOUNT rc=\$rc secs=\$(( \$(date +%s) - s )) mounted=\$(grep -c ' $MNT ' /proc/mounts)"
    ARM_MRC=$(field "$M/mount.txt" rc)
    echo "  STAGE [$arm] mount rc=$ARM_MRC secs=$(field "$M/mount.txt" secs) mounted=$(field "$M/mount.txt" mounted) at +$(el)s"

    measure "$A" 120 "$M/journal.txt" '^JOURNAL_END$' "the victim's journal across the refused mount" \
        "dmesg | sed -n '/$MARK-MOUNT/,\$p' | cut -c1-700; echo JOURNAL_END"

    # the knobs are one-shot and self-clearing, but a lap that died before its
    # mount would leave them armed for the next one, so read them back
    measure "$A" 40 "$M/knobs_after.txt" '^KNOBSAFTER ' "the knob state after the arm" \
        "echo 0 > $KNOB/dbg_auth_tail_blind
         echo KNOBSAFTER blind=\$(cat $KNOB/dbg_auth_tail_blind) park=\$(cat $KNOB/dbg_mount_unwind_park_ms) refuse=\$(cat $KNOB/dbg_admission_refuse)"

    ARM_INJ=$(cnt   "$M/journal.txt" 'P291-ADMISSION-REFUSE-INJECTED')
    ARM_BARR=$(cnt  "$M/journal.txt" 'recovery barrier failed')
    ARM_PARK=$(cnt  "$M/journal.txt" 'P291-AUTH-UNWIND-PARK ms=')
    ARM_RECOV=$(cnt "$M/journal.txt" 'P163-RECOVERED\|Starting recovery')
    # sess99: this MUST be the evidence that a foreign slice was actually
    # REPLAYED by this mount, because that is the only thing that gives the
    # unwind recovered metadata to push.  It used to count P163-RECOVERED,
    # which is the monitor's NO-REPLAY completion path (dlm/disklock.c) — the
    # exact opposite reading, and one the replay path never prints.  Four
    # consecutive laps (s97, s98, s100, s101) therefore reported VACUOUS while
    # their journals carried "foreign replay of slot N complete" and
    # P163-RECOVERY-COMPLETE.  Count the replayer's own completion line.
    ARM_FREP=$(cnt  "$M/journal.txt" 'foreign replay of slot [0-9]* complete')
    ARM_SURV=$(cnt  "$M/journal.txt" 'being recovered by another survivor')
    ARM_BARR_DONE=$(grep -ao 'barrier complete: cohort=[^ ]* late=[^ ]* replayed=[0-9]*' "$M/journal.txt" | tail -1)
    ARM_META=$(cnt  "$M/journal.txt" 'P291-AUTH-META-DETACHED')
    ARM_REF=$(cnt   "$M/journal.txt" 'P290-AUTH-REFUSED-META')
    ARM_TADM=$(cnt  "$M/journal.txt" 'P291-AUTH-TAIL-ADMIT site=meta')
    ARM_TADL=$(cnt  "$M/journal.txt" 'P291-AUTH-TAIL-ADMIT')
    ARM_BLND=$(cnt  "$M/journal.txt" 'P291-AUTH-TAIL-BLIND site=meta')
    ARM_NOAU=$(cnt  "$M/journal.txt" 'P291-AUTH-ABSENT')
    ARM_BUG=$(cnt   "$M/journal.txt" 'BUG:\|Oops\|kernel NULL pointer')
    echo "  STAGE [$arm] injected=$ARM_INJ barrier_failed=$ARM_BARR parked=$ARM_PARK foreign_replays=$ARM_FREP stolen_by_survivor=$ARM_SURV"
    echo "  STAGE [$arm] ${ARM_BARR_DONE:-barrier complete line absent}"
    echo "  STAGE [$arm] meta_detached=$ARM_META refused_meta=$ARM_REF tail_admit_meta=$ARM_TADM tail_admit_any=$ARM_TADL blind_meta=$ARM_BLND no_authority=$ARM_NOAU bug=$ARM_BUG"
    grep -a 'P291-ADMISSION-REFUSE-INJECTED\|P291-AUTH-UNWIND-PARK\|P291-AUTH-META-DETACHED\|P290-AUTH-REFUSED-META\|P291-AUTH-TAIL-ADMIT\|P291-AUTH-TAIL-BLIND\|P163-RECOVERED\|barrier complete\|recovery barrier failed' \
        "$M/journal.txt" | sed 's/.*mxfs: /      /; s/.*MXFS: /      /; s/.*XFS (sd[a-z]): /      /' | cut -c1-190 | head -12
    return 0
}

# ---- 1. run the arms
declare -A R_META R_REF R_TADM R_BLND R_RECOV R_INJ R_MRC
VAC=""
for arm in $ARMS; do
    echo "--- arm $arm at +$(el)s"
    if ! run_arm "$arm"; then
        echo "RESULT: ABORT label=$LABEL stage=arm:$arm evidence=$OUT"; exit 2
    fi
    # the ordering has to have been REACHED before any count from it means
    # anything, and each of these is a different way for it not to have been
    if [ "$ARM_MRC" = 0 ]; then
        VAC="arm $arm: the mount was ADMITTED, so out_unmount never ran"; break; fi
    if [ "$ARM_INJ" = 0 ]; then
        VAC="arm $arm: the injected admission refusal never fired, so the goto taken was not :5131"; break; fi
    if [ "$ARM_BARR" != 0 ]; then
        VAC="arm $arm: the recovery barrier refused the mount, which takes :5109 to out_filestream_unmount and never calls xfs_unmountfs"; break; fi
    if [ "$ARM_FREP" = 0 ]; then
        VAC="arm $arm: the refused mount completed NO FOREIGN REPLAY (stolen_by_survivor=$ARM_SURV), so it had no recovered metadata to push and any zero here says nothing"; break; fi
    R_META[$arm]=$ARM_META;  R_REF[$arm]=$ARM_REF;   R_TADM[$arm]=$ARM_TADM
    R_BLND[$arm]=$ARM_BLND;  R_RECOV[$arm]=$ARM_FREP;  R_INJ[$arm]=$ARM_INJ
    R_MRC[$arm]=$ARM_MRC
    ck "[$arm] the victim did not end up mounted" "$(field "$OUT/$arm/mount.txt" mounted)" 0
    ck "[$arm] no clustered submission reached the gate without an authority object" "$ARM_NOAU" 0
    ck "[$arm] zero BUG / Oops across the refused mount" "$ARM_BUG" 0
    if [ "$arm" != live ]; then
        ck "[$arm] the unwind parked past the authority lease" \
           "$([ "$ARM_PARK" -ge 1 ] && echo parked || echo unparked)" parked
    fi
done
if [ -n "$VAC" ]; then
    echo "  $VAC"
    echo "RESULT: VACUOUS label=$LABEL evidence=$OUT"; exit 3
fi

# ---- 2. the verdicts, one per arm
#
# live: the reachability answer.  A non-zero meta_detached is a metadata write
# that reached the arm with the DLM gone — the population the old branch could
# not see — and tail_admit_meta says the fixed gate ADMITTED it because the
# lease was live, which is the correct answer for a healthy node and is the
# no-regression half of the change.
if [ -n "${R_META[live]:-}" ]; then
    ckge "[live] the unwind reached the metadata arm with its DLM detached (reachability)" "${R_META[live]}" 1
    ckge "[live] the admitted metadata write was decided BY THE LEASE, not by an absent reference" "${R_TADM[live]}" 1
    ck   "[live] a live lease refused nothing" "${R_REF[live]}" 0
    ck   "[live] the pre-fix blind answer was not in force on this arm" "${R_BLND[live]}" 0
fi
# blind: the defect, reproduced.  Lease closed, pre-fix answer restored: the
# metadata is admitted and the lease is never asked.
if [ -n "${R_META[blind]:-}" ]; then
    ckge "[blind] the pre-fix gate admitted metadata WITHOUT consulting the closed lease (the defect)" "${R_BLND[blind]}" 1
    ck   "[blind] and refused nothing while doing it" "${R_REF[blind]}" 0
fi
# fixed: the same ordering, one knob apart, must now refuse.
if [ -n "${R_META[fixed]:-}" ]; then
    ckge "[fixed] the closed lease REFUSED the unwind's metadata writes" "${R_REF[fixed]}" 1
    ck   "[fixed] and admitted none of them blind" "${R_BLND[fixed]}" 0
fi

for arm in $ARMS; do
    echo "  ARM $arm: mount_rc=${R_MRC[$arm]:-?} foreign_replays=${R_RECOV[$arm]:-?} meta_detached=${R_META[$arm]:-?} refused_meta=${R_REF[$arm]:-?} tail_admit_meta=${R_TADM[$arm]:-?} blind_meta=${R_BLND[$arm]:-?}"
done

# ---- 3. leave A mounted and healthy, so the next lap does not start by
#         recovering this one's last dirty log
for n in "$B" "$A"; do
    measure "$n" 220 "$OUT/final_$n.txt" '^FINAL ' "the restore of $n to a healthy mount" \
        "rc=0; grep -q ' $MNT ' /proc/mounts || timeout 190 mount -t mxfs $DEV $MNT || rc=\$?
         echo FINAL rc=\$rc mounted=\$(grep -c ' $MNT ' /proc/mounts)"
    ck "$n ends the lap mounted and healthy" "$(field "$OUT/final_$n.txt" mounted)" 1
done

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
