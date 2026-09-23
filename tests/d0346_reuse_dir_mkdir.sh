#!/bin/bash
# d0346_reuse_dir_mkdir.sh — a peer's mkdir under a directory the other node
# just removed and recreated must not answer ESTALE.
#
# THE SHAPE (measured on the 2026-09-12 2/tcp board, evidence
# tests/evidence/run_fence_during_write_20260912T221211Z, both nodes' kernel
# logs, 22:19:53-55, ino 10594):
#   1. the READER (A) holds a live in-core inode for a directory, cached from a
#      lookup while it existed;
#   2. the CREATOR (B) removes that directory and creates a directory that
#      REUSES the inode number (the allocator hands the just-freed number back);
#   3. B's new dinode is only logged: under deferred publish its EX on the new
#      child is local until the parent's BAST publishes it, and the parent's
#      release drain makes the DIRENT visible before the child dinode is on
#      the platter;
#   4. A resolves the new dirent, cache-hits its old shell (flagged by the
#      eviction ring's inode-freed event), FUA-reads the slot with no grant,
#      sees the post-free image (mode 0, generation old+1) and, before 0.84.24,
#      returned the old shell as an existing directory; the grant-less reload
#      that followed poisoned it ("P34H-INCARN-POISON src=reload ... disk_mode=0")
#      and A's create was refused before any transaction
#      ("P240-QUAR-NSOP-REFUSE op=create ... rc=-116"): mkdir: Stale file handle.
#
# This harness produces steps 1-3 on purpose and measures step 4 on A.  The
# number reuse is checked, not assumed: a round in which B's new directory did
# not get the old number produced no reuse and is counted VACUOUS, never OK.
#
# THE WINDOW IS HELD OPEN, NOT HOPED FOR.  On a quiet rig xfsaild destages B's
# new dinode within a few ms of the mkdir (s609d control: ten rounds, the
# reader's raw read found mode 040755 and the new generation every time, so no
# round read the free image and the lap measured nothing).  B arms
# dbg_iflush_pause_ino=<the number> after the remove+sync and before the
# recreate, kicks xfsaild through debugfs ail_push, and waits until the pause
# has fired (dbg_iflush_pause_n>=1): xfsaild has copied the new image into
# the cluster buffer and is holding the write, so the platter keeps the
# post-free image for PAUSE_MS while A looks.  A round in which the pause did
# not fire, or in which A's kernel log shows no read of the free image for the
# number (ISTALE-CAW-EVICT dmode=00 or P346-REUSE-COORD), is VACUOUS: the
# window was not observed, so the round proves nothing either way.
#
# EXPECT_SV=<srcversion> lets a CONTROL lap run against a build already on
# the rig that is older than the tree's (the tree is rebuilt with the fix
# before the control has been measured); the console line records both.
#
# WHAT IT ASSERTS, per round, on the reader:
#   reused   B's recreated directory carries the old inode number (precondition;
#            a round without it is VACUOUS and does not count either way)
#   mkdir    A's mkdir under the recreated name returns 0, no "Stale file handle"
#   visible  B lists the entry A created (the create landed in the LIVE
#            incarnation, not in a dead shell)
#   kmsg     A's kernel log for the round carries no grant-less poison of that
#            number (P34H-INCARN-POISON src=reload disk_mode=0) and no
#            namespace-op refusal (P240-QUAR-NSOP-REFUSE ... rc=-116);
#            the coordination line (P346-REUSE-COORD) and the deferral line
#            (P346-INCARN-DEFER) are counted and reported, not asserted, so
#            the control build (which has neither) is measured by the same rows.
#
# derived time budget: a round is 6 ssh round trips (about 0.4 s each on this
# rig) plus a mkdir, an rm -rf of a 4-entry directory, a mkdir and a stat on
# each side — native XFS does all of that in well under 100 ms — so a round is
# bounded at 20 s and a timeout IS a failure.  10 rounds plus precondition
# and evidence capture: 240 s.
#
# Usage: tests/d0346_reuse_dir_mkdir.sh <label> [ROUNDS=10]
# Env:   MXFS_NODE_LIST (default test1,test2: A=first is the reader, B=second
#        is the creator), MNT (default /mnt/shared), PAUSE_MS (default 3000),
#        EXPECT_SV (default: the tree's mxfs.ko srcversion)
# Exit 0 PASS (every counted round OK, at least 3 counted), 1 FAIL, 2 INFRA.
set -u
LABEL=${1:?label}
ROUNDS=${2:-10}
PAUSE_MS=${PAUSE_MS:-3000}
cd "$(dirname "$0")/.." || exit 2

export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}      # reader
B=${MXFS_NODE_LIST##*,}      # creator
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
D=$MNT/d0346_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0346reuse_$LABEL
mkdir -p "$OUT"

filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" </dev/null 2>/dev/null | filt; }
restore() { rs 20 "$B" "echo 0 > $P/dbg_iflush_pause_ino; echo 0 > $P/dbg_ail_pin_ino" >/dev/null; }

TREE_SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
SV=${EXPECT_SV:-$TREE_SV}
echo "=== d0346_reuse_dir_mkdir label=$LABEL reader=$A creator=$B rounds=$ROUNDS pause_ms=$PAUSE_MS sv=$SV tree_sv=$TREE_SV $(date -u +%FT%TZ) ==="

# Precondition: both nodes mounted on the expected build (the tree's unless a
# control lap names an older one).  A lap on a build other than the one named
# measures something else and its evidence lies about which code produced it.
# The creator must also expose the pause knob and the debugfs ail_push kick.
bad=0
for n in $A $B; do
    info=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) knobs=\$(for k in dbg_iflush_pause_ino dbg_iflush_pause_ms dbg_iflush_pause_n; do test -w $P/\$k && printf 1 || printf 0; done) push=\$(ls /sys/kernel/debug/mxfs/*/ail_push 2>/dev/null | wc -l)")
    echo "  INFO $n $info"
    echo "$info" | grep -q "sv=$SV"  || { echo "  PRECOND $n srcversion != expected ($SV)"; bad=1; }
    echo "$info" | grep -q "mounted=1" || { echo "  PRECOND $n not mounted"; bad=1; }
    echo "$info" | grep -q "knobs=111" || { echo "  PRECOND $n lacks the iflush pause knobs"; bad=1; }
    echo "$info" | grep -q "push=1" || { echo "  PRECOND $n has no debugfs ail_push"; bad=1; }
done
[ "$bad" = 0 ] || { echo "RESULT: INFRA label=$LABEL precondition not met"; exit 2; }

# The parent and the recreated child must not share an inode cluster: the
# pause knob is keyed on the inode xfsaild pushes, and a cluster flush carries
# every dirty inode in the cluster as a passenger.  With the parent at the
# chunk's first number and the child at the next, xfsaild pushed the parent
# (dirtied by the same mkdir) and the child's image landed unpaused (s610a,
# ten rounds, pause_n=0 every round).  Sixty-four pad files after the parent
# put the child's number well outside the parent's cluster.
PINO=$(rs 40 "$B" "echo 0 > $P/dbg_iflush_pause_ino; echo 0 > $P/dbg_ail_pin_ino; echo $PAUSE_MS > $P/dbg_iflush_pause_ms; rm -rf $D; mkdir -p $D; for i in \$(seq 1 64); do : > $D/pad\$i; done; sync; stat -c %i $D" | tr -dc '0-9')
[ -n "$PINO" ] || { echo "RESULT: INFRA label=$LABEL could not create the parent on $B"; exit 2; }
echo "  INFO parent=$D ino=$PINO"

fails=0; counted=0; vacuous=0
for r in $(seq 1 "$ROUNDS"); do
    mark="D0346R-$LABEL-r$r"
    for n in $A $B; do rs 20 "$n" "echo $mark > /dev/kmsg" >/dev/null; done
    t0=$(date +%s)

    # 1. B creates the directory with a few entries (a block-form fork is not
    #    required: the measured case's OLD incarnation was block-form, but the
    #    judgement under test is made on the dinode's mode and generation).
    ino_old=$(rs 20 "$B" "mkdir -p $D/d && touch $D/d/f1 $D/d/f2 $D/d/f3 && sync && stat -c %i $D/d" | tr -dc '0-9')
    # 2. A caches the directory AND its children: a stat of each entry puts
    #    the child dentries in core, and a child dentry holds its parent's, so
    #    the old shell stays referenced after B's remove and cannot be retired
    #    by the poison-retire loop.  That is the board's state (the children
    #    of the previous row were cached), and without it the control build
    #    retired the poisoned shell on its first try and the kernel's retry
    #    hid the ESTALE from the user (s610c: poison=1 refuse=1 on every
    #    round, mkdir rc=0).  Its grant is released again when B's rm BASTs it.
    a_seen=$(rs 20 "$A" "stat -c %i $D/d $D/d/f1 $D/d/f2 $D/d/f3 | head -1 && ls $D/d | wc -l" | tr '\n' ' ')
    # 3. B removes and recreates it in one command so no peer access can slip
    #    between the free and the reuse.  The sync between them is what makes
    #    the number come back: the unlink's free is deferred to inodegc, and
    #    without it the recreate picks the NEXT free number and the old one is
    #    freed afterwards (measured s609c: ten rounds alternating between two
    #    numbers, all vacuous).  sync flushes inodegc and destages the post-free
    #    image, which is the platter state the board's failure read.  NO sync
    #    after the mkdir — the new dinode must stay undestaged; that is the
    #    window — and the pause knob, armed for the old number between the
    #    sync and the recreate, holds xfsaild's write of the new image after
    #    the copy-in.  ail_push starts that write on demand; the wait proves
    #    the hold began before A looks.
    #    The PARENT's write must land first: the mkdir dirties the parent too,
    #    and a pause that catches xfsaild with the parent's write still on its
    #    delayed-write list holds that write as well, so the parent's release
    #    drain on B (which A's path walk triggers) waited out the whole pause
    #    and the dirent and the child's dinode landed together (s610b: ten
    #    rounds, drain_ms=2537, the reader's first read of the child already
    #    saw the new image).  So: pin the child (xfsaild skips it), kick once
    #    so the parent lands, unpin, arm the pause, kick again.
    b3=$(rs 30 "$B" "rm -rf $D/d && sync && echo ${ino_old:-0} > $P/dbg_ail_pin_ino && mkdir $D/d && echo ino=\$(stat -c %i $D/d) && echo 1 > /sys/kernel/debug/mxfs/*/ail_push && sleep 0.4 && echo 0 > $P/dbg_ail_pin_ino && echo 0 > $P/dbg_iflush_pause_n && echo ${ino_old:-0} > $P/dbg_iflush_pause_ino && echo 1 > /sys/kernel/debug/mxfs/*/ail_push; i=0; while [ \$i -lt 30 ]; do [ \$(cat $P/dbg_iflush_pause_n) -ge 1 ] && break; sleep 0.1; i=\$((i+1)); done; dmesg | awk '/$mark/{f=1} f' > /tmp/d0346_b3.txt; echo pause_n=\$(cat $P/dbg_iflush_pause_n) waited_ds=\$i pin_hits=\$(grep -ac 'P-AILPIN-HOLD ino=${ino_old:-0} ' /tmp/d0346_b3.txt) parent_landed=\$(grep -a 'P56-DIRWRITE ino=$PINO ' /tmp/d0346_b3.txt | grep -ac 'comm=xfsaild')")
    ino_new=$(echo "$b3" | grep -ao 'ino=[0-9]*' | head -1 | cut -d= -f2)
    pause_n=$(echo "$b3" | grep -ao 'pause_n=[0-9]*' | head -1 | cut -d= -f2)
    b3f=$(echo "$b3" | grep -ao 'pin_hits=[0-9]* parent_landed=[0-9]*' | head -1)
    # 4. A creates under the recreated name at once.
    res=$(rs 20 "$A" "e=\$(mkdir $D/d/sub_$r 2>&1); echo rc=\$? err=[\$e]")
    # 5. the create must have landed in the LIVE incarnation: B lists it.
    #    The pause is disarmed here; the held write lands when its ms elapse.
    vis=$(rs 20 "$B" "echo 0 > $P/dbg_iflush_pause_ino; ls $D/d 2>/dev/null | grep -c '^sub_$r\$'" | tr -dc '0-9')
    wall=$(( $(date +%s) - t0 ))

    rc=$(echo "$res" | sed -n 's/.*rc=\([0-9]*\).*/\1/p')
    stale=$(echo "$res" | grep -c -i 'stale file handle')
    rs 45 "$A" "dmesg | awk '/$mark/{f=1} f'" > "$OUT/round${r}_${A}_kmsg.txt" 2>/dev/null
    k="$OUT/round${r}_${A}_kmsg.txt"
    poison=$(grep -a 'P34H-INCARN-POISON' "$k" | grep -a "ino=${ino_old:-NONE} " | grep -ac 'disk_mode=0')
    refuse=$(grep -a 'P240-QUAR-NSOP-REFUSE' "$k" | grep -a "ino=${ino_old:-NONE} " | grep -ac 'rc=-116')
    coord=$(grep -a 'P346-REUSE-COORD ' "$k" | grep -ac "ino=${ino_old:-NONE} ")
    defer=$(grep -a 'P346-INCARN-DEFER' "$k" | grep -ac "ino=${ino_old:-NONE} ")
    evict=$(grep -a 'ISTALE-CAW-EVICT' "$k" | grep -ac "ino=${ino_old:-NONE} ")
    # the reader read the FREE image of the number: the evict arm's raw read
    # (dmode=00), the coordination that only a free read enters, or the
    # grant-less reload's verdict on it (poison before the fix, defer after;
    # s610c showed the reload reaching the free image before the eviction
    # ring's freed event had even arrived, so the evict arm is not the only
    # reader of the window)
    freeread=$(( $(grep -a 'ISTALE-CAW-EVICT' "$k" | grep -a "ino=${ino_old:-NONE} " | grep -ac 'dmode=00 ') + coord + poison + defer ))

    line="round=$r ino_old=${ino_old:-?} ino_new=${ino_new:-?} A_cached=[${a_seen:-?}] pause_n=${pause_n:-?} ${b3f:-pin_hits=? parent_landed=?} mkdir_rc=${rc:-?} stale=$stale visible=${vis:-?} freeread=$freeread poison=$poison refuse=$refuse coord=$coord defer=$defer evict=$evict wall=${wall}s"
    if [ -z "$ino_old" ] || [ -z "$ino_new" ] || [ "$ino_old" != "$ino_new" ]; then
        vacuous=$((vacuous+1))
        echo "$line VACUOUS (number not reused)" | tee -a "$OUT/rounds.txt"
        continue
    fi
    if [ "${pause_n:-0}" -lt 1 ]; then
        vacuous=$((vacuous+1))
        echo "$line VACUOUS (pause did not fire: the window was not held)" | tee -a "$OUT/rounds.txt"
        continue
    fi
    if [ "$freeread" -lt 1 ]; then
        vacuous=$((vacuous+1))
        echo "$line VACUOUS (reader never read the free image: the window was not observed)" | tee -a "$OUT/rounds.txt"
        continue
    fi
    counted=$((counted+1))
    ok=1
    [ "${rc:-1}" = 0 ]   || ok=0
    [ "$stale" = 0 ]     || ok=0
    [ "${vis:-0}" = 1 ]  || ok=0
    [ "$poison" = 0 ]    || ok=0
    [ "$refuse" = 0 ]    || ok=0
    [ "$wall" -le 20 ]   || ok=0          # a timeout IS a failure
    [ "$ok" = 1 ] || fails=$((fails+1))
    echo "$line $([ $ok = 1 ] && echo OK || echo FAIL)" | tee -a "$OUT/rounds.txt"
done

# Both nodes' kernel logs for the whole lap, for the record.
for n in $A $B; do rs 60 "$n" "dmesg | awk '/D0346R-$LABEL-r1\$/{f=1} f'" > "$OUT/lap_${n}_kmsg.txt" 2>/dev/null; done
restore
rs 30 "$B" "rm -rf $D" >/dev/null

verdict=PASS
[ "$fails" = 0 ] || verdict=FAIL
[ "$counted" -ge 3 ] || verdict=VACUOUS
echo "RESULT: $verdict label=$LABEL rounds=$ROUNDS counted=$counted vacuous=$vacuous fails=$fails sv=$SV evidence=$OUT"
[ "$verdict" = PASS ] || { [ "$verdict" = VACUOUS ] && exit 2; exit 1; }
exit 0
