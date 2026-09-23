#!/bin/bash
# lu_reset_barrier.sh — does the post-reset convergence barrier hold when this
# node's authority survived, and REFUSE when it did not?
#
# WHAT THIS IS FOR.  A LOGICAL UNIT RESET terminates the tasks of every I_T
# nexus attached to the unit, INCLUDING THE ISSUER'S OWN.  So the node that
# issues one to retire a dead peer's accepted work can come out the other side
# with its own heartbeat write stranded and blocked for far longer than its
# 30 s authority lease — and a node that goes on replaying a dead peer's
# journal slice with authority it no longer holds is a second authority over
# that slice, which is the integrity case the whole retirement obligation
# exists to prevent.  The barrier is what must hold before one replay byte or
# one recovery-commit byte is written.  Nothing in this file issues a reset,
# and one of the assertions is that nothing did.
#
# WHY THE HOLD ARM IS FIRST AND THE REFUSAL ARM IS LAST.  A barrier that
# refused everything would pass a refusal arm and protect nothing, and one that
# held unconditionally would pass a hold arm and protect nothing either.  So
# both are measured, on the same build, against the same LUN, minutes apart —
# and the middle arm separates the two readings that would otherwise be
# confused: a barrier that merely READ the last heartbeat timestamp would hold
# instantly, exactly as a correct one does, whenever the cluster is healthy.
#
# THE ARMS.
#   hold    B unmounted, so A is the only registrant — the shape a death whose
#           registration the target purged leaves behind, and the only shape in
#           which the barrier is reachable at all.  The command path answers,
#           the admission assertion set is re-established, the PR generation is
#           unchanged, and a heartbeat lands.  Must HOLD.
#   waited  The same, with A's heartbeat thread paused for 12 s — under the
#           30 s lease, so authority never lapses.  Must HOLD, and it must have
#           WAITED: a barrier reading a stale last-beat stamp returns in
#           milliseconds, a barrier waiting for a beat issued after the call
#           cannot return before the pause ends.
#   lapsed  The same, with the pause set past the lease.  No beat can land
#           inside it, the authority gate closes itself at the deadline, and
#           the barrier must REFUSE — with its storage half still reporting
#           CONVERGED, so the refusal is attributable to authority and not to
#           a storage check that happened to fail at the same moment.  This arm
#           ends with A's mount forced down, which is the designed consequence
#           of losing authority, so it runs last.
#
# Usage: tests/lu_reset_barrier.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived): boot-wait plus prep_cluster, measured 72-137 s, bound 300
# + B's unmount, a native unmount of an idle mxfs mount measures 2-4 s, bound
# 60 + the PR census before 40 + the hold arm, which is two admissions (9 ms
# each, measured) and at most one heartbeat interval of waiting (2 s), bound 30
# + the waited arm, 12 s of pause plus up to one interval to consume it, bound
# 45 + the lapsed arm, the 30 s lease plus the shutdown it triggers, bound 90
# + the no-issue and PR-after checks 80 = 645 s.  Caller bound 680 s.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the node whose barrier is asked
B=${MXFS_NODE_LIST##*,}          # the other registrant, unmounted throughout
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lrb_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# THE KERNEL-LOG WINDOW MUST BE UNIQUE TO THIS LAP.  The ring survives module
# reloads and the nodes are not rebooted between laps, so a marker built from
# the arm name alone matches an EARLIER lap's marker first, and sed opens a
# range at its first match: every verdict read out of that window would belong
# to a run that has already finished.
MARKID="LRB-$LABEL-$(date +%s%N)"
PAUSEKNOB=/sys/module/mxfs/parameters/dl_inject_hb_pause_ms

echo "=== lu_reset_barrier label=$LABEL A(asked)=$A B(peer)=$B $(date -u +%FT%TZ) ==="

if [ "$(strings -a mxfs.ko | grep -c 'P307-LURESET-BARRIER')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no post-reset convergence barrier, so there is nothing here to measure"
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

mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
echo "STAGE device on $A: $DEV at +$(el)s"

# ---- 1. A must be mounted and must expose the trigger, or nothing here is a
#         measurement of the barrier.
measure "$A" 40 "$OUT/A_mounted.txt" '^MOUNT_END$' "the mxfs mount on $A" \
    "echo $MARKID-mounted > /dev/kmsg 2>/dev/null; \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); \
     echo BARF=\$(ls /sys/kernel/debug/mxfs/*/lu_reset_barrier 2>/dev/null | head -1); \
     echo KNOB=\$(test -w $PAUSEKNOB && echo yes || echo no); \
     echo MOUNT_END"
ck "$A has an mxfs mount at $MNT" "$(field "$OUT/A_mounted.txt" MOUNTED)" 1
BARF=$(field "$OUT/A_mounted.txt" BARF)
if [ -z "$BARF" ]; then
    echo "ABORT: $A exposes no lu_reset_barrier trigger under /sys/kernel/debug/mxfs — the barrier cannot be asked"
    echo "RESULT: ABORT label=$LABEL stage=trigger evidence=$OUT"; exit 2
fi
if [ "$(field "$OUT/A_mounted.txt" KNOB)" != yes ]; then
    echo "ABORT: $A has no writable $PAUSEKNOB — the two heartbeat arms cannot be armed, and a lap that ran only the hold arm would pass a barrier that holds unconditionally"
    echo "RESULT: ABORT label=$LABEL stage=knob evidence=$OUT"; exit 2
fi
echo "STAGE trigger=$BARF at +$(el)s"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=mounted evidence=$OUT"; exit 2; }

# ---- 2. B's per-nexus key, read from the TARGET's own view, and then B taken
#         out so its registration is gone.  The barrier is only reachable when
#         the admission it starts with is admitted, and that needs A to be the
#         sole registrant.
fullstatus() { timeout 40 "$SSH" "$1" "sg_persist --in --read-full-status -d $DEV 2>&1" > "$OUT/$2.fs.txt" 2>&1; }
own_key() {   # <node> <tag> -> hex key or empty
    fullstatus "$1" "$2"
    awk -v want="$1-mxfs-node" '
        /[Kk]ey[ \t]*=[ \t]*0[xX][0-9a-fA-F]+/ {
            k=$0; sub(/.*[Kk]ey[ \t]*=[ \t]*/, "", k); sub(/[^0-9a-fA-FxX].*/, "", k); cur=k; next
        }
        index($0, want) > 0 && cur != "" { print cur; exit }
    ' "$OUT/$2.fs.txt"
}
BKEY=$(own_key "$B" "B_before")
if [ -z "$BKEY" ]; then
    echo "ABORT: could not read B's per-nexus key from the target — not the topology this measures"
    echo "RESULT: ABORT label=$LABEL stage=keys evidence=$OUT"; exit 2
fi
echo "STAGE B key=$BKEY at +$(el)s"

measure "$B" 60 "$OUT/B_umount.txt" '^UMOUNT_END$' "the unmount of $B" \
    "umount $MNT; echo UMOUNT_RC=\$?; \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); echo UMOUNT_END"
ck "B unmounted cleanly" "$(field "$OUT/B_umount.txt" UMOUNT_RC)" 0
ck "B no longer holds the mount" "$(field "$OUT/B_umount.txt" MOUNTED)" 0
BKEY_AFTER=$(own_key "$B" "B_after")
ck "B's registration is gone from the target" "$([ -z "$BKEY_AFTER" ] && echo gone || echo present)" gone
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=umount evidence=$OUT"; exit 2; }
echo "STAGE B unregistered at +$(el)s"

# ---- 3. the PR state, so nothing the barrier does to the target goes
#         unnoticed.  Absorb the unit attention first: the command after one
#         reports POWER ON / RESET OCCURRED, and a reader that does not consume
#         it reports absent state that is present.
prstate_into() {   # $1 outfile, $2 what
    measure "$A" 40 "$1" '^PR_END$' "$2" \
        "sg_persist -i -k $DEV > /dev/null 2>&1; \
         echo '--- keys'; sg_persist -i -k $DEV 2>&1 | grep -a '0x' | sort; \
         echo '--- resv'; sg_persist -i -r $DEV 2>&1 | grep -aiv 'generation' | sed -n '2,6p'; \
         echo PR_END"
    sed -n '/^--- keys/,/^PR_END/p' "$1" | grep -av '^PR_END$' > "$1.state"
}
prstate_into "$OUT/A_pr_before.txt" "the PR state before the barrier is asked"

# ---- 4. the arms.  Each writes one line into the module's own trigger; the
#         verdict is read out of the module's log, because what is under test
#         is what the MODULE decided, not what a shell concluded about it.
# THE PAUSE MUST BE IN EFFECT BEFORE THE BARRIER IS ASKED, not merely armed.
# The knob is consumed at the top of the heartbeat loop, so arming it and
# writing immediately leaves a beat that was ALREADY IN FLIGHT free to complete
# inside the barrier's wait — which is a beat this node issued before the call,
# lands in milliseconds, and would make the waited arm report no wait at all
# while the implementation under test was perfectly correct.  So the arm waits
# for the module's own P-HB-INJECT-PAUSE line, in this arm's window, first.  Its
# own bound is three heartbeat intervals; longer means the knob was not taken,
# and the arm's vacuity check says so.
arm() {   # $1 name, $2 timeout-s, $3 pause-ms (0 = none)
    local name=$1 tmo=$2 pause=$3
    measure "$A" "$tmo" "$OUT/A_arm_${name}.txt" '^ARM_END$' "arm $name on $A" \
        "echo '$MARKID-$name' > /dev/kmsg 2>/dev/null; \
         if [ '$pause' != 0 ]; then \
             echo '$pause' > $PAUSEKNOB; \
             i=0; \
             while [ \$i -lt 30 ]; do \
                 dmesg | sed -n '/$MARKID-$name/,\$p' | grep -aq 'P-HB-INJECT-PAUSE' && break; \
                 i=\$((i+1)); sleep 0.2; \
             done; \
             echo PAUSE_POLLS=\$i; \
         fi; \
         s=\$(date +%s%N); \
         echo '0 $BKEY' > $BARF 2>/dev/null; \
         echo BAR_RC=\$?; \
         e=\$(date +%s%N); echo WALL_MS=\$(( (e-s)/1000000 )); \
         echo 0 > $PAUSEKNOB 2>/dev/null; \
         dmesg | sed -n '/$MARKID-$name/,\$p' | grep -a 'P307-LURESET\|P306-LURESET\|P305-LURESET\|P-HB-INJECT-PAUSE\|P290-AUTH-CLOSED\|P290-AUTH-HB-STOP\|Shutting down filesystem' | sed 's/^/DMESG: /'; \
         echo ARM_END"
    grep -a '^DMESG: ' "$OUT/A_arm_${name}.txt" > "$OUT/A_arm_${name}.dmesg"
}
# Fields are read from the line that carries them, never from the whole file: a
# barrier lap prints three different P307 lines and several of their field names
# collide.
barfield()  { grep -a 'P307-LURESET-BARRIER'  "$OUT/A_arm_$1.dmesg" | head -1 | grep -ao "$2=[^ ]*" | head -1 | cut -d= -f2; }
convfield() { grep -a 'P307-LURESET-CONVERGE' "$OUT/A_arm_$1.dmesg" | head -1 | grep -ao "$2=[^ ]*" | head -1 | cut -d= -f2; }
probefield(){ grep -a 'P307-LURESET-PROBE'    "$OUT/A_arm_$1.dmesg" | head -1 | grep -ao "$2=[^ ]*" | head -1 | cut -d= -f2; }
haspause()  { grep -ac 'P-HB-INJECT-PAUSE'    "$OUT/A_arm_$1.dmesg"; }

# hold — THE CONTROL ARM.  If this refuses, every refusal below proves nothing.
arm hold 40 0
ck "hold: the controlled probe answered"          "$([ -n "$(probefield hold ms)" ] && echo yes || echo no)" yes
ck "hold: one probe was enough"                   "$(probefield hold tries)" 1
ck "hold: the storage half converged"             "$(convfield hold converged)" 1
ck "hold: it said so"                             "$(convfield hold reason)" converged
ck "hold: the re-admission was admitted"          "$(convfield hold readmit)" admitted
ck "hold: A is still the only registrant"         "$(convfield hold other_n)" 0
# THE CONTINUITY CHECK, NAMED.  converged=1 already implies it passed, but a
# lap that never reads the two generations cannot tell a barrier that compares
# them from one that dropped the comparison: both print converged=1 on a quiet
# LUN.  Assert the pair, and assert that it is a real generation and not the
# zero an unparsed field would give.
GEN_B=$(convfield hold gen_before); GEN_A=$(convfield hold gen_after)
ck "hold: the PR generation did not move across the barrier" \
   "$([ -n "$GEN_B" ] && [ "$GEN_B" = "$GEN_A" ] && echo same || echo "differ($GEN_B/$GEN_A)")" same
ckge "hold: and it is a generation the target actually reports" "$GEN_B" 1
ck "hold: the barrier HELD"                       "$(barfield hold held)" 1
ck "hold: a heartbeat landed after the call"      "$(barfield hold beat_landed)" 1
ck "hold: the write succeeded"                    "$(field "$OUT/A_arm_hold.txt" BAR_RC)" 0
echo "FINDING hold gen=$GEN_B->$GEN_A probe_ms=$(probefield hold ms) total_ms=$(convfield hold total_ms) wait_ms=$(barfield hold wait_ms) wall_ms=$(field "$OUT/A_arm_hold.txt" WALL_MS) at +$(el)s"

# waited — the barrier must wait for a beat ISSUED AFTER the call, not read the
# last one.  12 s of pause is under the 30 s lease, so authority never lapses
# and the only visible difference between the two implementations is the wait.
arm waited 60 12000
if [ "$(haspause waited)" = 0 ]; then
    echo "VACUOUS: the heartbeat pause was never taken (no P-HB-INJECT-PAUSE in the arm window), so this arm measured a healthy cluster twice"
    echo "RESULT: VACUOUS label=$LABEL stage=waited evidence=$OUT"; exit 3
fi
ck "waited: the barrier still HELD"               "$(barfield waited held)" 1
ck "waited: a heartbeat landed after the call"    "$(barfield waited beat_landed)" 1
ck "waited: the write succeeded"                  "$(field "$OUT/A_arm_waited.txt" BAR_RC)" 0
ckge "waited: it WAITED for that beat (ms)"       "$(barfield waited wait_ms)" 5000
echo "FINDING waited wait_ms=$(barfield waited wait_ms) gen=$(convfield waited gen_before)->$(convfield waited gen_after) wall_ms=$(field "$OUT/A_arm_waited.txt" WALL_MS) at +$(el)s"

# ---- 5. the barrier's own RESERVE changed nothing, MEASURED BEFORE THE ARM
#         THAT COSTS A's AUTHORITY.  The lapsed arm ends with A self-fenced, and
#         a withdrawal retires this node's registration on purpose — so a
#         key-set comparison taken after it would report the designed
#         withdrawal and say nothing about what the barrier did to the target.
prstate_into "$OUT/A_pr_after.txt" "the PR state after the two holding arms"
normkeys() { grep -aoE '0x[0-9a-fA-F]+' "$1" | sed 's/^0x0*//' | tr 'A-F' 'a-f' | sort -u; }
for t in before after; do
    sed -n '/^--- keys/,/^--- resv/p' "$OUT/A_pr_$t.txt.state" | grep -av 'generation' \
        > "$OUT/keys_$t.txt"
    normkeys "$OUT/keys_$t.txt" > "$OUT/keys_$t.norm"
    sed -n '/^--- resv/,$p' "$OUT/A_pr_$t.txt.state" > "$OUT/resv_$t.txt"
done
ck "the reservation stanza is byte-identical across the holding arms" \
   "$(cmp -s "$OUT/resv_before.txt" "$OUT/resv_after.txt" && echo identical || echo changed)" identical
ck "no registration appeared or vanished across the holding arms" \
   "$(cmp -s "$OUT/keys_before.norm" "$OUT/keys_after.norm" && echo unchanged || echo moved)" unchanged

# lapsed — THE REFUSAL.  The pause runs past the lease, no beat can land inside
# it, and the authority gate closes itself at the deadline.  The storage half
# must STILL report converged, or the refusal is not attributable to authority.
arm lapsed 90 45000
if [ "$(haspause lapsed)" = 0 ]; then
    echo "VACUOUS: the heartbeat pause was never taken in the lapsed arm, so the lease had no reason to expire"
    echo "RESULT: VACUOUS label=$LABEL stage=lapsed evidence=$OUT"; exit 3
fi
ck "lapsed: the storage half STILL converged"     "$(convfield lapsed converged)" 1
ck "lapsed: the barrier REFUSED"                  "$(barfield lapsed held)" 0
ck "lapsed: no heartbeat landed after the call"   "$(barfield lapsed beat_landed)" 0
ck "lapsed: the write was refused too"            "$([ "$(field "$OUT/A_arm_lapsed.txt" BAR_RC)" != 0 ] && echo refused || echo accepted)" refused
ckge "lapsed: it waited out the lease (ms)"       "$(barfield lapsed wait_ms)" 20000
# THE MECHANISM, NOT ONLY THE VERDICT.  A refusal that happened for some other
# reason would satisfy every assertion above; the module must name the lapse in
# its own log, in this arm's window.
ck "lapsed: the module closed the authority lease itself" \
   "$(grep -ac 'P290-AUTH-CLOSED' "$OUT/A_arm_lapsed.dmesg")" 1
echo "FINDING lapsed wait_ms=$(barfield lapsed wait_ms) deadline_ms=$(barfield lapsed deadline_ms) wall_ms=$(field "$OUT/A_arm_lapsed.txt" WALL_MS) at +$(el)s"

# ---- 6. the barrier issued no reset, on any arm.  A lap that reset the
#         logical unit measured something other than the barrier.
measure "$A" 40 "$OUT/A_noissue.txt" '^NOISSUE_END$' "whether any reset was issued on $A" \
    "echo ISSUES=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'P305-LURESET-ISSUE'); \
     echo VERDICTS=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'P305-LURESET-VERDICT'); \
     echo OOPS=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'BUG:\|Oops\|general protection'); \
     echo NOISSUE_END"
ck "no LOGICAL UNIT RESET was issued in this lap" "$(field "$OUT/A_noissue.txt" ISSUES)" 0
ck "no reset verdict was reached in this lap"     "$(field "$OUT/A_noissue.txt" VERDICTS)" 0
ck "no BUG or Oops on A"                          "$(field "$OUT/A_noissue.txt" OOPS)" 0

echo "=== lu_reset_barrier label=$LABEL fails=$fails wall=$(el)s evidence=$OUT ==="
[ $fails = 0 ] && { echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0; }
echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
