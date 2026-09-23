#!/bin/bash
# lu_reset_admit_gate.sh — does the module refuse an LU-scope reset while
# another initiator is registered, and admit one when it is the only registrant?
#
# WHAT THIS IS FOR.  A LOGICAL UNIT RESET reaches work whose originating iSCSI
# session is gone, which is why MXFS wants it: a target that purges a
# registration together with the session destroys the evidence PREEMPT AND
# ABORT needs before the first fence attempt is even made.  But the reset's
# scope is the LOGICAL UNIT, so it terminates the tasks of every I_T nexus
# attached to it.  The admission gate is the rule that decides when an LU-scope
# operation is the right tool at all, and this lap measures the gate — nothing
# here issues a reset, and one of the assertions is that nothing did.
#
# WHY A REFUSAL IS NOT ENOUGH, AND WHY THE CONTROL ARM IS THE LAST ONE.  A gate
# that refused everything — a census that never parses, a reservation read that
# always fails, a typo in a comparison — would pass every refusal arm in this
# file and fail nobody.  So the lap ends with an arm that MUST be ADMITTED, on
# the same build, against the same LUN, minutes apart.  The refusals only mean
# something beside it.
#
# THE ARMS.
#   peer     A and B both mounted, no victim named.  Two registrations exist,
#            so an LU reset would strand a live member's in-flight I/O for
#            nothing: the gate must refuse with
#            reason=another-initiator-is-registered.
#   victim   A and B both mounted, and B's OWN key (read from the target's READ
#            FULL STATUS, not from a file) named as the victim.  A registered
#            victim can be fenced by the precisely-scoped key preempt, so the
#            gate must refuse naming THAT fact —
#            reason=victim-is-registered-preempt-and-abort-applies — because the
#            useful refusal tells the caller which operation to run instead.
#   sole     B unmounted, so its registration is gone and A is the only
#            registrant, which is exactly the shape a purged-registration death
#            leaves behind.  The gate must ADMIT, with own_n=1, other_n=0 and
#            the all-registrants reservation still in force.
#
# WHAT ELSE IS ASSERTED.  The gate issues a matching-scope/type RESERVE as its
# proof that the one registration is on OUR nexus rather than a re-use of our
# key value, and that RESERVE must change nothing: the registrations and the
# reservation are captured before the first arm and after the last and must
# compare identical.  A's mount must still accept work afterwards, and there
# must be zero P305-LURESET-ISSUE lines in the whole window — a gate lap that
# reset the logical unit has tested something else.
#
# Usage: tests/lu_reset_admit_gate.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived): boot-wait plus prep_cluster, measured 72-137 s, bound 300 +
# the PR census before 40 + three arms, each one debugfs write that issues three
# PR IN commands and one PR OUT and then reads the kernel log, measured in
# milliseconds at the target, bound 40 each = 120 + B's unmount, a native
# unmount of an idle mxfs mount measures 2-4 s, bound 60 + the PR census after
# 40 + liveness and health 30 = 590 s.  Caller bound 620 s.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the node whose gate is asked
B=${MXFS_NODE_LIST##*,}          # the other registrant, unmounted for the control arm
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lrag_$LABEL
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
# to a run that has already finished.  Measured once already, on the witness
# probe: a 14 s lap reported the previous lap's nonce and a 47261 ms wall.
MARKID="LRAG-$LABEL-$(date +%s%N)"

echo "=== lu_reset_admit_gate label=$LABEL A(asked)=$A B(peer)=$B $(date -u +%FT%TZ) ==="

if [ "$(strings -a mxfs.ko | grep -c 'P306-LURESET-ADMIT')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no LU-reset admission gate, so there is nothing here to measure"
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

# ---- 1. both nodes must be mounted, or the refusal arms have no second
#         registrant and would pass for the wrong reason.
for n in "$A" "$B"; do
    measure "$n" 40 "$OUT/${n}_mounted.txt" '^MOUNT_END$' "the mxfs mount on $n" \
        "echo $MARKID-mounted > /dev/kmsg 2>/dev/null; \
         echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); \
         echo GATEF=\$(ls /sys/kernel/debug/mxfs/*/lu_reset_admit 2>/dev/null | head -1); \
         echo MOUNT_END"
    ck "$n has an mxfs mount at $MNT" "$(field "$OUT/${n}_mounted.txt" MOUNTED)" 1
done
GATEF=$(field "$OUT/${A}_mounted.txt" GATEF)
if [ -z "$GATEF" ]; then
    echo "ABORT: $A exposes no lu_reset_admit trigger under /sys/kernel/debug/mxfs — the gate cannot be asked"
    echo "RESULT: ABORT label=$LABEL stage=trigger evidence=$OUT"; exit 2
fi
echo "STAGE trigger=$GATEF at +$(el)s"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=mounted evidence=$OUT"; exit 2; }

# ---- 2. the keys, read from the TARGET's own per-nexus view.  A key taken from
#         a file or from a node's own log would not say which nexus carries it,
#         and "the victim is registered" is a statement about a nexus.
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
AKEY=$(own_key "$A" "A_before")
BKEY=$(own_key "$B" "B_before")
if [ -z "$AKEY" ] || [ -z "$BKEY" ] || [ "$AKEY" = "$BKEY" ]; then
    echo "ABORT: could not read two distinct per-nexus keys (A=$AKEY B=$BKEY) — not the topology this measures"
    echo "RESULT: ABORT label=$LABEL stage=keys evidence=$OUT"; exit 2
fi
echo "STAGE A key=$AKEY B key=$BKEY at +$(el)s"

# ---- 3. the PR state, so the gate's own RESERVE cannot change anything
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
prstate_into "$OUT/A_pr_before.txt" "the PR state before the gate is asked"

# ---- 4. the arms.  Each writes one line into the module's own trigger; the
#         verdict is read out of the module's log, because what is under test is
#         what the MODULE decided, not what a shell concluded about it.
arm() {   # $1 name, $2 victim-node, $3 victim-key
    local name=$1 vnode=$2 vkey=$3
    measure "$A" 40 "$OUT/A_arm_${name}.txt" '^ARM_END$' "arm $name on $A" \
        "echo '$MARKID-$name' > /dev/kmsg 2>/dev/null; \
         s=\$(date +%s%N); \
         echo '$vnode $vkey' > $GATEF 2>/dev/null; \
         echo ADMIT_RC=\$?; \
         e=\$(date +%s%N); echo WALL_MS=\$(( (e-s)/1000000 )); \
         dmesg | sed -n '/$MARKID-$name/,\$p' | grep -a 'P306-LURESET\|P305-LURESET' | sed 's/^/DMESG: /'; \
         echo ARM_END"
    grep -a '^DMESG: ' "$OUT/A_arm_${name}.txt" > "$OUT/A_arm_${name}.dmesg"
}
armfield() { grep -ao "$2=[^ ]*" "$OUT/A_arm_$1.dmesg" | head -1 | cut -d= -f2; }

# peer — two registrations, no victim named.  The generic refusal.
arm peer 0 0
ck "peer: the gate refused"            "$(armfield peer admitted)"  0
ck "peer: it named the other registrant" "$(armfield peer reason)"  another-initiator-is-registered
ck "peer: our key is on exactly one nexus" "$(armfield peer own_n)" 1
ckge "peer: at least one other registrant was seen" "$(armfield peer other_n)" 1
ck "peer: the write was refused too"   "$([ "$(field "$OUT/A_arm_peer.txt" ADMIT_RC)" != 0 ] && echo refused || echo accepted)" refused
echo "FINDING peer resv_type=$(armfield peer resv_type) gen=$(armfield peer gen) wall_ms=$(field "$OUT/A_arm_peer.txt" WALL_MS) at +$(el)s"

# victim — the same two registrations, but B named.  The refusal must name the
# fact that tells the caller to run the key preempt instead.
arm victim 0 "$BKEY"
ck "victim: the gate refused"          "$(armfield victim admitted)" 0
ck "victim: it named the registered victim" "$(armfield victim reason)" victim-is-registered-preempt-and-abort-applies
ck "victim: the victim's key was seen registered" "$(armfield victim victim_present)" 1
echo "FINDING victim gen=$(armfield victim gen) wall_ms=$(field "$OUT/A_arm_victim.txt" WALL_MS) at +$(el)s"

# ---- 5. take B out, so its registration is gone — the shape a death whose
#         registration the target purged leaves behind.
measure "$B" 60 "$OUT/B_umount.txt" '^UMOUNT_END$' "the unmount of $B" \
    "umount $MNT; echo UMOUNT_RC=\$?; \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); echo UMOUNT_END"
ck "B unmounted cleanly" "$(field "$OUT/B_umount.txt" UMOUNT_RC)" 0
ck "B no longer holds the mount" "$(field "$OUT/B_umount.txt" MOUNTED)" 0
BKEY_AFTER=$(own_key "$B" "B_after")
ck "B's registration is gone from the target" "$([ -z "$BKEY_AFTER" ] && echo gone || echo present)" gone
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=umount evidence=$OUT"; exit 2; }
echo "STAGE B unregistered at +$(el)s"

# sole — THE CONTROL ARM.  This must be admitted or every refusal above proves
# nothing at all.
arm sole 0 "$BKEY"
ck "sole: the gate ADMITTED"           "$(armfield sole admitted)" 1
ck "sole: it said so"                  "$(armfield sole reason)"   admitted
ck "sole: our key is on exactly one nexus" "$(armfield sole own_n)" 1
ck "sole: no other initiator is registered" "$(armfield sole other_n)" 0
ck "sole: the victim's registration is gone" "$(armfield sole victim_present)" 0
ck "sole: the all-registrants reservation is in force" "$(armfield sole resv_type)" 0x7
ck "sole: the write succeeded"          "$(field "$OUT/A_arm_sole.txt" ADMIT_RC)" 0
echo "FINDING sole gen=$(armfield sole gen) wall_ms=$(field "$OUT/A_arm_sole.txt" WALL_MS) at +$(el)s"

# ---- 6. the gate issued no reset, on any arm.  A lap that reset the logical
#         unit measured something other than admission.
measure "$A" 40 "$OUT/A_noissue.txt" '^NOISSUE_END$' "whether any reset was issued on $A" \
    "echo ISSUES=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'P305-LURESET-ISSUE'); \
     echo VERDICTS=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'P305-LURESET-VERDICT'); \
     echo NOISSUE_END"
ck "no LOGICAL UNIT RESET was issued in this lap" "$(field "$OUT/A_noissue.txt" ISSUES)" 0
ck "no reset verdict was reached in this lap"     "$(field "$OUT/A_noissue.txt" VERDICTS)" 0

# ---- 7. the gate's own RESERVE changed nothing.  Two separate statements,
#         because sg_persist prints the registration COUNT in prose ("2
#         registered reservation keys follow") and a whole-stanza diff therefore
#         reports B's intended unmount twice and says nothing about what the
#         gate did.  The reservation stanza must be byte-identical; the key set
#         may lose exactly B's key and gain nothing.
prstate_into "$OUT/A_pr_after.txt" "the PR state after the gate was asked"
normkeys() { grep -aoE '0x[0-9a-fA-F]+' "$1" | sed 's/^0x0*//' | tr 'A-F' 'a-f' | sort -u; }
for t in before after; do
    sed -n '/^--- keys/,/^--- resv/p' "$OUT/A_pr_$t.txt.state" | grep -av 'generation' \
        > "$OUT/keys_$t.txt"
    normkeys "$OUT/keys_$t.txt" > "$OUT/keys_$t.norm"
    sed -n '/^--- resv/,$p' "$OUT/A_pr_$t.txt.state" > "$OUT/resv_$t.txt"
done
if diff -q "$OUT/resv_before.txt" "$OUT/resv_after.txt" > /dev/null 2>&1; then
    ck "the gate left the reservation itself untouched" same same
else
    diff -u "$OUT/resv_before.txt" "$OUT/resv_after.txt" > "$OUT/resv_diff.txt" 2>&1
    ck "the gate left the reservation itself untouched" changed same
fi
BK=$(printf '%s' "${BKEY#0x}" | sed 's/^0*//' | tr 'A-F' 'a-f')
LEFT=$(comm -23 "$OUT/keys_before.norm" "$OUT/keys_after.norm" | tr '\n' ',' | sed 's/,$//')
JOINED=$(comm -13 "$OUT/keys_before.norm" "$OUT/keys_after.norm" | tr '\n' ',' | sed 's/,$//')
ck "the only registration that left is B's own"    "${LEFT:-none}" "$BK"
ck "no registration appeared while the gate ran"   "${JOINED:-none}" none

# ---- 8. A is still a working mount.  A gate that broke the filesystem it asked
#         about would fail the bar whatever it decided.
measure "$A" 40 "$OUT/A_health.txt" '^HEALTH_END$' "A's health after the gate" \
    "d=$MNT/lrag_$LABEL; mkdir -p \$d && printf 'post\n' > \$d/f && sync -f $MNT && echo WORK_OK; \
     echo BUGS=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'BUG:\|Oops\|kernel panic'); \
     echo SHUT=\$(dmesg | sed -n '/$MARKID-mounted/,\$p' | grep -ac 'Shutting down filesystem'); \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); \
     echo HEALTH_END"
ck "A still accepts work after the gate"  "$(cnt "$OUT/A_health.txt" '^WORK_OK$')" 1
ck "no BUG or Oops on A"                  "$(field "$OUT/A_health.txt" BUGS)" 0
ck "no filesystem shutdown on A"          "$(field "$OUT/A_health.txt" SHUT)" 0
ck "A is still mounted"                   "$(field "$OUT/A_health.txt" MOUNTED)" 1

echo "=== lu_reset_admit_gate $LABEL: fails=$fails wall=$(el)s ==="
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
