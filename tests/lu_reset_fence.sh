#!/bin/bash
# lu_reset_fence.sh — does the witnessed-LU-reset fence mint a certificate
# when its whole construction contract held, and REFUSE whenever any part of
# it did not?
#
# WHAT THIS IS FOR.  When the target has already purged a dead node's
# registration there is nothing left for a PREEMPT AND ABORT to NAME, so every
# fence attempt classifies KEY_ABSENT_UNPROVEN however often it is retried,
# and the dead node's journal slice can never be replayed.  The route out is a
# LOGICAL UNIT RESET: an operation whose own defined effect is to terminate
# the tasks of every I_T nexus attached to the unit, which reaches the
# victim's already-accepted work whatever became of its registration.  That is
# a retirement witness.  It is also destructive, and it is worth nothing
# unless the node that issued it can prove, afterwards, that it still holds
# the authority the certificate would be acted on under.
#
# So the certificate rests on four facts, and this lap measures one arm per
# fact — each arm removing exactly one of them and requiring the refusal:
#
#   peer     Another initiator is registered on the unit.  The reset's scope
#            is the whole logical unit, so its work would be collateral.  Must
#            REFUSE, and — the assertion that matters — must issue NOTHING:
#            the gate sits before the command boundary or it is not a gate.
#   krel     This node is the sole registrant, so admission would pass, but
#            the audited-kernel pin is told a release the build has not read.
#            The witness's per-operation meaning rests on a kernel-internal
#            one-TMF-per-session invariant rather than on any correlator on
#            the wire, so a release nobody audited is a witness nobody can
#            use.  Must REFUSE, and again must issue NOTHING — spending a
#            bystander's in-flight I/O on a witness this build could not have
#            used afterwards is pure damage.
#   certify  Every fact present.  A REAL LOGICAL UNIT RESET is issued against
#            the shipping LUN, witnessed, and the post-reset barrier holds.
#            Must CERTIFY, with kind 24 and all three retirement fields set
#            together — the consumer demotes any proving kind back to
#            KEY_ABSENT_UNPROVEN when the basis is NONE, so a half-filled
#            certificate is not a weaker one, it is none at all.
#   lapsed   Every fact present except the last: the heartbeat is paused past
#            the authority lease, so the reset is issued and witnessed and
#            THEN the barrier refuses.  Must NOT certify, and its storage half
#            must still report converged, so the refusal is attributable to
#            authority and not to a storage check that failed at the same
#            moment.  A witnessed reset plus a lapsed lease is exactly the
#            state that must leave a resumable durable intent and no
#            certificate.  It costs this node its authority, so it runs last.
#
# WHY THE CERTIFY ARM IS NOT OPTIONAL.  A fence that refused everything would
# pass all three refusal arms and protect nothing, and it would also never
# retire anybody's work, which is the defect this whole route exists to close.
# The control arm is the one that has to issue the reset.
#
# Usage: tests/lu_reset_fence.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived): boot-wait plus prep_cluster, measured 72-137 s, bound 300
# + the peer arm, one admission (9 ms measured) against a two-registrant
#   table, bound 30
# + B's unmount, a native unmount of an idle mxfs mount measures 2-4 s, bound
#   60 + the PR census before 40
# + the krel arm, a pin read with no target command at all, bound 30
# + the certify arm: admission 9 ms + the upcall, whose helper does two sysfs
#   snapshots either side of one ioctl, + the reset itself under libiscsi's
#   30 s task-management timeout + the barrier, which is one PR IN, one
#   re-admission and at most one heartbeat interval of waiting, bound 120
# + the PR census after 40
# + the lapsed arm: the same again with a 45 s pause and the 30 s lease to
#   wait out, plus the shutdown losing authority triggers, bound 150
# + the reset-count and oops checks 40 = 810 s.  Caller bound 850 s.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the node that fences
B=${MXFS_NODE_LIST##*,}          # the other registrant, unmounted after arm 1
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lrf_$LABEL
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
MARKID="LRF-$LABEL-$(date +%s%N)"
PAUSEKNOB=/sys/module/mxfs/parameters/dl_inject_hb_pause_ms
KRELKNOB=/sys/module/mxfs/parameters/lu_reset_krel_probe
HELPKNOB=/sys/module/mxfs/parameters/lu_reset_helper
# A release string the pin cannot possibly carry.  It names itself so a reader
# of the kernel log knows immediately that it is an injected value.
FAKEKREL="0.0.0-mxfs-unaudited-probe"

echo "=== lu_reset_fence label=$LABEL A(fencer)=$A B(peer)=$B $(date -u +%FT%TZ) ==="

if [ "$(strings -a mxfs.ko | grep -c 'P308-LURESET-FENCE')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no witnessed-LU-reset fence, so there is nothing here to measure"
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

# ---- 1. the preconditions, every one of which makes the difference between a
#         measurement and a lap that could not have measured anything.
#
#         THE HELPER IS ONE OF THEM AND IT IS NODE-LOCAL BY DESIGN: a fence
#         that upcalled into the build host's NFS export would make one node's
#         storage recovery depend on another machine being up.  The module's
#         own parameter says where it will look, so that is what is checked —
#         a path this lap assumed would be a lap that proves a helper exists
#         somewhere the module never reads.
measure "$A" 60 "$OUT/A_pre.txt" '^PRE_END$' "the preconditions on $A" \
    "echo $MARKID-pre > /dev/kmsg 2>/dev/null; \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); \
     echo FENCEF=\$(ls /sys/kernel/debug/mxfs/*/lu_reset_fence 2>/dev/null | head -1); \
     echo PAUSEW=\$(test -w $PAUSEKNOB && echo yes || echo no); \
     echo KRELW=\$(test -w $KRELKNOB && echo yes || echo no); \
     HELPER=\$(cat $HELPKNOB 2>/dev/null); echo HELPER=\$HELPER; \
     echo HELPEROK=\$([ -n \"\$HELPER\" ] && [ -x \"\$HELPER\" ] && echo yes || echo no); \
     echo CHAN=\$([ -e /proc/fs/mxfs/lu_reset_report ] && echo yes || echo no); \
     echo KREL=\$(uname -r); \
     echo PRE_END"
ck "$A has an mxfs mount at $MNT" "$(field "$OUT/A_pre.txt" MOUNTED)" 1
FENCEF=$(field "$OUT/A_pre.txt" FENCEF)
KREL=$(field "$OUT/A_pre.txt" KREL)
abort_pre() { echo "ABORT: $1"; echo "RESULT: ABORT label=$LABEL stage=pre evidence=$OUT"; exit 2; }
[ -n "$FENCEF" ] || abort_pre "$A exposes no lu_reset_fence trigger under /sys/kernel/debug/mxfs — the fence cannot be asked"
[ "$(field "$OUT/A_pre.txt" PAUSEW)" = yes ] || abort_pre "$A has no writable $PAUSEKNOB — the lapsed arm cannot be armed, and a lap without it would pass a fence that certifies whatever the barrier said"
[ "$(field "$OUT/A_pre.txt" KRELW)" = yes ] || abort_pre "$A has no writable $KRELKNOB — the audited-kernel pin's refusal cannot be exercised"
[ "$(field "$OUT/A_pre.txt" HELPEROK)" = yes ] || abort_pre "$A has no executable witness helper at the path the module reads ($(field "$OUT/A_pre.txt" HELPER)) — every reset would refuse for that reason and the certify arm would measure the missing file"
[ "$(field "$OUT/A_pre.txt" CHAN)" = yes ] || abort_pre "$A has no /proc/fs/mxfs/lu_reset_report channel — the helper would have nowhere to report and every witness would be INDETERMINATE"
echo "STAGE trigger=$FENCEF krel=$KREL helper=$(field "$OUT/A_pre.txt" HELPER) at +$(el)s"
[ $fails = 0 ] || abort_pre "preconditions"

# ---- 2. the arms.  Each writes one line into the module's own trigger; the
#         verdict is read out of the module's log, because what is under test
#         is what the MODULE decided, not what a shell concluded about it.
arm() {   # $1 name, $2 timeout-s, $3 pause-ms (0 = none), $4 krel-probe ("" = none)
    local name=$1 tmo=$2 pause=$3 fakekrel=$4
    measure "$A" "$tmo" "$OUT/A_arm_${name}.txt" '^ARM_END$' "arm $name on $A" \
        "echo '$MARKID-$name' > /dev/kmsg 2>/dev/null; \
         if [ -n '$fakekrel' ]; then echo '$fakekrel' > $KRELKNOB; fi; \
         echo KRELSET=\$(cat $KRELKNOB 2>/dev/null); \
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
         echo '0 $VKEY' > $FENCEF 2>/dev/null; \
         echo FENCE_RC=\$?; \
         e=\$(date +%s%N); echo WALL_MS=\$(( (e-s)/1000000 )); \
         echo 0 > $PAUSEKNOB 2>/dev/null; \
         echo '' > $KRELKNOB 2>/dev/null; \
         dmesg | sed -n '/$MARKID-$name/,\$p' | grep -a 'P308-LURESET\|P307-LURESET\|P306-LURESET\|P305-LURESET\|P-HB-INJECT-PAUSE\|P290-AUTH-CLOSED\|Shutting down filesystem' | sed 's/^/DMESG: /'; \
         echo ARM_END"
    grep -a '^DMESG: ' "$OUT/A_arm_${name}.txt" > "$OUT/A_arm_${name}.dmesg"
}
# Fields are read from the LINE that carries them, never from the whole file: a
# fence lap prints five different P30x lines and several of their field names
# collide (gen_after, rc, reason).
ffield()  { grep -a 'P308-LURESET-FENCE'   "$OUT/A_arm_$1.dmesg" | head -1 | grep -ao "$2=[^ ]*" | head -1 | cut -d= -f2; }
wfield()  { grep -a 'P305-LURESET-VERDICT' "$OUT/A_arm_$1.dmesg" | head -1 | grep -ao "$2=[^ ]*" | head -1 | cut -d= -f2; }
nresets() { grep -ac 'P305-LURESET-VERDICT' "$OUT/A_arm_$1.dmesg"; }
haspause(){ grep -ac 'P-HB-INJECT-PAUSE'   "$OUT/A_arm_$1.dmesg"; }

# VKEY — the victim's key.  0 names no particular registration, which is
# exactly the case this route exists for: the target purged the dead node's
# descriptor, so there is no key left to name.  The admission gate's job is to
# establish that the table holds ONE descriptor and it is ours, and a named
# victim key would only give it a second thing to look for.
VKEY=0

# ---- arm 1: another initiator is registered.  B is still mounted, so the
#      unit carries two descriptors and an LU-scope reset would take B's
#      accepted work with it.  Run FIRST, because every later arm needs B gone.
arm peer 40 0 ""
ck "peer: the fence refused"                       "$(ffield peer certified)" 0
ck "peer: and named the reason"                    "$(ffield peer verdict)" not-admitted
ck "peer: the admission gate was actually asked"   "$(ffield peer admit_run)" 1
ck "peer: it saw the other registrant"             "$(ffield peer admission)" another-initiator-is-registered
ck "peer: NOTHING was issued"                      "$(ffield peer issued)" 0
ck "peer: and no reset verdict was even reached"   "$(nresets peer)" 0
ck "peer: the result is not a proving kind"        "$(ffield peer basis)" none
echo "FINDING peer verdict=$(ffield peer verdict) admission=$(ffield peer admission) wall_ms=$(field "$OUT/A_arm_peer.txt" WALL_MS) at +$(el)s"

# ---- 3. B out, so A is the sole registrant — the shape a death whose
#         registration the target purged leaves behind, and the only shape in
#         which this route is reachable at all.
measure "$B" 60 "$OUT/B_umount.txt" '^UMOUNT_END$' "the unmount of $B" \
    "umount $MNT; echo UMOUNT_RC=\$?; \
     echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts); echo UMOUNT_END"
ck "B unmounted cleanly"          "$(field "$OUT/B_umount.txt" UMOUNT_RC)" 0
ck "B no longer holds the mount"  "$(field "$OUT/B_umount.txt" MOUNTED)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=umount evidence=$OUT"; exit 2; }
echo "STAGE B unregistered at +$(el)s"

# ---- 4. the PR state, so what the reset does to the target does not go
#         unnoticed.  Absorb the unit attention first: the command after a
#         reset reports POWER ON / RESET OCCURRED, and a reader that does not
#         consume it reports absent state that is present.
prstate_into() {   # $1 outfile, $2 what
    measure "$A" 40 "$1" '^PR_END$' "$2" \
        "sg_persist -i -k $DEV > /dev/null 2>&1; \
         echo '--- keys'; sg_persist -i -k $DEV 2>&1 | grep -a '0x' | sort; \
         echo '--- resv'; sg_persist -i -r $DEV 2>&1 | grep -aiv 'generation' | sed -n '2,6p'; \
         echo PR_END"
    sed -n '/^--- keys/,/^PR_END/p' "$1" | grep -av '^PR_END$' > "$1.state"
}
prstate_into "$OUT/A_pr_before.txt" "the PR state before any reset is issued"

# ---- arm 2: the audited-kernel pin.  A is the sole registrant now, so
#      admission WOULD pass; the only thing removed is the pin's answer.  The
#      injector is refusal-only by construction — the module ignores a value
#      the pin would accept — so this arm cannot accidentally be measuring a
#      pin that was talked into agreeing.
arm krel 40 0 "$FAKEKREL"
if [ "$(grep -ac 'P308-LURESET-KRELPROBE substituting' "$OUT/A_arm_krel.dmesg")" = 0 ]; then
    echo "VACUOUS: the kernel-pin injector was never taken (no P308-LURESET-KRELPROBE line in the arm window), so this arm asked the pin about the running kernel and measured the certify arm twice"
    echo "RESULT: VACUOUS label=$LABEL stage=krel evidence=$OUT"; exit 3
fi
ck "krel: the fence refused"                       "$(ffield krel certified)" 0
ck "krel: and named the pin"                       "$(ffield krel verdict)" kernel-unaudited
ck "krel: NOTHING was issued"                      "$(ffield krel issued)" 0
ck "krel: and no reset verdict was even reached"   "$(nresets krel)" 0
# THE ORDER IS THE POINT.  The pin must be read BEFORE the admission gate runs
# its RESERVE, so a refusal here touches the target not at all.
ck "krel: the admission gate was never even asked" "$(ffield krel admit_run)" 0
ck "krel: the injected release is the one it saw"  "$(ffield krel krel)" "$FAKEKREL"
echo "FINDING krel verdict=$(ffield krel verdict) krel=$(ffield krel krel) wall_ms=$(field "$OUT/A_arm_krel.txt" WALL_MS) at +$(el)s"

# ---- arm 3: THE CONTROL.  Every fact present.  This issues a real LOGICAL
#      UNIT RESET against the shipping LUN.
arm certify 120 0 ""
ck "certify: a LOGICAL UNIT RESET was issued"      "$(ffield certify issued)" 1
ck "certify: exactly one reset verdict was reached" "$(nresets certify)" 1
ck "certify: the target answered it"               "$(ffield certify pal)" WITNESSED
ck "certify: the witness names this kernel"        "$(ffield certify krel)" "$KREL"
ck "certify: the admission gate was asked"         "$(ffield certify admit_run)" 1
ck "certify: and admitted"                         "$(ffield certify admitted)" 1
ck "certify: the storage half converged"           "$(ffield certify converged)" 1
ck "certify: the storage half said so"             "$(ffield certify storage)" converged
ck "certify: THE FENCE CERTIFIED"                  "$(ffield certify certified)" 1
ck "certify: and said so"                          "$(ffield certify verdict)" certified
ck "certify: the write succeeded"                  "$(field "$OUT/A_arm_certify.txt" FENCE_RC)" 0
# THE THREE RETIREMENT FIELDS, ASSERTED SEPARATELY.  The consumer demotes any
# proving kind back to KEY_ABSENT_UNPROVEN when the basis is NONE, so a lap
# that read only the kind could pass on a certificate that authorises nothing.
ck "certify: the durable kind is the witnessed-LU-reset profile" "$(ffield certify kind)" 24
ck "certify: the phase is VERIFIED"                "$(ffield certify phase)" VERIFIED
ck "certify: the retirement basis is a completed target operation" \
   "$(ffield certify basis)" completed-target-op
ck "certify: the claim is the reset's own defined effect" \
   "$(ffield certify claim)" witnessed-lu-reset-terminated-all-tasks-on-the-unit
ck "certify: the observation is the sole-registrant one" \
   "$(ffield certify obs)" sole-registrant-victim-absent
# THE GENERATION CONTINUITY, NAMED.  converged=1 already implies the check
# passed, but a lap that never reads the two generations cannot tell a barrier
# that compares them from one that dropped the comparison.
GEN_B=$(ffield certify gen_admit); GEN_A=$(ffield certify gen_after)
ck "certify: the PR generation did not move across the reset" \
   "$([ -n "$GEN_B" ] && [ "$GEN_B" = "$GEN_A" ] && echo same || echo "differ($GEN_B/$GEN_A)")" same
ckge "certify: and it is a generation the target actually reports" "$GEN_B" 1
echo "FINDING certify kind=$(ffield certify kind) basis=$(ffield certify basis) reset_ms=$(ffield certify reset_ms) total_ms=$(ffield certify total_ms) gen=$GEN_B->$GEN_A wall_ms=$(field "$OUT/A_arm_certify.txt" WALL_MS) at +$(el)s"

# ---- 5. what the reset did to the target's PR state, MEASURED BEFORE THE ARM
#         THAT COSTS A's AUTHORITY.  A LOGICAL UNIT RESET is a task-management
#         function: it terminates tasks and must leave registrations and the
#         reservation exactly as they were.  If it cleared them, every
#         assertion above would still pass while the cluster's exclusion had
#         silently been taken down.
prstate_into "$OUT/A_pr_after.txt" "the PR state after the witnessed reset"
normkeys() { grep -aoE '0x[0-9a-fA-F]+' "$1" | sed 's/^0x0*//' | tr 'A-F' 'a-f' | sort -u; }
for t in before after; do
    sed -n '/^--- keys/,/^--- resv/p' "$OUT/A_pr_$t.txt.state" | grep -av 'generation' \
        > "$OUT/keys_$t.txt"
    normkeys "$OUT/keys_$t.txt" > "$OUT/keys_$t.norm"
    sed -n '/^--- resv/,$p' "$OUT/A_pr_$t.txt.state" > "$OUT/resv_$t.txt"
done
ck "the reservation survived the reset byte-identical" \
   "$(cmp -s "$OUT/resv_before.txt" "$OUT/resv_after.txt" && echo identical || echo changed)" identical
ck "no registration appeared or vanished across the reset" \
   "$(cmp -s "$OUT/keys_before.norm" "$OUT/keys_after.norm" && echo unchanged || echo moved)" unchanged

# ---- arm 4: the reset happens and the authority does not survive it.  The
#      pause runs past the 30 s lease, so no beat can land inside it and the
#      authority gate closes itself at the deadline.  This is the arm that
#      separates a fence which certifies because the barrier held from one
#      that certifies because it reached the end of a function.
arm lapsed 150 45000 ""
if [ "$(haspause lapsed)" = 0 ]; then
    echo "VACUOUS: the heartbeat pause was never taken in the lapsed arm, so the lease had no reason to expire and this arm measured the certify arm twice"
    echo "RESULT: VACUOUS label=$LABEL stage=lapsed evidence=$OUT"; exit 3
fi
ck "lapsed: a LOGICAL UNIT RESET was still issued"  "$(ffield lapsed issued)" 1
ck "lapsed: the target answered it"                 "$(ffield lapsed pal)" WITNESSED
ck "lapsed: the storage half STILL converged"       "$(ffield lapsed converged)" 1
ck "lapsed: THE FENCE REFUSED TO CERTIFY"           "$(ffield lapsed certified)" 0
ck "lapsed: and named the barrier"                  "$(ffield lapsed verdict)" barrier-refused
ck "lapsed: the write was refused too" \
   "$([ "$(field "$OUT/A_arm_lapsed.txt" FENCE_RC)" != 0 ] && echo refused || echo accepted)" refused
# NO HALF-CERTIFICATE.  The reset really happened here, so this is the exact
# state in which a fence that carried the kind forward without its basis would
# hand a consumer something that reads like proof.
ck "lapsed: no proving kind was minted"             "$(ffield lapsed kind)" 6
ck "lapsed: no retirement basis was claimed"        "$(ffield lapsed basis)" none
ck "lapsed: no retirement claim was made"           "$(ffield lapsed claim)" none
# THE PHASE IS WHAT STOPS A RE-DRIVE.  A retryable attempt is one where
# nothing was submitted; this one submitted a reset.
ck "lapsed: the attempt is recorded as having submitted" \
   "$(ffield lapsed phase)" MAY_HAVE_SUBMITTED
# THE MECHANISM, NOT ONLY THE VERDICT.  A refusal that happened for some other
# reason would satisfy every assertion above; the module must name the lapse.
ck "lapsed: the module closed the authority lease itself" \
   "$(grep -ac 'P290-AUTH-CLOSED' "$OUT/A_arm_lapsed.dmesg")" 1
echo "FINDING lapsed verdict=$(ffield lapsed verdict) kind=$(ffield lapsed kind) reset_ms=$(ffield lapsed reset_ms) total_ms=$(ffield lapsed total_ms) wall_ms=$(field "$OUT/A_arm_lapsed.txt" WALL_MS) at +$(el)s"

# ---- 6. the whole-lap accounting.  Exactly two resets were issued — one per
#         arm that was supposed to issue one — and neither refusal arm issued
#         anything at all.  A lap that reset the unit four times measured
#         something other than the gate.
measure "$A" 40 "$OUT/A_tally.txt" '^TALLY_END$' "the whole-lap reset tally on $A" \
    "echo VERDICTS=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -ac 'P305-LURESET-VERDICT'); \
     echo WITNESSED=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -a 'P305-LURESET-VERDICT' | grep -ac 'verdict=WITNESSED'); \
     echo FENCES=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -ac 'P308-LURESET-FENCE'); \
     echo CERTS=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -a 'P308-LURESET-FENCE' | grep -ac 'certified=1'); \
     echo OOPS=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -ac 'BUG:\|Oops\|general protection'); \
     echo CORRUPT=\$(dmesg | sed -n '/$MARKID-pre/,\$p' | grep -ac 'Corruption of in-memory'); \
     echo TALLY_END"
ck "exactly two LOGICAL UNIT RESETS were issued in this lap" "$(field "$OUT/A_tally.txt" VERDICTS)" 2
ck "and the target witnessed both"                           "$(field "$OUT/A_tally.txt" WITNESSED)" 2
ck "the fence was asked four times"                          "$(field "$OUT/A_tally.txt" FENCES)" 4
ck "and certified exactly once"                              "$(field "$OUT/A_tally.txt" CERTS)" 1
ck "no BUG or Oops on A"                                     "$(field "$OUT/A_tally.txt" OOPS)" 0
ck "no in-memory corruption reported on A"                   "$(field "$OUT/A_tally.txt" CORRUPT)" 0

echo "=== lu_reset_fence label=$LABEL fails=$fails wall=$(el)s evidence=$OUT ==="
[ $fails = 0 ] && { echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0; }
echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
