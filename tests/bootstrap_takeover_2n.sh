#!/bin/bash
# bootstrap_takeover_2n.sh — the whole-cluster BOOTSTRAP-OWNER TAKEOVER, on two
# nodes over CAW (see THE TRANSPORT IS CAW below), against a target that purges
# a registration with its session.
#
# WHAT IS UNDER TEST.  Until 0.89.16 the takeover answered an ABSENT owner key
# with a fence kind derived from bookkeeping: the node's own PR ledger saying
# FENCED, the ledger saying RETIRED, or a boot boundary showing this boot's key
# had replaced the old one on our own nexus.  None of the three ran an
# operation, and all three stamped a kind whose whole contract is that one did.
# They were deleted; the absent case now refuses with
# P-BOOT-TAKEOVER-FENCE-UNPROVEN and mints nothing.  No lap on this rig has
# ever driven a bootstrap takeover at all, so the refusal has never been
# observed from outside the source.
#
# WHY THE COUNTERFACTUAL IS THE HARD PART (design-consult ruling, session 86,
# docs/rulings/bootstrap-takeover-closure-and-the-recovery-dead-end.md).  A lap
# that only shows this build refusing an absent key proves nothing on its own.
# If none of the three antecedents held, the build that still HAD the branches
# would also have refused — by falling off the end of the same chain — so the
# lap would exercise the new refusal without ever reproducing the defect, while
# reading like a regression test for it.  The module therefore prints
# would_have_minted=<antecedent> on the refusal line, evaluated at the moment
# of the decision, and this harness grades that field.  An arm whose refusal
# says would_have_minted=none is reported as NOT REPRODUCING and is not
# credited.
#
# TWO ARMS, and they differ in exactly that field:
#   self     A CLAIMs the term, is power-cut, REBOOTS, and mounts again.  Its
#            new boot contends for its own previous boot's term.  Same host
#            uuid, different boot uuid, our own key registered, the old key
#            purged with the old session — which is the SELF-SUCCESSION
#            antecedent by construction, and the one the deleted branch (b)
#            read.  This is the arm that reproduces the defect deterministically.
#   foreign  B mounts instead and contends for A's term.  Different host, so
#            self-succession cannot hold; the ledger antecedents decide, and
#            whatever they are is recorded rather than assumed.
# 'both' runs self and then foreign, in one lap: a refusal leaves the record
# exactly as it stands, so the second arm starts from the same state.
#
# WHAT A REFUSAL MUST NOT DO.  Absence of kind 16 is not the assertion —
# absence of AUTHORITY is, because substituting any other unsupported class, or
# a spuriously "proven" one, preserves the defect exactly.  So: no certificate
# of ANY kind minted for this attempt, no P-BOOT-INHERIT, no P-BOOT-TAKEOVER
# reseal, no lineage entry, no manifest sealed, no execution lease, no recovery
# descriptor written for A1, and the durable record's owner, term, state and
# protected contents unchanged across the whole attempt.
#
# THE OBSERVER.  B stays UP and UNMOUNTED for the whole bootstrap phase, which
# is what makes the pre-cut and post-cut platter reads possible at all: once A
# is destroyed there is otherwise no node that can read the LUN.  An unmounted
# node registers no PR key and writes no heartbeat, so it does not disturb the
# whole-cluster-outage shape; its frozen slot is one of the victims either way.
# It reads the record with `chk_mxfs --bootstrap` (read-only, O_DIRECT, no
# O_EXCL) and the target's key table with `chk_mxfs --pr-keys`.
#
# THE DEAD END IS EXPECTED AND IS A SEPARATE RECORD.  A refused takeover leaves
# the term CLAIMED and owned by a key that can never come back, so every later
# mount repeats the same contend-wait-refuse.  That is filed as its own defect;
# this lap MEASURES it (the permanence arm below) rather than treating it as
# this lap's failure.  The refusal itself is the required safe behaviour.
#
# the budget rule (derived): prep <= 300 (measured 45-58) + payload ~15 +
# destroy ~10 + boot both 60-150 + module copy ~30 + A's bootstrap mount to
# P-BOOT-CLAIMED (one frozen survivor scan: 62 s dead window + 2.5 s poll,
# measured 65-75) bound 200 + captures ~40 + destroy ~10 + A boot 60-150 +
# mount attempt (abandon window 6 s + fence + unwind) bound 300 + captures ~60
# + the foreign arm (B mount attempt bound 300 + captures ~60) + the
# permanence arm (two more attempts, bound 300 each).  Summed at the BOUNDS
# rather than at the measured refusal (a refused mount took 40.5 s on the
# sibling crash-cut lap, not its 300 s bound): 60 prep + 40 payload + 15
# destroy + 150 boot + 60 module copy + 20 insmod + 200 claim + 60 captures +
# 50 cut and re-read + 640 self arm + 460 foreign arm + 240 permanence + 40
# final = 2035, and the two arms' mount attempts are the only parts that can
# grow.  Caller bound 1800 s for 'self' or 'foreign', 2600 s for 'both'.
#
# IT LEAVES THE RECORD CLAIMED AND THE FLEET UNMOUNTED.  That is the state
# under test and the harness must not clear it; the next prep's mkfs rewrites
# the record IDLE.
#
# THE TRANSPORT IS CAW, AND THAT IS A MEASURED FACT RATHER THAN A PREFERENCE.
# The whole-cluster bootstrap does not run on TCP at all.  v5_bootstrap_run has
# exactly one call site (dlm/v5_mount.c:16211); the TCP arm of
# mxfs_v5_dlm_init ends `return ctx` at :15990, and everything from :15993 is
# the CAW arm.  The tree says so at :15653 -- "the TCP transport carries its own
# durable authority ledger and no PR-fence bootstrap; the record is opened for
# the owner-liveness view only ... (bootstrap is a CAW path)".  Two laps of this
# harness on 2/tcp (s86d, s86e) drove the exact shape and neither reached a
# claim: the mount read the record, took an ordinary heartbeat slot 12 ms later,
# and was refused by the admission barrier 122 s on.  So a TCP run of this
# harness can only ever report VACUOUS, and it refuses up front rather than
# spend 430 s discovering it again.
#
# Usage: tests/bootstrap_takeover_2n.sh <label> [self|foreign|both]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, NFILES (32),
#        CLAIM_BOUND (200), JOIN_BOUND (300), MXFS_TRANSPORT (caw)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${2:-both}
case $ARM in self|foreign|both) ;; *) echo "arm must be self, foreign or both"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-caw}
if [ "$MXFS_TRANSPORT" = tcp ]; then
    echo "ABORT: the whole-cluster bootstrap is a CAW path — v5_bootstrap_run has one"
    echo "       call site and it is in the CAW arm of mxfs_v5_dlm_init, after the TCP"
    echo "       arm has returned.  On TCP the record is read for the owner-liveness"
    echo "       view and the pre-register admission gate, and never advanced, so this"
    echo "       lap cannot reach a claim.  Measured twice (s86d, s86e).  Run it as:"
    echo "       MXFS_TRANSPORT=caw $0 <label> [arm]"
    exit 2
fi
A=${MXFS_NODE_LIST%%,*}          # claims the bootstrap term, then is power-cut
B=${MXFS_NODE_LIST##*,}          # the unmounted observer, then the foreign contender
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
NFILES=${NFILES:-32}
CLAIM_BOUND=${CLAIM_BOUND:-200}
JOIN_BOUND=${JOIN_BOUND:-300}
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_btk_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
echo "=== bootstrap_takeover_2n arm=$ARM label=$LABEL A(owner)=$A B(observer)=$B $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# a field out of the BOOTSTRAP line: bs_field <file> <name>
bs_field(){ grep -a '^BOOTSTRAP state=' "$1" | head -1 | grep -ao " $2=[^ ]*" | head -1 | cut -d= -f2-; }
bad_lines() { echo $(( $(cnt "$1" 'hutting down filesystem') + $(cnt "$1" 'BUG:\|Oops') )); }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
deploy_ko() {
    local n=$1
    value_now_into got "$n" 150 "$OUT/${n}_md5_$2.txt" '^[0-9a-f]{32}$' "the module copy on $n" \
        "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n holds the tree build (md5)" "$got" "$MD5"
}
# the durable bootstrap record, read from an UNMOUNTED node, O_DIRECT
rec_into() {    # <node> <file> <what>
    measure "$1" 60 "$2" '^BOOTSTRAP ' "$3" "$CHK --bootstrap $MXFS_DEV 2>&1"
}
keys_into() {   # <node> <file> <what>
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -a 'Key=\|type:\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
normkey() { printf '0x%016x' "$(( $1 ))"; }

# ---- 0. the build, and the instrument this lap grades
if [ "$(strings -a mxfs.ko | grep -c 'would_have_minted')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no would_have_minted antecedent field on the"
    echo "       takeover refusal, so this lap cannot tell a reproduced defect"
    echo "       from a refusal that the OLD build would also have given."
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
if [ "$(strings -a tools/chk_mxfs | grep -c 'BOOTSTRAP state=')" = 0 ]; then
    echo "ABORT: tools/chk_mxfs has no --bootstrap reader (build the tools)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MD5=$(md5sum mxfs.ko | cut -c1-32)
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 "$MXFS_TRANSPORT" prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. both slices dirty, then the whole cluster dies
for n in "$A" "$B"; do
    measure "$n" 60 "$OUT/${n}_files.txt" '^FILES_END$' "$n's fsynced payload" \
        "d=$MNT/btk_${LABEL}_$n; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'btk %s %s file %s\n' $LABEL $n \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
    grep -av '^FILES_END' "$OUT/${n}_files.txt" > "$OUT/${n}_files_sha.txt"
    ck "$n fsynced $NFILES files before the outage" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/${n}_files_sha.txt")" "$NFILES"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=payload evidence=$OUT"; exit 2; }
$VIRSH destroy "$A" > /dev/null 2>&1
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE whole-cluster outage: both nodes destroyed at +$(el)s"
sleep 5
$VIRSH start "$A" > /dev/null 2>&1
$VIRSH start "$B" > /dev/null 2>&1
waitboot "$A" "$B"
deploy_ko "$A" 1
deploy_ko "$B" 1
# B: module loaded, NOT mounted.  A mount is what registers a PR key and takes
# a heartbeat slot, so an insmod alone leaves B outside the cluster entirely.
measure "$B" 60 "$OUT/B_insmod.txt" '^INSMOD_RC=' "the observer's module load" \
    "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
ck "the observer $B is loaded and NOT mounted" "$(grep -ac '^NOT_MOUNTED' "$OUT/B_insmod.txt")" 1

# ---- 2. A alone claims the bootstrap term
MARK="BTK-MARK-$LABEL"
rsx 60 "$A" "echo $MARK > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; nohup timeout $CLAIM_BOUND mount -t mxfs $MXFS_DEV $MNT > /run/btk_mount.log 2>&1 & echo LAUNCHED" > "$OUT/A_mount_launch.txt"
capture_require "$OUT/A_mount_launch.txt" '^LAUNCHED$' "A's bootstrap mount launch"
echo "STAGE A's bootstrap mount launched at +$(el)s (waiting for P-BOOT-CLAIMED, bound ${CLAIM_BOUND}s)"
wait_for_into claimed "$A" "$CLAIM_BOUND" "$MARK" "P-BOOT-CLAIMED"
if [ "$claimed" = timeout ]; then
    window_into "$OUT/A_window_noclaim.txt" "$A" 30 "$MARK"
    echo "  A never claimed the bootstrap term; its bootstrap lines:"
    grep -a 'P-BOOT' "$OUT/A_window_noclaim.txt" | sed 's/.*mxfs: /    /' | cut -c1-180 | head -10
    # MEASURED 2026-09-20 (lap s86d): the interesting case is not "no bootstrap
    # line" but "the ordinary path took it instead" — A claimed an ordinary
    # slot 12 ms after reading the record, ran 116 inline replay rounds that
    # each refused both slices, and the admission barrier refused the mount at
    # its bound.  That is the diagnosis, and it was two greps away from the
    # VACUOUS verdict, so it is printed here.
    echo "  what the mount did instead:"
    grep -a 'claimed heartbeat slot\|MXFS mount ABORTED\|recovery barrier failed\|NOT replayed' \
        "$OUT/A_window_noclaim.txt" | sed 's/.*: /    /' | cut -c1-180 | head -4
    echo "  ($(cnt "$OUT/A_window_noclaim.txt" 'NOT replayed') inline replay refusals in this window)"
    echo "RESULT: VACUOUS label=$LABEL stage=claim evidence=$OUT"; exit 3
fi
window_into "$OUT/A_at_claim.txt" "$A" 20 "$MARK"
AKEY=$(grep -a 'P-BOOT-CLAIMED' "$OUT/A_at_claim.txt" | head -1 | grep -ao 'key=0x[0-9a-f]*' | head -1 | cut -d= -f2)
ANODE=$(grep -a 'P-BOOT-CLAIMED' "$OUT/A_at_claim.txt" | head -1 | grep -ao 'node=[0-9]*' | head -1 | cut -d= -f2)
echo "STAGE A claimed at +$(el)s: owner node=$ANODE key=$AKEY"
[ -n "$AKEY" ] || { echo "RESULT: ABORT label=$LABEL stage=claim-parse evidence=$OUT"; exit 2; }

# ---- 3. THE PRE-CUT STATE, bound to one owner boot and one term.  The ledger
#         is not evidence that a registration exists on the target; PR IN is.
rec_into "$B" "$OUT/rec_1_claimed.txt" "the durable record while A owns the term"
keys_into "$B" "$OUT/K1_claimed.txt" "READ KEYS while A owns the term"
R1_STATE=$(bs_field "$OUT/rec_1_claimed.txt" state)
R1_TERM=$(bs_field "$OUT/rec_1_claimed.txt" term)
R1_OWNER=$(bs_field "$OUT/rec_1_claimed.txt" owner)
R1_KEY=$(bs_field "$OUT/rec_1_claimed.txt" key)
R1_HOST=$(bs_field "$OUT/rec_1_claimed.txt" host)
R1_BOOT=$(bs_field "$OUT/rec_1_claimed.txt" boot)
echo "STAGE record at the claim: state=$R1_STATE term=$R1_TERM owner=$R1_OWNER key=$R1_KEY host=$R1_HOST boot=$R1_BOOT"
ck "the durable record is CLAIMED" "${R1_STATE%%(*}" "CLAIMED"
ck "the durable record's crc validates" "$(bs_field "$OUT/rec_1_claimed.txt" crc)" "OK"
ck "the record names A's node as owner" "${R1_OWNER%%/*}" "$ANODE"
ck "the record names A's key as owner key" "$(normkey "$R1_KEY")" "$(normkey "$AKEY")"
ck "the owner key is REGISTERED ON THE TARGET (PR IN, not our ledger)" "$(key_present "$OUT/K1_claimed.txt" "$(normkey "$AKEY")")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=precut evidence=$OUT"; exit 2; }

# ---- 4. the cut, and the record re-read before anything can touch it
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE destroyed $A at +$(el)s (mid-CLAIMED)"
rec_into "$B" "$OUT/rec_2_aftercut.txt" "the durable record after the cut"
ck "after the cut the record still reads CLAIMED" "$(bs_field "$OUT/rec_2_aftercut.txt" state | sed 's/(.*//')" "CLAIMED"
ck "after the cut the term is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" term)" "$R1_TERM"
ck "after the cut the owner is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" owner)" "$R1_OWNER"
ck "after the cut the owner key is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" key)" "$R1_KEY"

# ---- 5. the arms.  Each is: bring the contender up, let it mount, and grade
#         the refusal and what it did NOT write.
arm_run() {     # <node> <arm-name> <tag>
    local n=$1 name=$2 tag=$3 j="$OUT/${tag}_journal.txt" ante
    local m0 mstate mterm mowner mkey

    m0="$OUT/rec_${tag}_before.txt"
    rec_into "$B" "$m0" "the record before the $name arm"
    mstate=$(bs_field "$m0" state); mterm=$(bs_field "$m0" term)
    mowner=$(bs_field "$m0" owner); mkey=$(bs_field "$m0" key)
    rsx $((JOIN_BOUND + 90)) "$n" "echo $MARK-$tag > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/${tag}_mount.txt"
    capture_require "$OUT/${tag}_mount.txt" '^(MOUNTED|NOT_MOUNTED)$' "the $name mount attempt"
    measure "$n" 60 "$j" '^JOURNAL_END$' "the kernel journal for the $name arm" \
        "dmesg | sed -n '/$MARK-$tag/,\$p' | cut -c1-600; echo JOURNAL_END"
    echo "STAGE $name arm: mount rc=$(field "$OUT/${tag}_mount.txt" MOUNT_RC) wall=$(field "$OUT/${tag}_mount.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/${tag}_mount.txt") at +$(el)s"
    grep -a 'P-BOOT-TAKEOVER\|P-BOOT-CONTENDER' "$j" | sed 's/.*mxfs: /    /' | cut -c1-230 | head -8

    # it reached the takeover, not some earlier door
    ck "$name: the mount saw the term and registered as a takeover contender" "$(cnt "$j" 'P-BOOT-TAKEOVER-CANDIDATE')" 1
    ckge "$name: the abandon window elapsed and it contended" "$(cnt "$j" 'P-BOOT-CONTENDER-ABANDONED')" 1
    ckge "$name: the refusal is the absent-key fence refusal" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-UNPROVEN')" 1
    ck "$name: it took the slotless branch (no per-slot K fence ran)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-K ')" 0
    ck "$name: no PREEMPT AND ABORT was issued against the owner key (it was absent)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-REG')" 0
    ck "$name: the mount did NOT complete" "$(grep -ac '^MOUNTED' "$OUT/${tag}_mount.txt")" 0

    # THE COUNTERFACTUAL: which antecedent the deleted chain would have read
    ante=$(grep -a 'P-BOOT-TAKEOVER-FENCE-UNPROVEN' "$j" | head -1 | grep -ao 'would_have_minted=[A-Z-]*' | head -1 | cut -d= -f2)
    echo "STAGE $name arm counterfactual: would_have_minted=${ante:-?} $(grep -a 'P-BOOT-TAKEOVER-FENCE-UNPROVEN' "$j" | head -1 | grep -ao 'ledger_rc=[-0-9]* state=[0-9]* [a-z_]*=[A-Za-z-]* same_host=[01] boot_moved=[01] ours_present=[01]' | head -1)"
    case "$name" in
        self)
            # same host, later boot, our key registered, the old one purged:
            # this is branch (b)'s antecedent by construction, so a 'none' here
            # is a broken experiment, not a passing one
            ck "$name: the refusal reproduces the deleted self-succession branch" "${ante:-none}" "SELF-SUCCESSION" ;;
        foreign)
            if [ "${ante:-none}" = none ]; then
                echo "  NOT REPRODUCING: no deleted branch's antecedent held on this arm, so the"
                echo "  build that still had them would have refused this history too.  The arm is"
                echo "  recorded as refusal coverage only and credits nothing to the fix."
            else
                echo "  this arm reproduces the deleted '${ante}' branch"
            fi ;;
    esac

    # NO AUTHORITY WAS CREATED — of any class, not merely the retired one
    ck "$name: no certificate of any kind was minted" "$(cnt "$j" 'P236-FENCE-CERTIFIED')" 0
    ck "$name: no fence kind was stamped on a takeover outcome" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-DONE\|P-BOOT-TAKEOVER-KIND')" 0
    ck "$name: the term was not inherited" "$(cnt "$j" 'P-BOOT-INHERIT')" 0
    ck "$name: the record was not resealed by the takeover" "$(cnt "$j" 'P-BOOT-TAKEOVER term=')" 0
    ck "$name: nothing was sealed" "$(cnt "$j" 'P-BOOT-SEALED')" 0
    ck "$name: no execution lease was granted" "$(cnt "$j" 'P238-RECOV-LEASE')" 0
    ck "$name: no replay ran" "$(cnt "$j" 'P163-RECOVERY-COMPLETE')" 0
    ck "$name: zero shutdown / BUG / Oops" "$(bad_lines "$j")" 0

    # THE DURABLE RECORD DID NOT MOVE
    rec_into "$B" "$OUT/rec_${tag}_after.txt" "the record after the $name arm"
    ck "$name: the record's state is unchanged" "$(bs_field "$OUT/rec_${tag}_after.txt" state)" "$mstate"
    ck "$name: the record's term is unchanged" "$(bs_field "$OUT/rec_${tag}_after.txt" term)" "$mterm"
    ck "$name: the record's owner is unchanged" "$(bs_field "$OUT/rec_${tag}_after.txt" owner)" "$mowner"
    ck "$name: the record's owner key is unchanged" "$(bs_field "$OUT/rec_${tag}_after.txt" key)" "$mkey"
    ck "$name: no lineage entry was appended" "$(bs_field "$OUT/rec_${tag}_after.txt" lineage)" "$(bs_field "$m0" lineage)"
    ck "$name: prev_kind (the last fence kind the record carries) is unchanged" "$(bs_field "$OUT/rec_${tag}_after.txt" prev_kind)" "$(bs_field "$m0" prev_kind)"
    dump_slots=$(rsx 60 "$B" "python3 $DUMP $MXFS_DEV 2>/dev/null | grep -ac 'desc v'" | grep -aoE '^[0-9]+' | head -1)
    echo "STAGE $name arm: $dump_slots recovery descriptor(s) on the platter afterwards"
}

if [ "$ARM" = self ] || [ "$ARM" = both ]; then
    $VIRSH start "$A" > /dev/null 2>&1
    waitboot "$A"
    deploy_ko "$A" 2
    arm_run "$A" self self
fi
if [ "$ARM" = foreign ] || [ "$ARM" = both ]; then
    arm_run "$B" foreign foreign
fi

# ---- 6. PERMANENCE: the dead end is a separate record, and this is where it
#         is measured rather than asserted.  One more attempt on each node that
#         has a module loaded; the prerequisite (a retirement proof for a key
#         the target purged) cannot arrive by waiting, so the state-machine
#         argument is: the term is unchanged, nothing produces a proof, and
#         every ordinary mount returns to the same refusal.
again=0
for n in "$A" "$B"; do
    timeout 60 $SSH "$n" "lsmod | grep -q '^mxfs '" >/dev/null 2>&1 || continue
    rsx $((JOIN_BOUND + 60)) "$n" "echo $MARK-again-$n > /dev/kmsg; timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/again_${n}.txt"
    capture_require "$OUT/again_${n}.txt" '^(MOUNTED|NOT_MOUNTED)$' "the repeat mount on $n"
    measure "$n" 60 "$OUT/again_${n}_journal.txt" '^JOURNAL_END$' "the journal for the repeat mount on $n" \
        "dmesg | sed -n '/$MARK-again-$n/,\$p' | cut -c1-600; echo JOURNAL_END"
    ck "permanence: the repeat mount on $n is refused the same way" "$(cnt "$OUT/again_${n}_journal.txt" 'P-BOOT-TAKEOVER-FENCE-UNPROVEN')" 1
    ck "permanence: the repeat mount on $n did not complete" "$(grep -ac '^MOUNTED' "$OUT/again_${n}.txt")" 0
    again=$((again + 1))
done
rec_into "$B" "$OUT/rec_final.txt" "the durable record at the end"
ck "permanence: the record is STILL CLAIMED by a key that cannot come back" "$(bs_field "$OUT/rec_final.txt" state | sed 's/(.*//')" "CLAIMED"
ck "permanence: the term never moved across every attempt in this lap" "$(bs_field "$OUT/rec_final.txt" term)" "$R1_TERM"
echo "STAGE permanence: $again repeat attempt(s), record $(bs_field "$OUT/rec_final.txt" state) term=$(bs_field "$OUT/rec_final.txt" term) owner=$(bs_field "$OUT/rec_final.txt" owner)"
echo "STAGE the record is left CLAIMED on purpose — it IS the measured state; the next prep's mkfs rewrites it IDLE"

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
