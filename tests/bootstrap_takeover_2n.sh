#!/bin/bash
# bootstrap_takeover_2n.sh — the whole-cluster BOOTSTRAP-OWNER TAKEOVER, on two
# nodes over CAW (see THE TRANSPORT IS CAW below), against a target that purges
# a registration with its session.
#
# WHAT IS UNDER TEST.  The first node back from a whole-cluster outage claims
# the bootstrap term and is then cut.  The target purges its registration with
# its session, so no PREEMPT AND ABORT can name it.  Until 0.90.1 the takeover
# refused that absent key and every later mount repeated the refusal: after the
# cut, no node could mount the volume again (measured on this rig).  From
# 0.90.1 the absent key is fenced by the witnessed LOGICAL UNIT RESET (proof
# kind 24, the same producer ordinary slice recovery uses on this target), and
# the takeover must complete: the term resealed as T+1, the dead slices
# recovered, the mount up, every file both nodes fsynced before the outage read
# back identical, the other node able to join, both able to leave, and the
# volume checking clean.
#
# THREE ARMS:
#   self     A CLAIMs the term, is power-cut, REBOOTS, and mounts again.  Its
#            new boot contends for its own previous boot's term (same host,
#            new boot, the old key purged with the old session).  B then joins.
#   foreign  B contends for A's term.  A then reboots and joins.  With
#            CUT=freeze A is SUSPENDED instead of destroyed, left long enough
#            (PURGE_WAIT) for the target to purge its key, and resumed after
#            B's takeover: the stalled-but-alive owner, which must find the
#            term lost and land no write.
#   stale    B contends, is elected, and is destroyed at a TEST-ONLY hold
#            (STALE_POINT 15 = elected, nothing fenced; 16 = the old owner
#            fenced, nothing resealed).  A's next boot must fence B as a stale
#            contender AND its own previous boot as the old owner.
#
# THE OBSERVER.  B stays UP and UNMOUNTED for the whole bootstrap phase, which
# is what makes the pre-cut and post-cut platter reads possible at all: once A
# is destroyed there is otherwise no node that can read the LUN.  An unmounted
# node registers no PR key and writes no heartbeat, so it does not disturb the
# whole-cluster-outage shape; its frozen slot is one of the victims either way.
# It reads the record with `chk_mxfs --bootstrap` (read-only, O_DIRECT, no
# O_EXCL) and the target's key table with `chk_mxfs --pr-keys`.
#
# the budget rule (derived): prep <= 300 (measured 45-58) + payload ~15 +
# destroy ~10 + boot both 60-150 + module copy ~30 + A's bootstrap mount to
# P-BOOT-CLAIMED (one frozen survivor scan: 62 s dead window + 2.5 s poll,
# measured 65-75) bound 200 + captures ~40 + destroy ~10 + A boot 60-150 +
# takeover mount (abandon window 6 s + LU reset + barrier + two-slice recovery)
# bound 300 + captures ~60 + the join mount bound 300 + read-back ~20 + two
# unmounts ~20 + chk_mxfs ~60.  Summed at the BOUNDS: 60 prep + 40 payload +
# 15 destroy + 150 boot + 60 module copy + 20 insmod + 200 claim + 60
# captures + 50 cut and re-read + 480 takeover arm + 390 join + 40 read-back
# + 100 unmount and check = 1665.  Caller bound 1700 s for 'self' and
# 'foreign'; 'stale' adds the held contender (bound 300) and a second reboot
# (~200), 2200 s; CUT=freeze adds PURGE_WAIT, the 30 s resume watch and a
# reboot, 2000 s.
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
# THE TARGET'S PURGE, AND WHICH FENCE ROUTE A LAP MEASURES.  The absent-key
# route exists for a target that drops a lost initiator's registration with its
# session (the retired QNAP; data/rigs.json pr_registration_on_session_loss =
# purged).  A target that keeps the registration ('persists': clyde's SCST LUN)
# never shows the takeover an absent key after a cut; there the old owner's key
# is still present and the takeover's route is the exact-key PREEMPT AND ABORT.
# PURGE selects what the lap measures:
#   target   the target itself purges (a 'purged' rig only; its default)
#   emulate  the observer removes every registration left in the table once no
#            node is mounted (after the cut; after the held contender is cut),
#            with a PREEMPT from a temporary key it then unregisters.  The table
#            the takeover reads is then the one a purging target leaves: the
#            dead keys absent, no registrant, the reservation gone with them.
#            The PR generation moves, which a target-internal purge does not do;
#            nothing in the takeover reads the generation as evidence of how a
#            key left.  The default on a 'persists' rig.
#   none     nothing removes them: the takeover must fence the present owner
#            key with a certified PREEMPT AND ABORT (a 'persists' rig only).
#
# Usage: tests/bootstrap_takeover_2n.sh <label> [self|foreign|stale]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, NFILES (32),
#        CLAIM_BOUND (200), JOIN_BOUND (300), MXFS_TRANSPORT (cawd),
#        STALE_POINT (15|16, stale arm), CUT (destroy|freeze), PURGE_WAIT (60),
#        PURGE (target|emulate|none; default from the rig's declared class)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${2:-self}
case $ARM in self|foreign|stale) ;; *) echo "arm must be self, foreign or stale"; exit 2;; esac
# the stale arm's hold point on the first contender: 15 = elected, nothing
# fenced; 16 = the old owner fenced, nothing resealed
STALE=
[ "$ARM" = stale ] && STALE=${STALE_POINT:-15}
case "$STALE" in ''|15|16) ;; *) echo "STALE_POINT must be 15 or 16"; exit 2;; esac
PURGE_WAIT=${PURGE_WAIT:-60}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the run.sh condition the prep uses: cawd (direct in-guest iSCSI) is the
# 2-node rig's CAW condition; 'caw' is the multipath map, which only a
# multipath rig presents
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-cawd}
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
# HOLD_K=1: the ESCROWED-SLOT (K) route (D-BOOTSTRAP-TAKEOVER-K-ROUTE-NEVER-DRIVEN).
# A's bootstrap mount is held (bootstrap_inject=13, TEST ONLY) right after its
# adoption of a victim slot K has durably advanced the escrow to K_CLAIMED --
# the ruling's "controlled pause immediately after that real commit"; nothing
# is fabricated -- and A is cut there, so the contenders must take the K
# branch.  What the K branch then decides, and on what proof, is the
# measurement: a refusal is graded like the slotless arms; an acceptance is
# recorded with the kind and identities it rested on and the lap exits 4
# (EVIDENCE), because whether that proof covers the owner being replaced is
# the open question, not something a harness may score.
HOLD_K=${HOLD_K:-0}
# CUT=freeze (with HOLD_K=1, foreign arm only): A is SUSPENDED at the hold
# instead of destroyed, so its iSCSI session and its PR key survive (the QNAP
# purges a frozen initiator's key only ~40 s later), and B's K-route fence can
# run a real PREEMPT AND ABORT on A's exact key -- the legally reachable case
# that produces a certificate for the owner being replaced, which is the only
# way descriptor consumption on the K route is exercised.  After the arm A is
# resumed and must find itself excluded.
CUT=${CUT:-destroy}
case "$CUT" in destroy|freeze) ;; *) echo "CUT must be destroy or freeze"; exit 2;; esac
if [ "$CUT" = freeze ] && [ "$ARM" != foreign ]; then
    echo "ABORT: CUT=freeze needs the foreign arm (the owner is frozen, not rebooted)"; exit 2
fi
if [ "$HOLD_K" = 1 ] && [ "$ARM" = stale ]; then
    echo "ABORT: the stale arm runs on the slotless route; HOLD_K=1 is a separate lap"; exit 2
fi
HOLD_BOUND=${HOLD_BOUND:-300}
KACCEPT=0
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_btk_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
PRCLASS=$(mxfs_rig_pr_class) || exit 2
case "$PRCLASS" in
    purged)   PURGE=${PURGE:-target} ;;
    persists) PURGE=${PURGE:-emulate} ;;
esac
case "$PRCLASS/$PURGE" in
    purged/target|persists/emulate|persists/none) ;;
    *) echo "ABORT: PURGE=$PURGE does not apply to a rig whose target's registrations are '$PRCLASS' on session loss"; exit 2 ;;
esac
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
echo "=== bootstrap_takeover_2n arm=$ARM label=$LABEL A(owner)=$A B(observer)=$B cut=$CUT pr_class=$PRCLASS purge=$PURGE $(date -u +%FT%TZ) ==="
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
        "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
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
# PURGE=emulate: from <node>, which is mounted nowhere, remove every
# registration in the table (only dead incarnations' keys can be there at the
# points this runs), then read the table back.  <tag> names the evidence files.
# The node registers with REGISTER AND IGNORE EXISTING KEY: after a whole-
# cluster outage its own nexus can still be registered under its previous
# incarnation's key (SCST keeps a lost session's registration, and a rebooted
# initiator comes back on the same I_T nexus), and a plain REGISTER from a
# registered nexus is a reservation conflict — measured lur_foreign_s6c:
# REGISTER_RC=24, nothing purged, the takeover took the PREEMPT route.  That
# stale key is purged with the rest, as a purging target would have done.
purge_emulate() {   # <node> <tag>
    local n=$1 tag=$2
    measure "$n" 60 "$OUT/purge_${tag}.txt" '^PURGE_END$' "the emulated purge ($tag)" \
        "T=0x4d58465055524745; ks=\$(sg_persist -n -i -k $MXFS_DEV 2>/dev/null | grep -aoE '^ +0x[0-9a-f]+' | tr -d ' ')
         echo KEYS_BEFORE \$ks
         sg_persist -n --out --register-ignore --param-sark=\$T $MXFS_DEV >/dev/null 2>&1; echo REGISTER_RC=\$?
         for k in \$ks; do sg_persist -n --out --preempt --param-rk=\$T --param-sark=\$k --prout-type=7 $MXFS_DEV >/dev/null 2>&1; echo PREEMPT \$k RC=\$?; done
         sg_persist -n --out --register --param-rk=\$T --param-sark=0 $MXFS_DEV >/dev/null 2>&1; echo UNREGISTER_RC=\$?
         echo PURGE_END"
    sed 's/^/    /' "$OUT/purge_${tag}.txt" | grep -v PURGE_END
    keys_into "$n" "$OUT/K_purged_${tag}.txt" "READ KEYS after the emulated purge ($tag)"
    ck "emulated purge ($tag): no registration is left on the target" "$(grep -acE '^  0x[0-9a-f]+' "$OUT/K_purged_${tag}.txt")" 0
}

# ---- 0. the build, and the instrument this lap grades
if [ "$(strings -a mxfs.ko | grep -c 'P-BOOT-TAKEOVER-FENCE-LURESET what=')" = 0 ]; then
    echo "ABORT: mxfs.ko has no witnessed-LU-reset route in the takeover's"
    echo "       absent-key arm (0.90.1+), so this lap would grade a build that"
    echo "       can only refuse."
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
    "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
ck "the observer $B is loaded and NOT mounted" "$(grep -ac '^NOT_MOUNTED' "$OUT/B_insmod.txt")" 1

# ---- 2. A alone claims the bootstrap term
MARK="BTK-MARK-$LABEL"
rsx 60 "$A" "echo $MARK > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; $( [ "$HOLD_K" = 1 ] && echo "echo 13 > /sys/module/mxfs/parameters/bootstrap_inject;" ) nohup timeout $([ "$HOLD_K" = 1 ] && echo $((CLAIM_BOUND + HOLD_BOUND + 600)) || echo $CLAIM_BOUND) mount -t mxfs $MXFS_DEV $MNT > /run/btk_mount.log 2>&1 & echo LAUNCHED" > "$OUT/A_mount_launch.txt"
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
    grep -a 'claimed heartbeat slot\|MXFS mount ABORTED\|recovery barrier failed\|NOT replayed\|P-TRANSPORT-MISMATCH-REFUSED\|DLM init failed' \
        "$OUT/A_window_noclaim.txt" | sed 's/.*: /    /' | cut -c1-180 | head -4
    echo "  ($(cnt "$OUT/A_window_noclaim.txt" 'NOT replayed') inline replay refusals in this window)"
    # A mount refused at DLM init never reached the bootstrap, so it measured
    # nothing about the takeover: the lap's own setup was wrong (measured
    # s6b: the module reloaded after the outage on the wrong transport).
    if grep -aq 'DLM init failed' "$OUT/A_window_noclaim.txt"; then
        echo "RESULT: ABORT label=$LABEL stage=claim-dlm-init evidence=$OUT"; exit 2
    fi
    echo "RESULT: VACUOUS label=$LABEL stage=claim evidence=$OUT"; exit 3
fi
window_into "$OUT/A_at_claim.txt" "$A" 20 "$MARK"
AKEY=$(grep -a 'P-BOOT-CLAIMED' "$OUT/A_at_claim.txt" | head -1 | grep -ao 'key=0x[0-9a-f]*' | head -1 | cut -d= -f2)
ANODE=$(grep -a 'P-BOOT-CLAIMED' "$OUT/A_at_claim.txt" | head -1 | grep -ao 'node=[0-9]*' | head -1 | cut -d= -f2)
echo "STAGE A claimed at +$(el)s: owner node=$ANODE key=$AKEY"
[ -n "$AKEY" ] || { echo "RESULT: ABORT label=$LABEL stage=claim-parse evidence=$OUT"; exit 2; }
if [ "$HOLD_K" = 1 ]; then
    wait_for_into held "$A" "$HOLD_BOUND" "$MARK" "P-BOOT-INJECT-HOLD point=13"
    if [ "$held" = timeout ]; then
        window_into "$OUT/A_window_nohold.txt" "$A" 30 "$MARK"
        grep -a 'P-BOOT' "$OUT/A_window_nohold.txt" | sed 's/.*mxfs: /    /' | cut -c1-180 | tail -8
        echo "RESULT: VACUOUS label=$LABEL stage=k-hold (A never reached K_CLAIMED; the K route cannot be driven on this schedule) evidence=$OUT"; exit 3
    fi
    window_into "$OUT/A_at_hold.txt" "$A" 20 "$MARK"
    grep -a 'P-BOOT-ADOPT\|P-BOOT-INJECT-HOLD' "$OUT/A_at_hold.txt" | sed 's/.*mxfs: /    /' | cut -c1-200 | head -3
    echo "STAGE A is held after K_CLAIMED at +$(el)s"
fi

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
# in K mode the adoption comes after the claim and the term is already
# RECOVERING when A is held: still open, short of RECOVERY_COMPLETE, which is
# the shape the K route needs
if [ "$HOLD_K" = 1 ]; then
    ck "the durable record's term is open (CLAIMED or RECOVERING)" "$(echo "${R1_STATE%%(*}" | grep -acxE 'CLAIMED|RECOVERING')" 1
else
    ck "the durable record is CLAIMED" "${R1_STATE%%(*}" "CLAIMED"
fi
ck "the durable record's crc validates" "$(bs_field "$OUT/rec_1_claimed.txt" crc)" "OK"
ck "the record names A's node as owner" "${R1_OWNER%%/*}" "$ANODE"
ck "the record names A's key as owner key" "$(normkey "$R1_KEY")" "$(normkey "$AKEY")"
ck "the owner key is REGISTERED ON THE TARGET (PR IN, not our ledger)" "$(key_present "$OUT/K1_claimed.txt" "$(normkey "$AKEY")")" 1
if [ "$HOLD_K" = 1 ]; then
    ck "the durable escrow is K_CLAIMED (2)" "$(bs_field "$OUT/rec_1_claimed.txt" escrow)" "2"
    RK=$(bs_field "$OUT/rec_1_claimed.txt" K)
    echo "STAGE escrowed slot K=$RK; its heartbeat record and recovery descriptor before the cut:"
    rsx 60 "$B" "python3 $DUMP $MXFS_DEV 2>/dev/null" > "$OUT/hb_precut.txt"
    awk -v k="$RK" '$1=="slot" && $2==k {p=1; print; next} $1=="slot" {p=0} p' "$OUT/hb_precut.txt" > "$OUT/K_slot_precut.txt"
    sed 's/^/    /' "$OUT/K_slot_precut.txt" | cut -c1-200 | head -12
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=precut evidence=$OUT"; exit 2; }

# ---- 4. the cut, and the record re-read before anything can touch it
if [ "$CUT" = freeze ]; then
    $VIRSH suspend "$A" > /dev/null 2>&1
    echo "STAGE froze $A at +$(el)s (session and key kept; the QNAP purges a frozen key ~40 s later)"
else
    $VIRSH destroy "$A" > /dev/null 2>&1
    echo "STAGE destroyed $A at +$(el)s (mid-CLAIMED)"
fi
rec_into "$B" "$OUT/rec_2_aftercut.txt" "the durable record after the cut"
if [ "$PURGE" = emulate ] && [ "$CUT" = destroy ]; then
    purge_emulate "$B" aftercut
fi
ck "after the cut the record's state is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" state)" "$R1_STATE"
ck "after the cut the term is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" term)" "$R1_TERM"
ck "after the cut the owner is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" owner)" "$R1_OWNER"
ck "after the cut the owner key is unchanged" "$(bs_field "$OUT/rec_2_aftercut.txt" key)" "$R1_KEY"

# ---- 5. the arms.  Each is: bring the contender up, let it mount, and grade
#         the refusal and what it did NOT write.
arm_run() {     # <node> <arm-name> <tag>
    # j on its own line: every word of one `local` is expanded before any of
    # them is assigned, so ${tag} beside tag=$3 read an unset variable
    local n=$1 name=$2 tag=$3 j ante
    j="$OUT/${tag}_journal.txt"
    local m0 mstate mterm mowner mkey

    m0="$OUT/rec_${tag}_before.txt"
    rec_into "$B" "$m0" "the record before the $name arm"
    mstate=$(bs_field "$m0" state); mterm=$(bs_field "$m0" term)
    mowner=$(bs_field "$m0" owner); mkey=$(bs_field "$m0" key)
    rsx $((JOIN_BOUND + 90)) "$n" "echo $MARK-$tag > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/${tag}_mount.txt"
    capture_require "$OUT/${tag}_mount.txt" '^(MOUNTED|NOT_MOUNTED)$' "the $name mount attempt"
    measure "$n" 60 "$j" '^JOURNAL_END$' "the kernel journal for the $name arm" \
        "dmesg | sed -n '/$MARK-$tag/,\$p' | cut -c1-600; echo JOURNAL_END"
    echo "STAGE $name arm: mount rc=$(field "$OUT/${tag}_mount.txt" MOUNT_RC) wall=$(field "$OUT/${tag}_mount.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/${tag}_mount.txt") at +$(el)s"
    grep -a 'P-BOOT-TAKEOVER\|P-BOOT-CONTENDER' "$j" | sed 's/.*mxfs: /    /' | cut -c1-230 | head -8

    # it reached the takeover, not some earlier door
    ck "$name: the mount saw the term and registered as a takeover contender" "$(cnt "$j" 'P-BOOT-TAKEOVER-CANDIDATE')" 1
    ckge "$name: the abandon window elapsed and it contended" "$(cnt "$j" 'P-BOOT-CONTENDER-ABANDONED')" 1
    if [ "$HOLD_K" = 1 ]; then
        local kline krc
        kline=$(grep -a 'P-BOOT-TAKEOVER-FENCE-K ' "$j" | head -1)
        ckge "$name: the takeover took the K branch (P-BOOT-TAKEOVER-FENCE-K)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-K ')" 1
        echo "STAGE $name K route: $(echo "$kline" | sed 's/.*mxfs: //' | cut -c1-230)"
        grep -a 'P-BOOT-TAKEOVER-KIND-REFUSED\|P-BOOT-TAKEOVER-MOVED\|OLD-FENCE-DONE\|P-BOOT-TAKEOVER term=\|P-BOOT-INHERIT\|P-BOOT-SEALED\|P238-RECOV-LEASE' "$j" | sed 's/.*mxfs: /    /' | cut -c1-200 | head -8
        krc=$(echo "$kline" | grep -ao ' rc=[-0-9]*' | head -1 | cut -d= -f2)
        if [ "${krc:-x}" = 0 ] && [ "$(cnt "$j" 'P-BOOT-TAKEOVER-KIND-REFUSED')" = 0 ]; then
            echo "  K ROUTE ACCEPTED the old owner as fenced from K's descriptor: which identity and"
            echo "  which operation that descriptor certifies is what must be adjudicated -- recorded,"
            echo "  not scored"
            KACCEPT=1
            rec_into "$B" "$OUT/rec_${tag}_after.txt" "the record after the $name arm"
            sed 's/^/    /' "$OUT/rec_${tag}_after.txt" | cut -c1-260 | head -2
            return
        fi
    elif [ "$PURGE" = none ]; then
    # THE OLD OWNER'S KEY IS STILL REGISTERED, AND ITS OWN PREEMPT AND ABORT FENCES IT
    ck "$name: it took the slotless branch (no per-slot K fence ran)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-K ')" 0
    ckge "$name: the old owner's present key was fenced by a certified PREEMPT AND ABORT" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-REG what=old-owner .*kind=PREEMPT_ABORT_PROVEN_V1.* rc=0')" 1
    ck "$name: no LU reset was needed" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-LURESET what=')" 0
    echo "STAGE $name arm fence: $(grep -a 'P-BOOT-TAKEOVER-FENCE-REG what=old-owner' "$j" | head -1 | sed 's/.*mxfs: //' | cut -c1-200)"
    else
    # THE OLD OWNER'S KEY IS ABSENT, AND THE WITNESSED LU RESET FENCES IT
    ck "$name: it took the slotless branch (no per-slot K fence ran)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-K ')" 0
    ck "$name: no PREEMPT AND ABORT was issued against the owner key (it was absent)" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-REG what=old-owner')" 0
    ckge "$name: the old owner was fenced by a CERTIFIED witnessed LU reset" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-LURESET what=old-owner .*certified=1 ')" 1
    if [ -n "$STALE" ]; then
        ckge "$name: the stale contender was fenced by a CERTIFIED witnessed LU reset" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-LURESET what=stale-contender .*certified=1 ')" 1
    fi
    ck "$name: no LU reset refused to certify" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-LURESET .*certified=0 ')" 0
    ck "$name: the LU-reset route was never unaskable" "$(cnt "$j" 'P-BOOT-TAKEOVER-FENCE-LURESET-UNASKED')" 0
    ckge "$name: the post-reset barrier held on the bootstrap-term arm" "$(cnt "$j" 'P307-LURESET-BARRIER .*held=1 arm=bootstrap-term')" 1
    ck "$name: the barrier never refused" "$(cnt "$j" 'P307-LURESET-BARRIER .*held=0')" 0
    ante=$(grep -a 'P-BOOT-TAKEOVER-FENCE-LURESET what=old-owner' "$j" | head -1 | grep -ao 'antecedent=[A-Z-]*' | head -1 | cut -d= -f2)
    echo "STAGE $name arm fence: $(grep -a 'P-BOOT-TAKEOVER-FENCE-LURESET what=old-owner' "$j" | head -1 | grep -ao 'certified=[01] verdict=[^ ]* issued=[01] kind=[^ ]* gen=[0-9]* krel=[^ ]* total_ms=[0-9]*' | head -1) antecedent=${ante:-?}"
    fi

    # THE TERM WAS TAKEN OVER, RECOVERED, AND THE MOUNT COMPLETED
    ckge "$name: the record was resealed by the takeover (T+1)" "$(cnt "$j" 'P-BOOT-TAKEOVER term=')" 1
    ck "$name: the takeover never saw the record move under it" "$(cnt "$j" 'P-BOOT-TAKEOVER-MOVED')" 0
    ck "$name: the mount completed" "$(grep -ac '^MOUNTED' "$OUT/${tag}_mount.txt")" 1
    ck "$name: zero shutdown / BUG / Oops" "$(bad_lines "$j")" 0
    rec_into "$B" "$OUT/rec_${tag}_after.txt" "the record after the $name arm"
    echo "STAGE $name arm record after: $(grep -a '^BOOTSTRAP' "$OUT/rec_${tag}_after.txt" | cut -c1-230)"
    ckge "$name: the term advanced past the dead owner's" "$(( $(bs_field "$OUT/rec_${tag}_after.txt" term) > R1_TERM ))" 1
    ck "$name: the record's crc validates" "$(bs_field "$OUT/rec_${tag}_after.txt" crc)" "OK"
    ckge "$name: a lineage entry was appended for the dead term" "$(( $(bs_field "$OUT/rec_${tag}_after.txt" lineage) > $(bs_field "$m0" lineage) ))" 1
    verify_data "$n" "${tag}"
}

# every file both nodes fsynced before the outage is read back, bit for bit,
# through the mount on <node>
verify_data() {     # <node> <tag>
    local n=$1 tag=$2 src
    for src in "$A" "$B"; do
        measure "$n" 60 "$OUT/${tag}_verify_${src}.txt" '^VERIFY_END$' "the $src payload read through $n" \
            "cd $MNT/btk_${LABEL}_$src && sha256sum f* | sort; echo VERIFY_END"
        grep -av '^VERIFY_END' "$OUT/${tag}_verify_${src}.txt" > "$OUT/${tag}_verify_${src}_sha.txt"
        ck "$tag: every file $src fsynced before the outage reads back identical through $n" \
            "$(cmp -s "$OUT/${tag}_verify_${src}_sha.txt" "$OUT/${src}_files_sha.txt" && echo same || echo DIFFERENT)" same
    done
}

# an ordinary mount after the takeover: the volume is not a dead end
join_run() {        # <node> <tag>
    local n=$1 tag=$2 j
    j="$OUT/${tag}_journal.txt"
    rsx $((JOIN_BOUND + 90)) "$n" "echo $MARK-$tag > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/${tag}_mount.txt"
    capture_require "$OUT/${tag}_mount.txt" '^(MOUNTED|NOT_MOUNTED)$' "the $tag mount"
    measure "$n" 60 "$j" '^JOURNAL_END$' "the kernel journal for the $tag mount" \
        "dmesg | sed -n '/$MARK-$tag/,\$p' | cut -c1-600; echo JOURNAL_END"
    echo "STAGE $tag: mount on $n rc=$(field "$OUT/${tag}_mount.txt" MOUNT_RC) wall=$(field "$OUT/${tag}_mount.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/${tag}_mount.txt") at +$(el)s"
    ck "$tag: the mount on $n completed" "$(grep -ac '^MOUNTED' "$OUT/${tag}_mount.txt")" 1
    ck "$tag: zero shutdown / BUG / Oops on $n" "$(bad_lines "$j")" 0
    verify_data "$n" "$tag"
}

umount_node() {     # <node> <tag>
    measure "$1" 90 "$OUT/${2}_umount.txt" '^UMOUNT_RC=' "the unmount on $1" \
        "timeout 60 umount $MNT; echo UMOUNT_RC=\$?"
    ck "$2: $1 unmounted cleanly" "$(field "$OUT/${2}_umount.txt" UMOUNT_RC)" 0
}

case "$ARM" in
self)
    $VIRSH start "$A" > /dev/null 2>&1
    waitboot "$A"
    deploy_ko "$A" 2
    arm_run "$A" self self
    [ "$HOLD_K" = 1 ] || join_run "$B" join
    ;;
foreign)
    if [ "$CUT" = freeze ] && [ "$HOLD_K" != 1 ]; then
        # the owner is alive but stalled: its session is gone only once the
        # target has purged its key, which is the case the LU reset exists for
        if [ "$PURGE" = target ]; then
            echo "STAGE waiting ${PURGE_WAIT}s for the target to purge the frozen owner's key"
            sleep "$PURGE_WAIT"
        elif [ "$PURGE" = emulate ]; then
            purge_emulate "$B" frozen
        fi
        keys_into "$B" "$OUT/K_before_foreign.txt" "READ KEYS before the foreign arm"
        if [ "$PURGE" = none ]; then
            ck "the frozen owner's key is still registered (this target keeps it)" "$(key_present "$OUT/K_before_foreign.txt" "$(normkey "$AKEY")")" 1
        else
            ck "the frozen owner's key has been purged" "$(key_present "$OUT/K_before_foreign.txt" "$(normkey "$AKEY")")" 0
        fi
    fi
    arm_run "$B" foreign foreign
    ;;
stale)
    # B contends, is elected, and dies at the chosen point; A's next boot must
    # fence B as a stale contender AND its own previous boot as the old owner
    rsx 60 "$B" "echo $MARK-stalehold > /dev/kmsg; echo $STALE > /sys/module/mxfs/parameters/bootstrap_inject; nohup timeout $((JOIN_BOUND + HOLD_BOUND)) mount -t mxfs $MXFS_DEV $MNT > /run/btk_stale.log 2>&1 & echo LAUNCHED" > "$OUT/B_stale_launch.txt"
    capture_require "$OUT/B_stale_launch.txt" '^LAUNCHED$' "the contender's held mount launch"
    wait_for_into held "$B" "$HOLD_BOUND" "$MARK-stalehold" "P-BOOT-INJECT-HOLD point=$STALE"
    if [ "$held" = timeout ]; then
        window_into "$OUT/B_window_nohold.txt" "$B" 30 "$MARK-stalehold"
        grep -a 'P-BOOT' "$OUT/B_window_nohold.txt" | sed 's/.*mxfs: /    /' | cut -c1-180 | tail -8
        echo "RESULT: VACUOUS label=$LABEL stage=stale-hold (the contender never reached hold $STALE) evidence=$OUT"; exit 3
    fi
    window_into "$OUT/B_at_stalehold.txt" "$B" 20 "$MARK-stalehold"
    grep -a 'P-BOOT-CONTENDER-ELECTED\|P-BOOT-TAKEOVER-FENCE\|P-BOOT-INJECT-HOLD' "$OUT/B_at_stalehold.txt" | sed 's/.*mxfs: /    /' | cut -c1-200 | head -4
    $VIRSH destroy "$B" > /dev/null 2>&1
    echo "STAGE destroyed the held contender $B at hold $STALE at +$(el)s"
    $VIRSH start "$A" > /dev/null 2>&1
    $VIRSH start "$B" > /dev/null 2>&1
    waitboot "$A" "$B"
    deploy_ko "$A" 2
    deploy_ko "$B" 2
    measure "$B" 60 "$OUT/B_insmod2.txt" '^INSMOD_RC=' "the observer's module load after its cut" \
        "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?"
    [ "$PURGE" = emulate ] && purge_emulate "$B" stalecut
    arm_run "$A" stale stale
    join_run "$B" join
    ;;
esac

if [ "$CUT" = freeze ] && [ "$HOLD_K" != 1 ]; then
    # the stalled owner resumes into a term another node took over.  It must
    # write nothing that lands: not the record (its compare-and-write finds it
    # resealed), and not the volume (it is unregistered under the new owner's
    # exclusive reservation).  Then the data is re-read through B.
    $VIRSH resume "$A" > /dev/null 2>&1
    echo "STAGE resumed $A at +$(el)s; it must find the term lost and write nothing"
    sleep 30
    measure "$A" 60 "$OUT/A_after_resume.txt" '^JOURNAL_END$' "A's journal after the resume" \
        "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P131-SELF-FENCE\|P-WITHDRAW\|RESERVATION\|hutting down\|P-BOOT\|BUG:\|Oops' | tail -30 | cut -c1-300; echo JOURNAL_END"
    sed 's/^/    /' "$OUT/A_after_resume.txt" | cut -c1-200 | tail -12
    ck "zero BUG / Oops on the resumed owner" "$(cnt "$OUT/A_after_resume.txt" 'BUG:\|Oops')" 0
    keys_into "$B" "$OUT/K_after_resume.txt" "READ KEYS after A resumed"
    ck "the resumed owner's key is NOT on the target" "$(key_present "$OUT/K_after_resume.txt" "$(normkey "$AKEY")")" 0
    rec_into "$B" "$OUT/rec_after_resume.txt" "the record after A resumed"
    ck "the resumed owner did not take the record back" "$(bs_field "$OUT/rec_after_resume.txt" term)" "$(bs_field "$OUT/rec_foreign_after.txt" term)"
    verify_data "$B" after_resume
    # the stalled owner's own mount is dead; a reboot is its way back in
    $VIRSH destroy "$A" > /dev/null 2>&1
    $VIRSH start "$A" > /dev/null 2>&1
    waitboot "$A"
    deploy_ko "$A" 3
    join_run "$A" join
elif [ "$ARM" = foreign ] && [ "$HOLD_K" != 1 ]; then
    $VIRSH start "$A" > /dev/null 2>&1
    waitboot "$A"
    deploy_ko "$A" 2
    join_run "$A" join
fi

# ---- 6. BOTH NODES LEAVE CLEANLY, AND THE VOLUME CHECKS CLEAN
if [ "$HOLD_K" != 1 ]; then
    umount_node "$A" final
    umount_node "$B" final
    rec_into "$B" "$OUT/rec_final.txt" "the durable record at the end"
    echo "STAGE final record: $(grep -a '^BOOTSTRAP' "$OUT/rec_final.txt" | cut -c1-230)"
    mxfs_chk_on_node "$B" "$OUT/chk_final.txt" "chk_mxfs on the unmounted volume"
    ck "chk_mxfs finds the volume clean after the takeover" "$(mxfs_chk_rc "$OUT/chk_final.txt")" 0
fi

if [ "$KACCEPT" = 1 ] && [ $fails = 0 ]; then
    echo "RESULT: EVIDENCE label=$LABEL arm=$ARM (the K route accepted; adjudicate the proof it used) fails=0 wall=$(el)s evidence=$OUT"
    exit 4
fi
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
