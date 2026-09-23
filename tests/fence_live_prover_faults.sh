#!/bin/bash
# fence_live_prover_faults.sh — the fence matrix's LIVE-PROVER faults.
#
# The six crash cuts of tests/fence_crash_cuts.sh all DESTROY the prover.  The
# design-consult ruling banked in docs/rulings/fence-crash-matrix-cuts.md is
# explicit that this leaves a whole class untested: "MAY_HAVE_SUBMITTED needs
# live-prover faults, not only destroyed provers: a definite pre-command
# failure, an uncertain submission, a successful target action with the
# response lost, an arm CAS that fails or completes ambiguously."  A destroyed
# prover cannot produce any of them, because the thing under test is what THIS
# prover does NEXT with an answer it cannot trust — and a destroyed prover does
# nothing next.
#
# The ruling offers one way to omit these as crash laps: "the matrix may omit
# them as crash laps only once it establishes that pending I/O has drained
# before a successor acts."  That route is closed in this tree by design, and
# the module says so itself — dlm/scsipr.c, on the post-reset probe bound:
# "waiting that out here would be this barrier doing the pre-reset drain the
# design ruling rejected."  There is no drain to establish, so the faults have
# to be injected.
#
# THE INJECTOR is mxfs.pr_fence_submit_inject, read at the command-submission
# boundary inside mxfs_scsipr_fence_node().  It is one-shot and filtered by
# victim node (pr_fence_submit_inject_victim), because the ruling refuses a
# global one-shot that can catch the wrong attempt.  Nothing it does changes
# what the target is asked to do except by not asking: mode 5 issues the REAL
# PREEMPT AND ABORT and the victim key really is consumed; only the answer the
# prover is handed is replaced.
#
#   1 precommand  a DEFINITE pre-command failure: nothing armed, nothing
#                 issued, the attempt stays PRECOMMAND and is repeatable.
#   2 armfail     the arm CAS is refused: nothing durable, nothing issued.
#   3 armambig    the arm CAS LANDED and is reported as having FAILED — a
#                 durable marker names a submission the prover believes it
#                 never made.
#   4 uncertain   armed, and NO PROUT issued, but the prover is given a
#                 transport timeout: it cannot tell this from a command that
#                 reached the target.
#   5 lostresp    the PROUT IS issued, the target acts, the victim key really
#                 is consumed — and the successful response is replaced with a
#                 transport timeout while this prover stays ALIVE.
#
# WHY THE VICTIM MUST BE SILENT AND NOT DESTROYED.  Every mode sits AT or AFTER
# the command-submission boundary, and mxfs_scsipr_fence_node returns
# KEY_ABSENT_UNPROVEN well before that boundary when the victim's registration
# is already gone.  On this rig a destroyed victim loses its registration with
# its iSCSI session, so a destroyed arm would never reach the injector and
# every lap would burn its whole budget and report VACUOUS.  The silent victim
# keeps its session and its key, so the boundary is reached.  The combination
# is refused up front rather than discovered at the marker wait.
#
# WHAT EACH MODE ASSERTS is the ruling's own list: that durable arming alone
# never certifies, that a pre-command failure consumed nothing, that an
# uncertain submission is never blindly resubmitted under the SAME attempt
# (the fence term is what distinguishes "the same"), and — mode 5, the one no
# crash cut can reach — that a completed command whose response was lost is
# never relabelled as the proof it would have been.  Key absence plus a higher
# PR generation is NOT a PREEMPT AND ABORT receipt.
#
# BUDGET, derived from the stages and not chosen: boot 200 + prep 300 +
# identities/keys 90 + park-to-injection 200 (which contains the 62 s dead
# window) + captures 120 + settle 120 + restore 90 = 1120 s.  A queue entry
# for this lap carries 1150.
#
# Usage: tests/fence_live_prover_faults.sh <label> [mode]   (mode 1..5; env MODE)
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, PAUSE_MS (150000),
#        NFILES (32).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
MODE=${2:-${MODE:-}}
case ${MODE:-} in
    1) MNAME=precommand;; 2) MNAME=armfail;; 3) MNAME=armambig;;
    4) MNAME=uncertain;;  5) MNAME=lostresp;;
    *) echo "usage: $0 <label> <mode 1..5>"; exit 2;; esac
VICTIM=${VICTIM:-silent}
if [ "$VICTIM" != silent ]; then
    echo "ABORT: every mode of this lap sits at or after the command-submission boundary, and"
    echo "       a fence attempt against a victim whose registration is already gone returns"
    echo "       KEY_ABSENT_UNPROVEN long before that boundary.  On this rig a DESTROYED victim"
    echo "       loses its registration with its iSCSI session, so the injector would never be"
    echo "       reached.  Run it with the default silent victim."
    exit 2
fi
PAUSE_MS=${PAUSE_MS:-150000}
NFILES=${NFILES:-32}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; it stays ALIVE throughout
B=${MXFS_NODE_LIST##*,}          # the victim; parked, never destroyed mid-lap
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_flpf${MODE}_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FLPF-MARK-$LABEL-$MODE"
echo "=== fence_live_prover_faults mode=$MODE ($MNAME) label=$LABEL A(prover)=$A B(victim)=$B pause=${PAUSE_MS}ms $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

# EVERY EXIT DISARMS.  This lap arms a one-shot fence-submission injector on
# the prover and a one-shot heartbeat park on the victim.  An injector left
# armed across a lap boundary has already been measured pushing a following
# prep from a 45-58 s norm to 150 s, and this one would make the NEXT lap's
# first fence attempt fail for a reason that lap never armed.  Cleanup is
# idempotent, bounded, and must never change this lap's verdict, so every
# write's failure is ignored and the incoming status is passed through.
flpf_disarm() {
    local rc=$? n
    for n in "$A" "$B"; do
        rs 25 "$n" "for p in pr_fence_submit_inject pr_fence_submit_inject_victim dl_inject_hb_pause_ms; do [ -w $PARM/\$p ] && echo 0 > $PARM/\$p; done; true" >/dev/null 2>&1 || true
    done
    return $rc
}
trap flpf_disarm EXIT

field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
keys_into() {   # <node> <file> <what>
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -a 'Key=\|type:\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
pr_gen() { grep -ao 'PR generation=0x[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
normkey() { printf '0x%016x' "$(( $1 ))"; }
dump_into() {   # <node> <file> <what>
    measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"
}
desc_of()  { awk -v s="$2" '$1=="slot" && $2==s {f=1; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$1" | head -1; }
slot_of()  { grep -aE "^slot +$2 " "$1" | head -1; }
bad_lines() { echo $(( $(cnt "$1" 'hutting down filesystem') + $(cnt "$1" 'BUG:\|Oops') )); }
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        case "$st" in *"shut off"*) $VIRSH start "$n" >/dev/null 2>&1 || true ;; esac
    done
    for n in "$@"; do
        w=0
        while [ $w -lt 200 ]; do
            rs 10 "$n" 'test -f /run/systemd/system && echo up' 2>/dev/null | grep -qa up && break
            sleep 5; w=$((w+5))
        done
    done
}

# ---- 0. the fleet on the tree build, with THIS injector in it
if [ "$(strings -a mxfs.ko | grep -c 'P-PR-FENCE-INJECT')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P-PR-FENCE-INJECT injector (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# The knob must EXIST on the running module.  A tree that carries the string
# but a fleet running an older build would arm nothing and the lap would read
# "the injector never fired" as a filesystem verdict.
value_now_into hasknob "$A" 20 "$OUT/A_knob.txt" '^knob=[01]$' "the injector knob on $A" "[ -w $PARM/pr_fence_submit_inject ] && echo knob=1 || echo knob=0"
ck "the running module on $A exposes pr_fence_submit_inject" "${hasknob#knob=}" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=knob evidence=$OUT"; exit 2; }

# ---- 1. identities
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; VSLOT=\$slot_$B"
dump_into "$A" "$OUT/hb_0.txt" "the disklock table before the arm"
PNODE=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VNODE=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VEPOCH=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'epoch=[0-9]*' | cut -d= -f2)
VKEY=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
PKEY=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
if [ -z "$PNODE" ] || [ -z "$VNODE" ] || [ -z "$VKEY" ] || [ "$ASLOT" = "$VSLOT" ]; then
    echo "ABORT: the table did not yield two distinct live records for $A and $B"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2
fi
TERM0=$(desc_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'fence_term=[0-9]*' | cut -d= -f2)
echo "STAGE identities: prover A1=$PNODE slot $ASLOT key $PKEY; victim B1=$VNODE/$VEPOCH slot $VSLOT key $VKEY; fence_term before=${TERM0:-0}"
keys_into "$A" "$OUT/K0.txt" "READ KEYS before the arm"
GEN0=$(pr_gen "$OUT/K0.txt")
ck "before the arm: B1's key is registered (the boundary is reachable)" "$(key_present "$OUT/K0.txt" "$(normkey "$VKEY")")" 1
ck "before the arm: A1's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$PKEY")")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }

# ---- 2. an oracle B fsyncs and keeps, so a lap that corrupts is visible
measure "$B" 60 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/flpf_${LABEL}_$MODE; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'flpf %s mode $MODE file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"

# ---- 3. arm the injector on the PROVER, naming this victim
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED=' "arming the submission injector on $A" \
    "echo $MARK > /dev/kmsg; echo $VNODE > $PARM/pr_fence_submit_inject_victim; echo $MODE > $PARM/pr_fence_submit_inject; echo ARMED=\$(cat $PARM/pr_fence_submit_inject) victim=\$(cat $PARM/pr_fence_submit_inject_victim)"
ck "A armed mode $MODE for victim $VNODE" "$(grep -a '^ARMED=' "$OUT/A_arm.txt")" "ARMED=$MODE victim=$VNODE"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. park B's heartbeat.  B keeps its session, its registration and its
#         mount; only its beat stops, so A declares it dead and fences a victim
#         whose key is still on the target.
measure "$B" 30 "$OUT/B_park.txt" '^PAUSE_SEEN=' "parking B's heartbeat" \
    "echo $MARK > /dev/kmsg; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo PAUSE_SEEN=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing')"
ckge "B's heartbeat thread reported that it is parked" "$(field "$OUT/B_park.txt" PAUSE_SEEN)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=park evidence=$OUT"; exit 2; }
echo "STAGE B is silent at +$(el)s — waiting for A to reach the submission boundary (dead window 62 s, bound 200s)"

# ---- 5. the injection.  Either the mode's own line, or its VACUOUS decline.
wait_for_into hit "$A" 200 "$MARK" "P-PR-FENCE-INJECT"
if [ "$hit" = timeout ]; then
    echo "VACUOUS: A never reached the command-submission boundary within 200 s; its fence lines:"
    window_into "$OUT/A_nohit.txt" "$A" 40 "$MARK"
    grep -a 'P236-FENCE\|P-PR-FENCE\|P238-FENCE' "$OUT/A_nohit.txt" | sed 's/.*mxfs: /    /' | cut -c1-200 | tail -20
    echo "RESULT: VACUOUS label=$LABEL mode=$MODE evidence=$OUT"; exit 3
fi
echo "STAGE the injector fired at +$(el)s (waited ${hit}s)"

# ---- 6. captures AT the injection: A's window, the target, the platter
window_into "$OUT/A_at.txt" "$A" 60 "$MARK"
keys_into "$A" "$OUT/K1.txt" "READ KEYS after the injection"
dump_into "$A" "$OUT/hb_1.txt" "the disklock table after the injection"
GEN1=$(pr_gen "$OUT/K1.txt")
KEY1=$(key_present "$OUT/K1.txt" "$(normkey "$VKEY")")
S1=$(desc_of "$OUT/hb_1.txt" "$VSLOT")
FLAGS1=$(echo "$S1" | grep -ao 'flags=0x[0-9a-f]*' | cut -d= -f2)
STAGE1=$(echo "$S1" | grep -ao 'stage=[A-Z_]*' | cut -d= -f2)
KIND1=$(echo "$S1" | grep -ao 'fence_kind=[A-Z0-9_]*' | cut -d= -f2)
TERM1=$(echo "$S1" | grep -ao 'fence_term=[0-9]*' | cut -d= -f2)
ARMED1=$(( ${FLAGS1:-0} & 0x8 ))
echo "STAGE at the injection: stage=${STAGE1:-none} flags=${FLAGS1:-0} may_have_run=$ARMED1 kind=${KIND1:-none} fence_term=${TERM1:-0} victim_key_present=$KEY1 pr_gen ${GEN0:-?} -> ${GEN1:-?}"

# A decline is not a measurement of the mode: modes 3 and 5 depend on a real
# arm or a real command succeeding, and when one does not the injector says so
# and lets the true outcome stand.  That lap measured nothing about the fault.
count_file_into vac "$OUT/A_at.txt" 'P-PR-FENCE-INJECT-VACUOUS'
if [ "$vac" != 0 ]; then
    echo "VACUOUS: the injector declined mode $MODE because the state it substitutes into never existed:"
    grep -a 'P-PR-FENCE-INJECT-VACUOUS' "$OUT/A_at.txt" | sed 's/.*scsipr: /    /' | cut -c1-240
    echo "RESULT: VACUOUS label=$LABEL mode=$MODE evidence=$OUT"; exit 3
fi
count_file_into fired "$OUT/A_at.txt" "P-PR-FENCE-INJECT mode=$MODE $MNAME"
ck "the injection that fired is the one this lap armed (mode $MODE $MNAME)" "$fired" 1

# ---- 7. what every mode owes, whatever it substituted
count_file_into pa_done "$OUT/A_at.txt" 'P-PR-FENCE preempt-and-aborted'
# the certificate count is filtered by THIS victim: a certificate naming
# anyone else is not this attempt's and must not be read as one
count_file_into certd   "$OUT/A_at.txt" "P236-FENCE-CERTIFIED.*victim=$VNODE"
count_file_into crashes "$OUT/A_at.txt" 'BUG:\|Oops'
ck "the prover did not crash" "$crashes" 0
# WHY THIS IS /proc/mounts AND NOT `mountpoint -q`.  `mountpoint` stat()s the
# mount root, which is a PATH OPERATION, and on the two ambiguous arms a path
# operation is exactly what the design interferes with — P238-FENCE-BLOCKED-
# AMBIGUOUS says in terms that "path operations that need those grants now fail
# fast (EIO)".  So a stat answers "not a mountpoint" for a mount that is up and
# behaving correctly (mode 5 read mounted=0 and FAILed on it), or blocks when the
# grants are merely frozen rather than refused (mode 3's stat hit the bound and
# ABORTed the lap before a single assertion about the fault was reached).
# /proc/mounts is answered by the VFS without touching the filesystem.
value_now_into amnt "$A" 20 "$OUT/A_mounted.txt" '^mounted=[01]$' \
    "the prover's mount after the injection" \
    "grep -qs ' $MNT mxfs ' /proc/mounts && echo mounted=1 || echo mounted=0"
ck "the prover's mount is still present (this is a LIVE-prover fault)" "${amnt#mounted=}" 1

# USABILITY IS A SEPARATE QUESTION AND ON THESE ARMS IT IS NOT A VERDICT.
# Presence in /proc/mounts is necessary and not sufficient, so the path is
# probed too — but a refusal here is the DESIGNED containment on an ambiguous
# attempt, not a defect, so this is recorded rather than asserted.  What it
# discriminates is the three outcomes that look alike from a distance: served,
# refused fast (EIO, the design), and BLOCKED (no answer inside the bound, which
# is the one worth chasing).  The bound is what a stat on a served mount costs
# plus the ssh round trip, not a round number: a stat that has not answered in
# five seconds is not slow, it is waiting on something.
rsx 5 "$A" "stat -c ok $MNT >/dev/null 2>&1 && echo path=served || echo path=refused" \
    > "$OUT/A_path.txt" 2>&1
pathrc=$?
if [ "$pathrc" = 124 ]; then
    echo "NOTE the prover's mount is present but a stat on it did NOT answer within 5s — path operations are BLOCKED, not refused"
    echo "path=blocked" >> "$OUT/A_path.txt"
else
    echo "NOTE the prover's mount is present and a stat on it $(grep -ao 'path=[a-z]*' "$OUT/A_path.txt" | head -1 | cut -d= -f2)"
fi

# THE SUBJECT IS THE INJECTED ATTEMPT, AND A LATER CAPTURE CANNOT SEE IT.
# Modes 1-4 all leave the module saying "retry=automatic next_retry_ms=~300",
# and it means it: mode 1 re-armed 531 ms after the injection and had certified
# on a real receipt before this lap could read a single key.  Asserting "the
# victim's key is still registered" against a capture taken twenty seconds later
# therefore FAILS on correct behaviour — which is what it did, four times, on
# both mode 1 and mode 2.  The lap cannot outrun a 300 ms retry and must not try.
#
# So the questions are asked of the ORDER of the module's own lines instead,
# which is where the answer actually lives and which no delay can erase:
#   * the injected attempt must record that it consumed nothing;
#   * if the fence later completed, that completion must be a NEW submission
#     under its OWN durable boundary — a P304-FENCE-ARM logged after the
#     injection — and never a relabelling of the arm that was injected;
#   * if it did NOT complete, then the target must be untouched, which is the
#     old assertion and is still the right one for that branch.
awk '/P-PR-FENCE-INJECT mode=/{f=1; next} f' "$OUT/A_at.txt" > "$OUT/A_after.txt"
awk '/P-PR-FENCE-INJECT mode=/{exit} {print}' "$OUT/A_at.txt" > "$OUT/A_before.txt"
# A fresh arm ("P304-FENCE-ARM slot=") or the re-driven attempt meeting the
# boundary it already made ("P304-FENCE-ARM-STANDING", mode 3) both count; the
# bare prefix would also match P304-FENCE-ARM-FAIL / -LEASE-LOST, which are the
# opposite of an arm.
rearm_ln=$(grep -an 'P304-FENCE-ARM \|P304-FENCE-ARM-STANDING' "$OUT/A_after.txt" | head -1 | cut -d: -f1)
done_ln=$(grep -an 'P-PR-FENCE preempt-and-aborted' "$OUT/A_after.txt" | head -1 | cut -d: -f1)

case $MODE in
1|2|3|4)
    # Modes 1-3 fail BEFORE any command could have left this node, and the
    # module's P238-FENCE-PENDING line says exactly that.  Mode 4 is the one
    # mode whose whole point is that the prover CANNOT say it — the boundary
    # is armed and the response is a timeout — so the only honest record is
    # P238-FENCE-UNPROVEN with command_may_have_run=YES, and grading mode 4
    # against "=no" graded the inverse of the design (s138j did, and FAILed a
    # correct run on that one assertion).
    if [ "$MODE" = 4 ]; then
        ckge "the injected attempt recorded that a command MAY have run (phase MAY_HAVE_SUBMITTED)" \
             "$(cnt "$OUT/A_at.txt" 'phase=MAY_HAVE_SUBMITTED command_may_have_run=YES')" 1
        ck "the uncertain attempt was not put on the automatic retry series" \
           "$(cnt "$OUT/A_after.txt" 'P238-FENCE-PENDING')" 0
    else
        ckge "the injected attempt recorded that no command may have run" \
             "$(cnt "$OUT/A_at.txt" 'command_may_have_run=no')" 1
    fi
    if [ -n "$done_ln" ]; then
        echo "  NOTE the fence was re-driven automatically and completed after the injection — the assertions below are about HOW, not whether"
        if [ -n "$rearm_ln" ] && [ "$rearm_ln" -lt "$done_ln" ]; then
            echo "  PASS the completing command armed its own submission boundary first (P304-FENCE-ARM at +$rearm_ln, command at +$done_ln)"
        else
            echo "  FAIL a preempt-and-abort completed with no fresh P304-FENCE-ARM before it — the injected attempt's arm was reused as this command's boundary (rearm=${rearm_ln:-none} done=$done_ln)"
            fails=$((fails+1))
        fi
        ckge "the completion certified on a real receipt, not on the key's absence" \
             "$(cnt "$OUT/A_after.txt" 'PREEMPT_ABORT_PROVEN')" 1
    else
        echo "  NOTE the fence did not complete in this window — the target must therefore be untouched"
        ck "the victim's key is STILL registered (no PREEMPT AND ABORT was issued)" "$KEY1" 1
        ck "the PR generation did not move (no PERSISTENT RESERVE OUT landed)" "${GEN1:-x}" "${GEN0:-y}"
        ck "no completed preempt-and-abort is claimed in this window" "$pa_done" 0
    fi
    ;;
5)
    # The command really ran.  Both halves are asserted, because either one
    # alone would also be true of a lap where nothing happened at all.
    ck "the victim's key is GONE — the PREEMPT AND ABORT really completed at the target" "$KEY1" 0
    if [ "${GEN1:-x}" = "${GEN0:-y}" ]; then
        echo "  FAIL the PR generation did not move although the key was consumed (${GEN0:-?} -> ${GEN1:-?}); no PERSISTENT RESERVE OUT can have landed, so the key went another way and this lap did not measure a lost response"
        fails=$((fails+1))
    else
        echo "  PASS the PR generation moved across the completed command (${GEN0:-?} -> ${GEN1:-?})"
    fi
    ;;
esac

case $MODE in
1)
    # PRECOMMAND: the boundary was never crossed, so nothing durable may name
    # a submission and the attempt must stay repeatable.  Both questions are
    # asked of what the module logged BEFORE the injection — $ARMED1 is read off
    # the descriptor long after the automatic retry has armed its own boundary,
    # so it answers about the retry, not about the attempt that was injected.
    ck "the injected attempt armed no submission boundary" "$(cnt "$OUT/A_before.txt" 'P304-FENCE-ARM')" 0
    ck "the arm was never attempted, so the boundary never refused one" "$(cnt "$OUT/A_before.txt" 'P304-FENCE-NOARM')" 0
    ;;
2)
    # ARM REFUSED: the boundary refused, nothing durable, nothing issued.
    ckge "the submission boundary refused and said so" "$(cnt "$OUT/A_at.txt" 'P304-FENCE-NOARM')" 1
    ck "the injected attempt armed no submission boundary" "$(cnt "$OUT/A_before.txt" 'P304-FENCE-ARM')" 0
    ;;
3)
    # ARM LANDED, REPORTED FAILED: the marker IS durable and the prover thinks
    # it is not.  That asymmetry is the whole test — a retry must meet its own
    # standing arm and must not treat it as somebody else's.
    #
    # MEASURED s133c3 and s138m (before 0.89.63): the retry worker read the
    # durable arm, answered "ambiguous, not ours to retry", disarmed itself,
    # and nothing ever revisited the slot — the victim's grants stayed frozen,
    # a stat on the prover's own mount blocked past a 20 s bound, and the node
    # could not release the module eight minutes later.  The module now keeps,
    # per slot, whether THIS incarnation ever returned from an attempt having
    # crossed the command boundary under the standing attempt; an arm it never
    # issued under is re-driven under the boundary it already has
    # (P304-FENCE-RETRY-ARMLANDED, then P304-FENCE-ARM-STANDING at the arm
    # step) and completed by a real PREEMPT AND ABORT with a real receipt.
    # So the assertions are about that re-drive, and "the fence did not
    # complete" is the FAIL of this mode, not a branch of it.
    ckge "the submission boundary reported a refusal to the prover" "$(cnt "$OUT/A_at.txt" 'P304-FENCE-NOARM')" 1
    ckge "the arm landed BEFORE the prover was told it failed (P304-FENCE-ARM precedes the injection line)" "$(cnt "$OUT/A_before.txt" 'P304-FENCE-ARM ')" 1
    ck "nothing certified before the injection (the injected attempt itself certified nothing)" "$(cnt "$OUT/A_before.txt" "P236-FENCE-CERTIFIED.*victim=$VNODE")" 0
    ckge "the retry recognised the standing arm as its own and never issued under (P304-FENCE-RETRY-ARMLANDED)" "$(cnt "$OUT/A_after.txt" 'P304-FENCE-RETRY-ARMLANDED')" 1
    if [ -z "$done_ln" ]; then
        echo "  FAIL the fence was not re-driven to completion after the ambiguous arm — the standing arm was left as somebody else's, which is the s133c3/s138m hang"
        fails=$((fails+1))
    else
        cert_ln=$(grep -an "P236-FENCE-CERTIFIED.*victim=$VNODE" "$OUT/A_after.txt" | head -1 | cut -d: -f1)
        if [ -n "$cert_ln" ] && [ "$cert_ln" -gt "$done_ln" ]; then
            echo "  PASS the certificate follows the completing command (command at +$done_ln, certificate at +$cert_ln); durable arming alone certified nothing"
        else
            echo "  FAIL no certificate for this victim follows the completed command (cert=${cert_ln:-none} done=$done_ln)"
            fails=$((fails+1))
        fi
    fi
    ck "path operations on the prover's mount answered once the retry completed (nothing left frozen behind the arm)" "$(grep -ac 'path=blocked' "$OUT/A_path.txt")" 0
    ;;
4)
    # UNCERTAIN: armed, nothing issued, and the prover cannot tell.  It must
    # not resubmit under the SAME attempt; a new attempt needs a new term.
    ck "the submission is durably armed (may_have_run set)" "$ARMED1" 8
    ck "nothing certified on durable arming alone" "$certd" 0
    if [ "$pa_done" != 0 ] && [ "${TERM1:-0}" = "${TERM0:-0}" ]; then
        echo "  FAIL a preempt-and-abort was issued under the SAME fence term (${TERM0:-0}) after an uncertain submission — the attempt was blindly resubmitted"
        fails=$((fails+1))
    else
        echo "  PASS the uncertain submission was not resubmitted under the same attempt (pa_done=$pa_done term ${TERM0:-0} -> ${TERM1:-0})"
    fi
    ;;
5)
    # LOST RESPONSE, PROVER ALIVE.  The ruling's sharpest requirement: the
    # original certificate is lost and cannot be reconstructed from "key
    # absent".  A fresh certificate must name the mechanism actually used;
    # key absence plus a higher PR generation must never be relabelled as the
    # original PREEMPT AND ABORT success.
    ck "the submission is durably armed (may_have_run set)" "$ARMED1" 8
    ck "nothing certified on durable arming alone" "$certd" 0
    kindbad=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/A_at.txt" | grep -ac 'PREEMPT_ABORT_PROVEN')
    ck "no certificate claims PREEMPT_ABORT_PROVEN — the only completed command's response was LOST and cannot be its own receipt" "$kindbad" 0
    ck "the durable descriptor does not carry PREEMPT_ABORT_PROVEN as this attempt's kind" "$(echo "${KIND1:-none}" | grep -ac 'PREEMPT_ABORT_PROVEN')" 0
    ;;
esac

# ---- 8. settle: the cluster must still be safe a window later, and the
#         prover must not have wedged behind its own uncertain attempt.
sleep 60
window_into "$OUT/A_settle.txt" "$A" 60 "$MARK"
ck "the prover logged no shutdown or crash across the settle window" "$(bad_lines "$OUT/A_settle.txt")" 0
dump_into "$A" "$OUT/hb_2.txt" "the disklock table after the settle window"
S2=$(desc_of "$OUT/hb_2.txt" "$VSLOT")
KIND2=$(echo "$S2" | grep -ao 'fence_kind=[A-Z0-9_]*' | cut -d= -f2)
TERM2=$(echo "$S2" | grep -ao 'fence_term=[0-9]*' | cut -d= -f2)
echo "STAGE after settle: kind=${KIND2:-none} fence_term=${TERM2:-0}"
if [ "$MODE" = 5 ]; then
    ck "a settled certificate still never names PREEMPT_ABORT_PROVEN for the lost command" "$(echo "${KIND2:-none}" | grep -ac 'PREEMPT_ABORT_PROVEN')" 0
fi

# ---- 9. restore: B is parked and self-fenced; give it a clean boot so the
#         next lap does not inherit this one's state.
$VIRSH destroy "$B" >/dev/null 2>&1 || true
sleep 3
$VIRSH start "$B" >/dev/null 2>&1 || true

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL) label=$LABEL mode=$MODE ($MNAME) fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ] || exit 1
exit 0
