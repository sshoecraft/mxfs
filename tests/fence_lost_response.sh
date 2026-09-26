#!/bin/bash
# tests/fence_lost_response.sh — a real PREEMPT AND ABORT acts on the victim,
# its successful response is LOST on the way back to the fencing code, and the
# prover KEEPS RUNNING (ledger D-FENCE-CRASH-MATRIX-UNTESTED; the design-consult
# ruling that fixed this entry's shape, assertions and non-vacuity gate is
# banked in docs/rulings/fence-lost-response-live-prover.md).
#
# WHY THIS IS NOT ANOTHER CRASH CUT.  tests/fence_crash_cuts.sh cut 4 parks the
# prover after the P&A proved exclusion and destroys it there: the proof is lost
# WITH the prover, and a successor recovers across a boot boundary.  That is
# banked (12/12 on both victim arms).  It says nothing about a prover that is
# still alive and still deciding.  Here the target really performs the P&A — the
# victim's registration is removed and its task set aborted — and only the
# RESULT is withheld, at the fencing consumer boundary, from a node that carries
# on.  The durable state at that moment is:
#
#     stage FENCING, this node the prover, current term
#     MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN (0x8) durable      <- the arm
#     the target has ALREADY acted
#     the fencing state machine has NO proving response
#     neither endpoint has a new incarnation that could supply succession
#
# That is an ordinary transport ambiguity, and the defect it hunts is the
# shortcut out of it: turning the victim key's now-absence into evidence that
# the unanswered command succeeded, or into BOOT_SUCCESSION_ABSENT without any
# boot-succession evidence.  Either would certify exclusion this node cannot
# prove and authorise foreign-slice replay from it.
#
# THE INJECTION (pal/linux/kern.c, dbg_prout_lose_key, one-shot).  Armed with
# the victim's 64-bit PR key on the prover only.  It sits AFTER the real
# completion of the real PROUT and BEFORE that function's own classification and
# reporting: the command runs, its success is printed as a witness FOR THIS TEST
# ONLY, and -ETIMEDOUT is substituted in its place, so the substituted result
# travels the same path an unanswered command travels — P302-PROUT-ABORT-FAIL
# included.  That value is not invented for a convenient branch
# — it is what this stack's own unanswered command yields, and it reaches the
# fencing code as kind ERROR at phase MAY_HAVE_SUBMITTED, exactly as a genuinely
# lost response does.  A completion that is NOT the qualifying success disarms
# the gate and passes through unchanged (P305-PROUT-LOSS-NOTQUALIFIED), and this
# harness then ABORTs rather than grading a lap that never reached the state.
#
# THE LATCH.  After the loss the prover re-drives the attempt.  It will not
# issue a second P&A — the key is gone, so the re-drive classifies
# KEY_ABSENT_UNPROVEN before the submission boundary — so the two mechanisms
# that could resolve the ambiguity are the sole-survivor exclusive-write gate
# and boot succession.  Both already have refusal knobs
# (fence_gate_inject_refuse, fence_bootsucc_inject_refuse); they are held during
# the observation and then RELEASED, which is the recovery stimulus of phase B.
# Neither knob sleeps, so the prover's heartbeat keeps running: a prover that
# went stale because the harness held its heartbeat is not this lap.
#
# THE VERDICT IS IN THREE PARTS ("success or a named block" is too permissive,
# because an implementation that always blocks would pass; and "a certificate
# within the bound" was too permissive the other way, because it accepted a
# mechanism that proves only half of what a certificate needs):
#   A  ambiguity safety — with the alternatives refused, NOTHING may be
#      certified, sealed, claimed, replayed, purged or zeroed from this
#      transaction, the durable arm must survive, and the error path must be
#      shown to have actually run.
#   B  nothing certified while the victim still lives — with the refusals
#      released and B1 alive in its original incarnation, NO certificate may
#      appear, whichever mechanism it would name.  A certificate rests on
#      admission AND retirement, and while the victim's nexus is up no
#      retirement proof exists; the sole-survivor gate's sark=0 PREEMPT AND
#      ABORT retires nothing belonging to a registration already removed, so it
#      is admission only.  Blocking here is CORRECT (session-75 ruling,
#      docs/rulings/fence-ambiguous-drain-and-proof-resume.md).
#   C  progress once the boot boundary exists — B1's host is power-cut and
#      returns under a new boot, which supplies admission and retirement from
#      one event.  The prover must then certify by boot succession and complete
#      the recovery, bounded; blocking past THAT point is the liveness failure.
#      The retirement half is a target property, read from the rig's
#      declaration (data/rigs.json task_retirement_on_nexus_loss, measured by
#      tests/pr_retirement_probe.sh), never assumed.
#
# Budget (derived, not chosen): prep <=300 (measured 45-60) + identities, keys
# and the victim's files ~30 + arm and park ~10 + the 62 s dead window and the
# fence to the P&A ~10 + the non-vacuity and ambiguity captures ~60 + the
# latched observation OBSERVE_S (75, one 60 s re-drive sweep inside the 120 s
# fence_blocked_after_ms transition) + the three bounded fail-fast probes (45
# worst case, one acquire round trip each) + the released path to a certificate
# and P163-RECOVERY-COMPLETE ~240 + B's destroy, boot and mount ~280 + final
# captures ~40 ~= 925 s.  Caller bound 1000 s.
#
# Usage: tests/fence_lost_response.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2), MXFS_DEV, NFILES (64),
#        PAUSE_MS (480000), OBSERVE_S (75), PROGRESS_BOUND (240),
#        JOIN_BOUND (300)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; stays ALIVE throughout
B=${MXFS_NODE_LIST##*,}          # the victim; alive-but-silent, then fenced
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
NFILES=${NFILES:-64}
# the park must outlast the dead window, the captures, the latched observation
# and the released recovery, or B rejoins mid-lap and confounds phase B
PAUSE_MS=${PAUSE_MS:-480000}
OBSERVE_S=${OBSERVE_S:-75}
PROGRESS_BOUND=${PROGRESS_BOUND:-240}
JOIN_BOUND=${JOIN_BOUND:-300}
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_flr_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FLR-MARK-$LABEL"
# The victim's heartbeat park has to outlast the whole lap, so a lap that exits
# EARLY leaves a thread asleep for the rest of PAUSE_MS.  An unmount waits for
# that thread, so the next lap's prep stalls behind it — measured s74d->s74e.
# The victim is destroyed in the tail anyway, so destroy it on any exit taken
# after the park was armed.  The trap is disarmed once the tail has done it.
PARKED=0
FF_UNREACHED=0                   # the fail-fast probe never reached a frozen grant
flr_cleanup() { [ "$PARKED" = 1 ] && { echo "CLEANUP: destroying $B to clear its parked heartbeat (a lap that exits early would otherwise stall the next prep)"; $VIRSH destroy "$B" > /dev/null 2>&1; $VIRSH start "$B" > /dev/null 2>&1; }; return 0; }
trap flr_cleanup EXIT
MAY_HAVE_RUN=8                   # MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN
echo "=== fence_lost_response label=$LABEL A(prover,alive)=$A B(victim,silent)=$B nfiles=$NFILES observe=${OBSERVE_S}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# A PR key is a full unsigned 64-bit value: bash arithmetic is SIGNED, so
# $(( 0xf5413d536ca66aed )) yields a negative number, which a ullong module
# param rejects and which printf '%x' cannot render.  Normalize through python3.
normkey() { python3 -c "import sys; print('0x%016x' % (int(sys.argv[1], 16) & 0xFFFFFFFFFFFFFFFF))" "$1"; }
keydec()  { python3 -c "import sys; print(int(sys.argv[1], 16) & 0xFFFFFFFFFFFFFFFF)" "$1"; }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
keys_into() {   # <node> <file> <what>
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -a 'Key=\|type:\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
pr_gen() { grep -ao 'PR generation=0x[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
resv_of() {
    local t k
    grep -aiq 'RESV.*no reservation' "$1" && { echo none; return; }
    t=$(grep -a 'RESV.*scope:.*type:' "$1" | head -1 | sed 's/.*type: *//')
    k=$(grep -ao 'RESV.*Key=0x[0-9a-f]*' "$1" | head -1 | grep -ao '0x[0-9a-f]*')
    case "$t" in
        "Write Exclusive, all registrants"*) echo WEAR ;;
        "Write Exclusive"*) echo "WE1:$(normkey "${k:-0}")" ;;
        '') echo none ;;
        *) echo "other:$t" ;;
    esac
}
dump_into() {   # <node> <file> <what>
    measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"
}
slot_of()  { grep -aE "^slot +$2 " "$1" | head -1; }
desc_of()  { awk -v s="$2" '$1=="slot" && $2==s {f=1; print; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$1" | grep -a '^    desc' | head -1; }
desc_field() { printf '%s\n' "$1" | sed -n "s/.*[ ]$2=\([^ ]*\).*/\1/p"; }
slot_field() { printf '%s\n' "$1" | sed -n "s/.*[ ]$2=\([^ ]*\).*/\1/p"; }
bad_lines() { echo $(( $(cnt "$1" 'hutting down filesystem') + $(cnt "$1" 'BUG:\|Oops') )); }
# bootid_into <var> <node> <file> <what> — argument order follows
# value_now_into (var first, then host); reversing them sends ssh to a host
# named after the variable
bootid_into() { value_now_into "$1" "$2" 20 "$3" '^[0-9a-f-]{36}$' "$4" "cat /proc/sys/kernel/random/boot_id"; }

# ---- 0. the fleet on the tree build, with THIS injector in it
if [ "$(strings -a mxfs.ko | grep -c 'P305-PROUT-RESPONSE-LOST')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P305-PROUT-RESPONSE-LOST injector (build the tree first)"
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

# ---- 1. identities.  The injection is keyed on the VICTIM KEY, which names the
# victim node and its incarnation, so it is read from the platter, never guessed.
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; VSLOT=\$slot_$B"
dump_into "$A" "$OUT/hb_0.txt" "the disklock table before the arm"
PNODE=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$ASLOT")" node)
VNODE=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$VSLOT")" node)
VEPOCH=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$VSLOT")" epoch)
VKEY=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$VSLOT")" pr_key)
PKEY=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$ASLOT")" pr_key)
ATS0=$(slot_field "$(slot_of "$OUT/hb_0.txt" "$ASLOT")" ts_ms)
if [ -z "$PNODE" ] || [ -z "$VNODE" ] || [ -z "$VKEY" ] || [ -z "$PKEY" ] || [ "$ASLOT" = "$VSLOT" ]; then
    echo "ABORT: the table did not yield two distinct live records for $A and $B"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2
fi
bootid_into abid "$A" "$OUT/A_boot0.txt" "A's boot id before the arm"; ABOOT0=$abid
bootid_into bbid "$B" "$OUT/B_boot0.txt" "B's boot id before the arm"; BBOOT0=$bbid
echo "STAGE identities: prover A1=$PNODE slot $ASLOT key $PKEY; victim B1=$VNODE/$VEPOCH slot $VSLOT key $VKEY; target class: registration $(mxfs_rig_pr_class) on session loss"
keys_into "$A" "$OUT/K0.txt" "READ KEYS before the arm"
GEN0=$(pr_gen "$OUT/K0.txt")
ck "before the arm: B1's key is registered on the LUN" "$(key_present "$OUT/K0.txt" "$(normkey "$VKEY")")" 1
ck "before the arm: A1's key is registered on the LUN" "$(key_present "$OUT/K0.txt" "$(normkey "$PKEY")")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }

# ---- 2. the dirty-death oracle: B fsyncs NFILES files before it is fenced
measure "$B" 60 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/flr_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'flr %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before it was fenced" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"

# ---- 3. arm the prover: lose the response of the P&A that names B1's key, and
# hold the two mechanisms that could otherwise resolve the ambiguity.
# the knob is a ullong and reads back in decimal; compare decimals, never a
# bash-rendered hex of a value that overflows a signed 64-bit integer
VKEY_DEC=$(keydec "$VKEY")
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED=[0-9]+ gate=[01] bootsucc=[01]$' "the arm on $A" \
    "echo $MARK > /dev/kmsg; echo $VKEY_DEC > $PARM/dbg_prout_lose_key; echo 1 > $PARM/fence_gate_inject_refuse; echo 1 > $PARM/fence_bootsucc_inject_refuse; echo ARMED=\$(cat $PARM/dbg_prout_lose_key) gate=\$(cat $PARM/fence_gate_inject_refuse) bootsucc=\$(cat $PARM/fence_bootsucc_inject_refuse)"
ck "A armed the response-loss gate for B1's key with both alternatives refused" \
   "$(grep -a '^ARMED=' "$OUT/A_arm.txt")" "ARMED=$VKEY_DEC gate=1 bootsucc=1"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. B goes silent with its session, registration and writer ALIVE.  The
# writer's per-attempt rc is the containment oracle: after the P&A consumes B1's
# registration every write from the fenced incarnation must fail.
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, time
d, log = sys.argv[1], sys.argv[2]
for i in range(1200):
    t = time.time_ns()
    try:
        fd = os.open(d + "/w", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.write(fd, (str(t) + "\n").encode()); os.fsync(fd); os.close(fd); rc = 0
    except Exception:
        rc = 1
    with open(log, "a") as f:
        f.write("%d rc=%d\n" % (t, rc))
    time.sleep(0.5)
PY
)
measure "$B" 30 "$OUT/B_silence.txt" '^PAUSE_SEEN=[0-9]+$' "the writer and the heartbeat park on $B" \
    "d=$MNT/flr_$LABEL; echo $WRITER_B64 | base64 -d > /run/flr_writer.py; nohup python3 /run/flr_writer.py \$d /src/mxfs/$OUT/B_writer.txt > /dev/null 2>&1 & sleep 2; echo $MARK > /dev/kmsg; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo PAUSE_SEEN=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing')"
PARKED=1
ck "B's heartbeat parked with its session, registration and writer alive" "$(field "$OUT/B_silence.txt" PAUSE_SEEN)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=silence evidence=$OUT"; exit 2; }
T0=$(date +%s)
echo "STAGE $B silent (heartbeat parked ${PAUSE_MS} ms, writer running) at +$(el)s — waiting for A's P&A and the lost response (dead window 62 s)"

# ---- 5. the witness: the P&A really ran and its success was withheld
wait_for_into lost "$A" 110 "$MARK" "P305-PROUT-RESPONSE-LOST\|P305-PROUT-LOSS-NOTQUALIFIED"
T_LOSS=$(date +%s)
window_into "$OUT/A_at_loss.txt" "$A" 40 "$MARK"
if [ "$lost" = timeout ]; then
    echo "  FAIL <the prover never reached the PREEMPT AND ABORT: no P305 line within the bound>"
    echo "RESULT: VACUOUS label=$LABEL stage=noloss wall=$(el)s evidence=$OUT"; exit 3
fi
if [ "$(cnt "$OUT/A_at_loss.txt" 'P305-PROUT-LOSS-NOTQUALIFIED')" != 0 ]; then
    grep -a 'P305-PROUT-LOSS-NOTQUALIFIED' "$OUT/A_at_loss.txt" | sed 's/.*mxfs: /    /' | cut -c1-200 | head -1
    echo "ABORT: the armed PREEMPT AND ABORT did not produce the successful completion this entry withholds — the lost-response state was NOT reached, so there is nothing to grade"
    echo "RESULT: ABORT label=$LABEL stage=notqualified wall=$(el)s evidence=$OUT"; exit 2
fi
wit=$(grep -a 'P305-PROUT-RESPONSE-LOST' "$OUT/A_at_loss.txt" | head -1 | sed 's/.*mxfs: //')
echo "--- the witness (test-only; no MXFS path reads it): $(printf '%s' "$wit" | cut -c1-180)"
# the kernel prints these with %llx (unpadded); normkey both sides or a key
# whose top nibble is zero compares unequal to itself
ck "the witness names B1's key as the victim" "$(normkey "$(desc_field "$wit" victim_key)")" "$(normkey "$VKEY")"
ck "the witness names A1 as the issuing prover" "$(normkey "$(desc_field "$wit" my_key)")" "$(normkey "$PKEY")"
ck "the withheld result was the qualifying SUCCESS (real_rc=0)" "$(desc_field "$wit" real_rc)" "0"
echo "STAGE the P&A ran and its response was lost at +$(el)s ($(( T_LOSS - T0 ))s after B went silent)"

# ---- 6. NON-VACUITY, target-backed.  READ KEYS alone does not prove a P&A
# happened — a registration goes away for other reasons — so the witness above
# is correlated with the registration transition AND with the victim's session
# and incarnation being unchanged, which is the competing explanation.
keys_into "$A" "$OUT/K1.txt" "READ KEYS after the lost response"
GEN1=$(pr_gen "$OUT/K1.txt")
ck "B1's registration is GONE after the P&A" "$(key_present "$OUT/K1.txt" "$(normkey "$VKEY")")" 0
ck "A1's registration survives (we did not fence ourselves)" "$(key_present "$OUT/K1.txt" "$(normkey "$PKEY")")" 1
if [ -n "$GEN0" ] && [ -n "$GEN1" ] && [ "$GEN0" != "$GEN1" ]; then
    echo "  PASS the PR generation moved across the command ($GEN0 -> $GEN1): a PROUT landed"
else
    echo "  FAIL the PR generation did not move across the command got=${GEN0:-none}->${GEN1:-none}"; fails=$((fails+1))
fi
bootid_into bbid1 "$B" "$OUT/B_boot1.txt" "B's boot id after the P&A"
ck "B did not reboot (the registration went away by the P&A, not a session teardown)" "$bbid1" "$BBOOT0"
bootid_into abid1 "$A" "$OUT/A_boot1.txt" "A's boot id after the P&A"
ck "the prover is ALIVE and did not reboot — this is the live-prover entry" "$abid1" "$ABOOT0"
dump_into "$A" "$OUT/hb_1.txt" "the disklock table at the ambiguity"
VEPOCH1=$(slot_field "$(slot_of "$OUT/hb_1.txt" "$VSLOT")" epoch)
ck "B1's incarnation is unchanged (same victim, not a successor)" "$VEPOCH1" "$VEPOCH"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=vacuity wall=$(el)s evidence=$OUT"; exit 2; }

# ---- 7. PHASE A: ambiguity safety, read from the platter while the two
# alternative proofs are refused.  The arm is durable and must stay durable; an
# ambiguous result cannot undo "MAY HAVE RUN".
echo "STAGE observing the ambiguity for ${OBSERVE_S}s (both alternatives refused) at +$(el)s"
sleep "$OBSERVE_S"
dump_into "$A" "$OUT/hb_2.txt" "the disklock table after the observation"
window_into "$OUT/A_observed.txt" "$A" 60 "$MARK"
D2=$(desc_of "$OUT/hb_2.txt" "$VSLOT")
echo "--- the victim slot's durable descriptor: $(printf '%s' "$D2" | cut -c1-220)"
STAGE2=$(desc_field "$D2" stage)
DFLAGS2=$(desc_field "$D2" flags)
KIND2=$(desc_field "$D2" fence_kind)
ck "the attempt is still at stage FENCING — nothing was certified, sealed or claimed from it" "$STAGE2" "FENCING(1)"
if [ -n "$DFLAGS2" ] && [ $(( DFLAGS2 & MAY_HAVE_RUN )) -eq $MAY_HAVE_RUN ]; then
    echo "  PASS the durable arm survives the ambiguous result (flags=$DFLAGS2 carries MAY_HAVE_RUN)"
else
    echo "  FAIL the durable arm did not survive the ambiguous result got=flags=${DFLAGS2:-none} want bit 0x8"; fails=$((fails+1))
fi
# THE FORBIDDEN RELABELLINGS, read from the durable record and from the log.
case "$KIND2" in
    PREEMPT_ABORT_DONE*) echo "  FAIL the unanswered P&A was certified as PREEMPT_ABORT_DONE — key absence was relabelled as the original command's success"; fails=$((fails+1)) ;;
    BOOT_SUCCESSION_ABSENT*) echo "  FAIL key absence was relabelled as BOOT_SUCCESSION_ABSENT with no boot boundary — the victim never rebooted"; fails=$((fails+1)) ;;
    *) echo "  PASS no proving kind is on the platter for this attempt (fence_kind=${KIND2:-none})" ;;
esac
ck "no certificate was published for B1 while the proof was missing" \
   "$(grep -ac "P236-FENCE-CERTIFIED.*node=$VNODE\|P236-FENCE-CERTIFIED.*victim=$VNODE" "$OUT/A_observed.txt")" 0
ck "no recovery completed for B1's slice while the proof was missing" \
   "$(grep -ac "P163-RECOVERY-COMPLETE.*slot=$VSLOT" "$OUT/A_observed.txt")" 0
ck "B1's heartbeat record was not zeroed from this transaction" \
   "$(grep -acE "^slot +$VSLOT magic=MXLK" "$OUT/hb_2.txt")" 1
# a GENUINE second look at the target: the victim must not have re-registered
# during the observation, or its absence has a second explanation
keys_into "$A" "$OUT/K2.txt" "READ KEYS after the observation"
ck "the victim did not re-register during the observation" "$(key_present "$OUT/K2.txt" "$(normkey "$VKEY")")" 0
echo "--- the reservation through the ambiguity: $(resv_of "$OUT/K1.txt") -> $(resv_of "$OUT/K2.txt")"
# The error path must be shown to have RUN — holding at the gate is not evidence.
ck "the lost response reached the caller as this stack's unanswered-command result" \
   "$(grep -ac 'P302-PROUT-ABORT-FAIL.*rc=-110' "$OUT/A_observed.txt")" 1
# The error path's OWN output is the evidence that it ran: the fencing code
# classified the ambiguous result (P236-FENCEKIND kind=ERROR) and published its
# verdict (P238-FENCE-UNPROVEN).  Those are the module's decision, not the
# injection's line.  A RE-DRIVE is a different thing and is reported, not
# required: whether one fires inside the observation window is a property of
# the sweep period, and its absence is part of what this entry measures.
errpath=$(grep -ac 'P238-FENCE-UNPROVEN\|P236-FENCEKIND.*ERROR' "$OUT/A_observed.txt")
ckge "the prover's own error path ran and classified the ambiguous result" "$errpath" 1
redrive=$(grep -ac 'P238-FENCE-GATE-INJECT-REFUSED\|P238-FENCE-GATE-TRY\|P238-FENCE-GATE-NOTSOLE\|P-PR-FENCE-ABSENT\|P238-FENCE-BLOCKED\|P238-FENCE-UNRECORDED' "$OUT/A_observed.txt")
declined=$(grep -ac "P238-FENCE-HOLDER-STATE.*why='our current incarnation'" "$OUT/A_observed.txt")
echo "--- after the loss: re-drive attempts=$redrive; sweep passes that declined the attempt because its holder is this live prover=$declined"
grep -a 'P238-FENCE-\|P-PR-FENCE-ABSENT\|P305-PROUT' "$OUT/A_observed.txt" | sed 's/.*mxfs: /    /' | cut -c1-165 | head -6
# the prover must still be alive and heartbeating: a stale prover is a different
# lap, and would mean the harness caused what it measured
ATS2=$(slot_field "$(slot_of "$OUT/hb_2.txt" "$ASLOT")" ts_ms)
if [ -n "$ATS0" ] && [ -n "$ATS2" ] && [ "$ATS2" -gt "$ATS0" ]; then
    echo "  PASS the prover's heartbeat kept running through the ambiguity (ts_ms $ATS0 -> $ATS2)"
else
    echo "  FAIL the prover's heartbeat did not advance got=${ATS0:-none}->${ATS2:-none} — a stale prover is not this lap"; fails=$((fails+1))
fi
ck "A: zero shutdown / BUG / Oops through the ambiguity" "$(bad_lines "$OUT/A_observed.txt")" 0
# containment: the fenced incarnation's writes must not land
wfail=$(grep -ac 'rc=1' "$OUT/B_writer.txt" 2>/dev/null || echo 0)
wok=$(grep -ac 'rc=0' "$OUT/B_writer.txt" 2>/dev/null || echo 0)
echo "--- the fenced victim's writer: rc=0 $wok, rc=1 $wfail (its registration was consumed by the P&A)"
ckge "the fenced incarnation's writes stopped succeeding" "$wfail" 1
# ---- 7b. THE SLICE IS REFUSED, BUT THE NODE IS NOT HUNG.  Refusing to recover
# a slice without proof of exclusion is the invariant; making every waiter block
# forever on that refusal is not part of it.  Before 0.89.11 the acquire-path
# fail-fast was reachable only from the pre-command leg, so an operation needing
# one of the victim's frozen grants waited out an acquire budget that, for the
# root inode, never expires — measured 764 s and still climbing, with umount and
# the module unreleasable and only a power cycle clearing the node.
# Budget: a fail-fast returns within one acquire round trip, so 30 s is already
# generous, and the whole check is bounded so it cannot become the thing that
# hangs the lap.
ck "the ambiguous slice is marked RECOVERY_BLOCKED for the acquire path" \
   "$(cnt "$OUT/A_observed.txt" 'P238-FENCE-BLOCKED-AMBIGUOUS')" 1
# The probe must keep its own discriminator.  "rc != 0, quickly" is not a
# fail-fast: ENOENT is also rc=1 and also instant, and it means the operation
# never needed one of the frozen grants at all — the opposite of what this
# check claims (measured s74j: rc=1 in 0 s with ZERO acquire-path aborts, an
# indistinguishable vacuous pass).  So each probe keeps its errno CLASS and its
# verbatim stderr, and only EIO — with the acquire path's own abort line to
# corroborate it — counts as the fail-fast.
# Three targets, weakest first: the mount root, the directory B created, and
# the file B's writer is appending to and fsyncing at the moment it is fenced
# (that last one is held EX by the victim, so it is the grant this check is
# really about).  Each is separately bounded at 15 s.
FFCMD="d=$MNT/flr_$LABEL; \
e0=\$(timeout 15 ls -a $MNT 2>&1 >/dev/null); r0=\$?; \
e1=\$(timeout 15 stat \$d 2>&1 >/dev/null); r1=\$?; \
e2=\$(timeout 15 cat \$d/w 2>&1 >/dev/null); r2=\$?; \
c0=OTHER; c1=OTHER; c2=OTHER; \
case \"\$e0\" in '') c0=NONE;; *'Input/output error'*) c0=EIO;; *'No such file'*) c0=ENOENT;; *'Stale file handle'*) c0=ESTALE;; *'Structure needs cleaning'*) c0=EFSCORRUPTED;; esac; \
case \"\$e1\" in '') c1=NONE;; *'Input/output error'*) c1=EIO;; *'No such file'*) c1=ENOENT;; *'Stale file handle'*) c1=ESTALE;; *'Structure needs cleaning'*) c1=EFSCORRUPTED;; esac; \
case \"\$e2\" in '') c2=NONE;; *'Input/output error'*) c2=EIO;; *'No such file'*) c2=ENOENT;; *'Stale file handle'*) c2=ESTALE;; *'Structure needs cleaning'*) c2=EFSCORRUPTED;; esac; \
echo ROOT_RC=\$r0; echo ROOT_CLASS=\$c0; echo STAT_RC=\$r1; echo STAT_CLASS=\$c1; \
echo READ_RC=\$r2; echo READ_CLASS=\$c2; \
echo ROOT_ERR=\$e0; echo STAT_ERR=\$e1; echo READ_ERR=\$e2; echo FAILFAST_DONE=1"
tstart=$(date +%s)
measure "$A" 75 "$OUT/A_failfast.txt" '^FAILFAST_DONE=1$' "the path operations needing the fenced victim's grants on $A" \
    "$FFCMD"
twall=$(( $(date +%s) - tstart ))
FF_ROOT=$(field "$OUT/A_failfast.txt" ROOT_CLASS)
FF_STAT=$(field "$OUT/A_failfast.txt" STAT_CLASS)
FF_READ=$(field "$OUT/A_failfast.txt" READ_CLASS)
echo "--- the operations that used to hang returned in ${twall}s: root=$(field "$OUT/A_failfast.txt" ROOT_RC)/$FF_ROOT dir=$(field "$OUT/A_failfast.txt" STAT_RC)/$FF_STAT victimfile=$(field "$OUT/A_failfast.txt" READ_RC)/$FF_READ"
grep -a '^ROOT_ERR=\|^STAT_ERR=\|^READ_ERR=' "$OUT/A_failfast.txt" | cut -c1-160 | sed 's/^/    /'
# The recovery-blocked refusal reaches a caller by THREE different lines, and
# an assertion citing one of them FAILs a lap in which another did the work —
# measured s75b, where both file probes returned a real EIO while
# P240-RBLK-EIO-ABORT stood at zero because the entry gate refused them first.
# Which one fires depends on whether the resource is MASTERED by the blocked
# node or merely held by it, and that changes from lap to lap.
# One field per LINE: field() anchors its match at ^, so three keys on one
# line parse as one key and two empty strings — measured s75d, where
# RBLK_MASTER=6 sat in the capture while the verdict read it as empty and
# summed the refusals to zero.
measure "$A" 30 "$OUT/A_rblk.txt" '^RBLK_DONE=1$' "the acquire path's recovery-blocked refusals on $A" \
    "echo RBLK_EIO=\$(dmesg | grep -ac 'P240-RBLK-EIO-ABORT'); \
     echo RBLK_MASTER=\$(dmesg | grep -ac 'P-RBLK-COVERS-DEAD-MASTER'); \
     echo RBLK_HOLDER=\$(dmesg | grep -ac 'P-RBLK-COVERS-DEAD-HOLDER'); \
     echo RBLK_DONE=1"
rb_eio=$(field "$OUT/A_rblk.txt" RBLK_EIO)
rb_master=$(field "$OUT/A_rblk.txt" RBLK_MASTER)
rb_holder=$(field "$OUT/A_rblk.txt" RBLK_HOLDER)
eio=$(( ${rb_eio:-0} + ${rb_master:-0} + ${rb_holder:-0} ))
echo "--- the recovery-blocked refusals on $A: acquire-abort=$rb_eio entry-gate-dead-master=$rb_master entry-gate-dead-holder=$rb_holder"
case "$FF_ROOT$FF_STAT$FF_READ" in
    *EIO*)
        if [ "$twall" -le 45 ]; then
            echo "  PASS an operation needing the unrecovered slice's grants was REFUSED with EIO instead of hanging (${twall}s <= 45s)"
        else
            echo "  FAIL an operation needing the unrecovered slice's grants did not fail fast got=${twall}s want<=45s"; fails=$((fails+1))
        fi
        ckge "the refusal came from the recovery-blocked mechanism, not from somewhere else" "$eio" 1 ;;
    *)
        if [ "${eio:-0}" -ge 1 ] 2>/dev/null; then
            echo "  FAIL the recovery-blocked mechanism refused $eio time(s) but no probe reported EIO (root=$FF_ROOT dir=$FF_STAT victimfile=$FF_READ) — the refusal did not reach the caller"
            fails=$((fails+1))
        else
            # Not a verdict about MXFS: the probe never reached a frozen grant,
            # so it measured nothing either way.  Say so, keep phase B's
            # evidence, and refuse to grade the lap at the end.
            echo "  NOTE the fail-fast probe never reached one of the victim's frozen grants (root=$FF_ROOT dir=$FF_STAT victimfile=$FF_READ, ${twall}s, zero acquire-path aborts) — it measured nothing about the hang and this lap cannot be graded on it"
            FF_UNREACHED=1
        fi ;;
esac

PHASE_A=$fails
echo "STAGE phase A (ambiguity safety) fails=$PHASE_A at +$(el)s"

# ---- 8. PHASE B: release the refusals, and require that NOTHING is certified.
#
# THIS IS THE OPPOSITE OF WHAT THIS PHASE USED TO ASSERT, and the session-75
# design ruling is why (docs/rulings/fence-ambiguous-drain-and-proof-resume.md).
# It used to demand a certificate naming the sole-survivor exclusive-write gate
# within the bound, on the reasoning that B1's key is absent and A is the only
# live member, so the gate's preconditions hold.  They do hold.  The gate is
# still not a valid proof here:
#
#   A certificate rests on TWO facts.  ADMISSION — the victim cannot obtain
#   permission for a new write.  RETIREMENT — the writes the target ALREADY
#   ACCEPTED from it can no longer take effect.  The gate's PREEMPT AND ABORT
#   carries sark=0, so it aborts the task sets of THE REGISTRANTS IT REMOVES;
#   B1 is not one of them, because this lap's own unanswered command already
#   removed it.  So the gate would give admission and not retirement, and the
#   certificate authorises replaying B1's slice.
#
# B1 is alive, in its original incarnation, with its session up.  No
# drain-independent proof exists while that is true, so BLOCKING IS THE CORRECT
# BEHAVIOUR and a certificate appearing here is the defect — whichever
# mechanism it names.  Liveness is owed from the boot boundary in phase C, not
# from here.  The release still happens: it removes the harness's own
# interference, so what is measured afterwards is the implementation's choice
# and not this script's.
measure "$A" 30 "$OUT/A_release.txt" '^RELEASED gate=0 bootsucc=0$' "the release on $A" \
    "echo 0 > $PARM/fence_gate_inject_refuse; echo 0 > $PARM/fence_bootsucc_inject_refuse; echo RELEASED gate=\$(cat $PARM/fence_gate_inject_refuse) bootsucc=\$(cat $PARM/fence_bootsucc_inject_refuse)"
echo "STAGE released the refusals at +$(el)s — requiring NO certificate for ${PROGRESS_BOUND}s while B1 is alive in its original incarnation"
T_REL=$(date +%s)
# PROGRESS_BOUND is in SECONDS (wait_for_into polls every 2 s and counts
# seconds).  Here it is an exposure window, not a deadline: the re-drive sweep
# runs every 60 s, so the bound has to span several sweeps for the absence of a
# certificate to mean anything.
wait_for_into cert "$A" "$PROGRESS_BOUND" "$MARK" "P236-FENCE-CERTIFIED"
window_into "$OUT/A_progress.txt" "$A" 60 "$MARK"
dump_into "$A" "$OUT/hb_3.txt" "the disklock table after the release"
D3=$(desc_of "$OUT/hb_3.txt" "$VSLOT")
KIND3=$(desc_field "$D3" fence_kind)
certline=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/A_progress.txt" | tail -1 | sed 's/.*mxfs: //')
echo "--- the certificate: $(printf '%s' "${certline:-<none>}" | cut -c1-200)"
echo "--- the victim slot after the release: $(printf '%s' "$D3" | cut -c1-220)"
if [ "$cert" = timeout ]; then
    echo "  PASS nothing was certified in ${PROGRESS_BOUND}s while B1 was alive in its original incarnation — no proof of retirement exists yet, and refusing to invent one is correct"
else
    echo "  FAIL a certificate was published ${cert:+}$(( $(date +%s) - T_REL ))s after the release, while B1 was still alive in its original incarnation and no retirement proof existed"
    fails=$((fails+1))
fi
case "$certline$KIND3" in
    *PREEMPT_ABORT_DONE*)
        echo "  FAIL the certificate names PREEMPT_ABORT_DONE — the unanswered command was relabelled as its own proof"; fails=$((fails+1)) ;;
    *BOOT_SUCCESSION_ABSENT*)
        echo "  FAIL the certificate names BOOT_SUCCESSION_ABSENT — there was no boot boundary; the victim never rebooted"; fails=$((fails+1)) ;;
    *EXCLUSIVE_WRITE_GATE*)
        echo "  FAIL the certificate names the sole-survivor exclusive-write gate — its sark=0 PREEMPT AND ABORT retires nothing belonging to a victim whose registration was already removed, so it proves admission and not retirement"; fails=$((fails+1)) ;;
esac
ck "B1's slice was NOT replayed while its incarnation was still alive" \
   "$(cnt "$OUT/A_progress.txt" 'P163-RECOVERY-COMPLETE')" 0
ck "the ambiguity is still recorded, not discharged" \
   "$(cnt "$OUT/A_progress.txt" 'P238-FENCE-UNRECORDED')" 0

# ---- 9. PHASE C: the boot boundary, which is the first point at which a proof
# this node can stand behind exists.  B1's host is power-cut and returns under a
# new boot: the old nexus is gone, so the old incarnation can neither be
# admitted nor have work outstanding — both facts at once, from one event, with
# no argument about what the unanswered command did.
#
# The retirement half of that is a property of the TARGET, not of this code, so
# it is read from the rig's declaration rather than assumed.  A rig that has
# not measured it ABORTs here instead of predicting a recovery it cannot
# justify (tests/pr_retirement_probe.sh is what measures it).
RETCLASS=$(mxfs_rig_retirement_class)
echo "STAGE phase B complete at +$(el)s; the rig declares task retirement on nexus loss = $RETCLASS"
if [ "$RETCLASS" != retired-before-the-registration-purge ]; then
    echo "ABORT: this rig declares task_retirement_on_nexus_loss=$RETCLASS, so a recovery that crosses a boot boundary cannot be predicted on it; measure it with tests/pr_retirement_probe.sh"
    echo "RESULT: ABORT label=$LABEL stage=retirement-undeclared wall=$(el)s evidence=$OUT"; exit 2
fi
PHASE_B=$fails
PARKED=0                      # the tail destroys it; the trap must not repeat that
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(el)s — phase C, the boot boundary"
$VIRSH start "$B" > /dev/null 2>&1
waitboot "$B"
value_now_into bmd5 "$B" 200 "$OUT/B_md5.txt" '^[0-9a-f]{32}$' "the module copy on $B" \
    "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
ck "B holds the tree build (md5)" "$bmd5" "$(md5sum mxfs.ko | cut -c1-32)"
measure "$B" "$JOIN_BOUND" "$OUT/B_join.txt" '^MOUNT_RC=[0-9]+$' "B's return mount" \
    "rmmod mxfs 2>/dev/null; insmod $KO dyndbg=+p ${MXFS_MODARGS:-$(mxfs_rig_modargs)} 2>&1; mkdir -p $MNT; timeout 300 mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?"
ck "B returned and mounted" "$(field "$OUT/B_join.txt" MOUNT_RC)" "0"
# The liveness the ruling says IS owed, and only from here.  Across the boot
# boundary a drain-independent proof exists, so somebody must take it: the
# certificate must name boot succession (never the unanswered command, and
# never the gate), and B1's slice must actually be replayed.  Until the
# ambiguous slot is revisited by something, nothing does — an ambiguous attempt
# is not armed for retry and every proof mechanism is reachable only from the
# absent-key classification, which an unanswered command never becomes.  That
# is the open half of the lost-response defect, and these three lines are what
# measures it.
window_into "$OUT/A_boundary.txt" "$A" 90 "$MARK"
bcert=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/A_boundary.txt" | tail -1 | sed 's/.*mxfs: //')
echo "--- the certificate after the boot boundary: $(printf '%s' "${bcert:-<none>}" | cut -c1-200)"
case "${bcert:-none}" in
    *BOOT_SUCCESSION_ABSENT*)
        echo "  PASS the boot boundary was taken as the proof, named as boot succession — the one mechanism that supplies admission and retirement from a single event" ;;
    *PREEMPT_ABORT_DONE*)
        echo "  FAIL the certificate names PREEMPT_ABORT_DONE — the unanswered command was relabelled as its own proof at the boundary"; fails=$((fails+1)) ;;
    *EXCLUSIVE_WRITE_GATE*)
        echo "  FAIL the certificate names the exclusive-write gate — it retires nothing belonging to an already-removed registration, and the boot boundary was available"; fails=$((fails+1)) ;;
    none)
        echo "  FAIL no certificate after the boot boundary — a proof that needs no argument about the unanswered command existed and nothing consumed it; the ambiguous slot is never revisited"; fails=$((fails+1)) ;;
    *)
        echo "  FAIL the certificate names a mechanism this lap cannot account for got=[$bcert]"; fails=$((fails+1)) ;;
esac
# The replay runs AFTER the certificate is durable, so a window snapped at the
# certificate cannot contain its completion — measured s75d, where
# A_boundary.txt held the certificate and zero P163 while the end-of-lap window
# on the same node held the P163.  Asserted below, from the final windows.
measure "$B" 90 "$OUT/B_after.txt" '^FILES_END$' "the files B fsynced before it was fenced" \
    "cd $MNT/flr_$LABEL && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_after.txt" > "$OUT/B_after_sha.txt"
if diff -q "$OUT/B_files_sha.txt" "$OUT/B_after_sha.txt" > /dev/null 2>&1; then
    echo "  PASS all $NFILES files B fsynced before the fence came back byte-identical"
else
    echo "  FAIL the dirty-death oracle differs after recovery"; diff "$OUT/B_files_sha.txt" "$OUT/B_after_sha.txt" | head -5; fails=$((fails+1))
fi
for t in "$A" "$B"; do
    window_into "$OUT/${t}_final.txt" "$t" 60 ""
    ck "$t: zero shutdown / BUG / Oops over the lap" "$(bad_lines "$OUT/${t}_final.txt")" 0
done
# Either node may be the one that replayed B1's slice — the prover under its
# resumed proof, or B1's own successor once the certificate let it claim its
# slot — so the assertion is that the slice WAS replayed, not that a
# particular node did it.
ckge "B1's slice was replayed once the boot boundary supplied the proof" \
   "$(( $(cnt "$OUT/${A}_final.txt" 'P163-RECOVERY-COMPLETE') + $(cnt "$OUT/${B}_final.txt" 'P163-RECOVERY-COMPLETE') ))" 1
dump_into "$A" "$OUT/hb_4.txt" "the disklock table at the end"
ck "no fencing descriptor is left standing on B1's slot" \
   "$(desc_of "$OUT/hb_4.txt" "$VSLOT" | grep -ac 'stage=FENCING\|stage=SNAPSHOTTING')" 0

echo "--- phase A (ambiguity safety) fails=$PHASE_A; phase B (nothing certified while the victim lives) fails=$(( PHASE_B - PHASE_A )); phase C (progress once the boot boundary exists) fails=$(( fails - PHASE_B ))"
if [ "$FF_UNREACHED" = 1 ]; then
    echo "ABORT: the fail-fast probe never reached one of the victim's frozen grants, so phase A's hang check measured nothing; the evidence above stands but the lap is not graded"
    echo "RESULT: ABORT label=$LABEL stage=failfast-unreached fails=$fails wall=$(el)s evidence=$OUT"; exit 2
fi
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
