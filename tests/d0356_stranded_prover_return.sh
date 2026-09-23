#!/bin/bash
# d0356_stranded_prover_return.sh — the two-node residual of D-0356 (clean
# departure of a node that still owns a fencing attempt it cannot certify).
#
# THE QUESTION (design consult, 2026-09-18): when the only other member is the
# dead VICTIM of the departing node's standing attempt, the returning victim
# is the sole rescuer.  It must (a) prove the departed prover dead and fence
# its still-registered key, (b) take over the attempt that names its OWN
# previous incarnation and replay that slice, (c) be admitted with the data
# both incarnations wrote, and neither host may fault or shut down.  Nothing
# here forges platter state: the departing node is made unable to certify by
# the existing test knob that refuses the sole-survivor exclusive-write gate
# (fence_gate_inject_refuse), so its attempt keeps answering
# KEY_ABSENT_UNPROVEN exactly as it would against a target error.
#
# SHAPE
#   prep both -> A and B each write a witness file and sync -> arm the gate
#   refusal on A -> destroy B -> A detects the death, writes the intent, tries
#   the gate, is refused, keeps re-driving -> A unmounts normally (bounded) ->
#   record the platter (A's slot state, the descriptor's owner) and READ KEYS
#   (A's key) -> B cold-returns ALONE and mounts -> B must fence A, take the
#   attempt over, replay both slices, be admitted; both witnesses readable ->
#   A rejoins (knob cleared) -> both witnesses readable on A -> platter clean.
#
# budget (derived): prep 50 s (bound 300); witnesses 10 s; B's death detected
# inside the 31 x 2 s dead window + intent + gate refusal (bound 180); A's
# unmount has nothing to wait on but its own worker joins (bound 120); B boot
# 150 s; B's lone mount = A's 62 s stale window + fence + two clean-slice
# replays (bound 300); A's rejoin bound 300; captures 60 s.
#
# Usage: tests/d0356_stranded_prover_return.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default: the device
#        of A's live mxfs mount after prep, via mxfs_dev_resolve; no rig's
#        device path is assumed), MXFS_MODARGS, JOIN_BOUND (default 300),
#        UMOUNT_BOUND (default 120), MXFS_FAULT_UMOUNT_SRC=<node>:<stage>
#        (capture-contract verification only: a real `umount -l /src` on
#        <node> right before the named acquisition, platter | join; the lap
#        must then ABORT, never reach a verdict).
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS.
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover that cannot certify, then leaves
B=${MXFS_NODE_LIST##*,}          # the victim, then the lone rescuer
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
JOIN_BOUND=${JOIN_BOUND:-300}
UMOUNT_BOUND=${UMOUNT_BOUND:-120}
P=/sys/module/mxfs/parameters
CHK=/src/mxfs/tools/chk_mxfs
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0356spr_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/cnt/capture_require/ensure_src_or_abort/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
fault_before() { # <stage>
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
# hbdump <node> > <file>; keys <node> > <file>: the platter and the key table.
# The caller validates each file with capture_require (the dump's shape is
# '^slot +N magic=', the key listing's is '^PR keys on .*: N registered').
hbdump() { rsx 60 "$1" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"; }
keys()   { rsx 40 "$1" "$CHK --pr-keys $MXFS_DEV"; }
keylist() { grep -oE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | sort -u; }
normkey() { printf '0x%016x' "$(( $1 ))" 2>/dev/null; }
echo "=== d0356_stranded_prover_return label=$LABEL A(prover)=$A B(victim,rescuer)=$B sv=$SV $(date -u +%FT%TZ) ==="

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
rsx 30 "$A" 'cat /sys/module/mxfs/srcversion' > "$OUT/A_srcversion.txt"
capture_require "$OUT/A_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $A"
ck "prep deployed the tree build" "$(head -1 "$OUT/A_srcversion.txt")" "$SV"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL wrong build evidence=$OUT"; exit 2; }
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "STAGE device=$MXFS_DEV (from $A's live mount)"

# ---- witnesses: one file per incarnation, committed before anything dies.
WA="witness_A_$LABEL"; WB="witness_B_$LABEL"
rsx 30 "$A" "echo A-$LABEL-$(date +%s) > $MNT/$WA && sync -f $MNT && cat $MNT/$WA" > "$OUT/witness_A.txt"
rsx 30 "$B" "echo B-$LABEL-$(date +%s) > $MNT/$WB && sync -f $MNT && cat $MNT/$WB" > "$OUT/witness_B.txt"
capture_require "$OUT/witness_A.txt" "^A-$LABEL-[0-9]+$" "the witness write on $A"
capture_require "$OUT/witness_B.txt" "^B-$LABEL-[0-9]+$" "the witness write on $B"
ck "$A wrote and synced its witness" "$(cnt "$OUT/witness_A.txt" "^A-$LABEL-")" 1
ck "$B wrote and synced its witness" "$(cnt "$OUT/witness_B.txt" "^B-$LABEL-")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL witnesses evidence=$OUT"; exit 2; }
ensure_src_or_abort "$A"
hbdump "$A" > "$OUT/hb_before.txt"
capture_require "$OUT/hb_before.txt" '^slot +[0-9]+ magic=' "the platter dump on $A before the death"

# ---- arm: the sole-survivor gate is refused on A, so its attempt against a
#      purged key can never certify (the target on this rig purges a dead
#      nexus's registration, measured s578j/s53b).
value_now_into armed "$A" 30 "$OUT/rv_armed_1.txt" '^-?[0-9]+$' "armed on $A" "echo 1 > $P/fence_gate_inject_refuse; cat $P/fence_gate_inject_refuse"
ck "$A armed the gate refusal" "$armed" "1"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL could not arm evidence=$OUT"; exit 2; }

KMARK="D0356-MARK-$LABEL"
rsx 15 "$A" "echo $KMARK > /dev/kmsg" > /dev/null
AMARK=$(date +%s)
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(el)s — waiting for $A's intent and the gate refusal"
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after a kernel marker), so an ssh that never ran
# cannot read as "the line never appeared"
wait_for_into refusedw "$A" 180 "$KMARK" "P238-FENCE-GATE-INJECT-REFUSED"
refused=$([ "$refusedw" = timeout ] && echo 0 || echo 1); w=$refusedw
rs 30 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | grep -a 'P236-FENCE-INTENT \|P238-FENCE-GATE-INJECT-REFUSED\|P236-FENCEKIND' | cut -c1-400" > "$OUT/A_intent.txt"
sed 's/^/    /' "$OUT/A_intent.txt" | cut -c1-190 | head -3
ANODE=$(grep -ao 'prover=[0-9]*' "$OUT/A_intent.txt" | head -1 | cut -d= -f2)
BNODE=$(grep -ao 'P236-FENCE-INTENT slot=[0-9]* victim=[0-9]*' "$OUT/A_intent.txt" | head -1 | grep -ao 'victim=[0-9]*' | cut -d= -f2)
BSLOT=$(grep -ao 'P236-FENCE-INTENT slot=[0-9]*' "$OUT/A_intent.txt" | head -1 | grep -oE '[0-9]+$')
echo "STAGE A-refused=$refused polls=$w A_node=${ANODE:-?} B_old=${BNODE:-?} victim_slot=${BSLOT:-?} wall=$(el)s"
if [ "$refused" != 1 ] || [ -z "$ANODE" ]; then
    # "never refused" is a statement about the kernel only if its journal
    # was readable: prove that before calling the lap VACUOUS
    rsx 60 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_journal.txt"
    capture_require "$OUT/A_journal.txt" 'kernel: ' "the kernel journal on $A while waiting for the gate refusal"
    echo "  VACUOUS $A never reached a refused attempt — nothing is stranded"
    rs 20 "$A" "echo 0 > $P/fence_gate_inject_refuse" >/dev/null 2>&1
    $VIRSH start "$B" > /dev/null 2>&1     # never leave the victim powered off
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"; exit 3
fi
# the attempt keeps re-driving; give it a few rounds so the departure meets a
# STANDING, non-proving attempt rather than the first refusal
sleep 10

# ---- A LEAVES NORMALLY with the attempt standing and unprovable.
u0=$(date +%s)
rsx $((UMOUNT_BOUND + 20)) "$A" "
    T0=\$(date +%s%N)
    timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?
    echo UMOUNT_MS=\$(( (\$(date +%s%N) - T0) / 1000000 ))
    grep -c ' mxfs ' /proc/mounts | sed 's/^/STILL_MOUNTED=/'
    true
  " > "$OUT/A_umount.txt"
capture_require "$OUT/A_umount.txt" '^STILL_MOUNTED=[0-9]+$' "the unmount of $A"
urc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/A_umount.txt" | head -1)
ums=$(sed -n 's/^UMOUNT_MS=//p' "$OUT/A_umount.txt" | head -1)
still=$(sed -n 's/^STILL_MOUNTED=//p' "$OUT/A_umount.txt" | head -1)
echo "STAGE $A umount rc=${urc:-?} ms=${ums:-?} still_mounted=${still:-?} wall=$(( $(date +%s) - u0 ))s at +$(el)s"
ck "$A's unmount returned 0 within $UMOUNT_BOUND s" "${urc:-124}" "0"
ck "$A is no longer mounted" "${still:-1}" "0"
rsx 60 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_journal.txt"
capture_require "$OUT/A_journal.txt" 'kernel: ' "the kernel journal on $A across its departure"

# ---- what the departure left: the platter and the key table, read from A
#      (unmounted; the device and the PR nexus are still there).  Both tools
#      live on the share: the prerequisite is checked, then each capture is
#      validated against the shape its tool always emits.
ensure_src_or_abort "$A"
fault_before platter
hbdump "$A" > "$OUT/hb_after_umount.txt"
capture_require "$OUT/hb_after_umount.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after its departure"
keys "$A" > "$OUT/keys_after_umount.txt"
capture_require "$OUT/keys_after_umount.txt" '^PR keys on .*: [0-9]+ registered$' "the PR key listing on $A after its departure"
echo "STAGE platter after $A's departure:"
grep -a 'flags=\|desc ' "$OUT/hb_after_umount.txt" | cut -c1-200 | head -8 | sed 's/^/    /'
aslot_line=$(grep -a "node=$ANODE " "$OUT/hb_after_umount.txt" | head -1)
ASLOT=$(echo "$aslot_line" | grep -oE '^slot +[0-9]+' | grep -oE '[0-9]+$')
astate=$(echo "$aslot_line" | grep -oE 'flags=[A-Z_]+' | cut -d= -f2)
akey=$(echo "$aslot_line" | grep -oE 'pr_key=0x[0-9a-f]+' | cut -d= -f2)
desc_owner=$(grep -a 'desc ' "$OUT/hb_after_umount.txt" | grep -a "victim=$BNODE/" | grep -oE 'owner=[0-9]+' | head -1 | cut -d= -f2)
desc_stage=$(grep -a 'desc ' "$OUT/hb_after_umount.txt" | grep -a "victim=$BNODE/" | grep -oE 'stage=[A-Z_]+' | head -1 | cut -d= -f2)
key_present=$( [ -n "$akey" ] && keylist "$OUT/keys_after_umount.txt" | grep -c "^$(normkey "$akey")$" || echo 0)
echo "STAGE A slot=${ASLOT:-?} state=${astate:-?} key=${akey:-?} key_registered=$key_present ; attempt on slot $BSLOT: stage=${desc_stage:-none} owner=${desc_owner:-none}"
echo "  NOTE the departure's own account:"
grep -ah 'P278\|P236-RELEASE\|P236-RELINQ\|P236-RECOV-RELINQUISH\|P304-RETIRE-PENDING-RELEASED\|P302\|P301\|P303\|P259\|P-DEPART-POISON\|P-GOODBYE' "$OUT/A_journal.txt" \
  | sed 's/.*kernel: /      /' | cut -c1-170 | tail -8
# THE ONE COMBINATION THAT MUST NOT EXIST: a consumable (or key-less) record
# for A while a descriptor on the platter still names A as owner.
if [ "${desc_owner:-0}" = "$ANODE" ]; then
    ck "a standing attempt still owned by $A leaves $A's record non-consumable (ACTIVE) so the rescuer can prove it dead" "${astate:-?}" "ACTIVE"
    ck "and leaves $A's key registered as the fence target" "$key_present" "1"
    echo "  MEASURED the stranded-owner shape: A departed normally, its attempt stands under its own tuple"
else
    ckge "the attempt was given back or consumed before the release (owner=${desc_owner:-none}); A's record is then RETIRE_PENDING" "$(cnt "$OUT/hb_after_umount.txt" 'RETIRE_PENDING')" 1
    echo "  NOTE the stranded-owner shape was NOT produced on this build (attempt stage=${desc_stage:-none} owner=${desc_owner:-none}); B still judges A's departure alone below"
fi

# ---- B COLD-RETURNS ALONE.  Nothing is repaired by hand.
$VIRSH start "$B" > /dev/null 2>&1
w=0
until [ "$(rs 15 "$B" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
    w=$((w+1)); sleep 5
done
echo "STAGE $B booted polls=$w wall=$(el)s"
MD5=$(md5sum mxfs.ko | cut -c1-32)
ensure_src_or_abort "$B"
fault_before join
rsx 60 "$B" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32" > "$OUT/B_md5.txt"
capture_require "$OUT/B_md5.txt" '^[0-9a-f]{32}$' "the module copy on $B"
ck "$B runs the tree build (md5)" "$(head -1 "$OUT/B_md5.txt")" "$MD5"
RMARK=$(date +%s)
# the witness cats may legitimately fail (that IS the measurement): their
# text is output, and the list ends in a command whose status is the mount
# state's, so a failed cat is never mistaken for a failed invocation
rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; cat $MNT/$WA 2>&1; cat $MNT/$WB 2>&1; true" > "$OUT/B_join.txt"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the lone mount of $B"
bwall=$(sed -n 's/^WALL_MS=//p' "$OUT/B_join.txt" | head -1)
echo "STAGE $B lone mount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/B_join.txt" | head -1) wall=${bwall:-?}ms total=$(el)s"
rsx 60 "$B" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/B_journal.txt"
capture_require "$OUT/B_journal.txt" 'kernel: ' "the kernel journal on $B across its lone mount"
hbdump "$B" > "$OUT/hb_after_B.txt"
capture_require "$OUT/hb_after_B.txt" '^slot +[0-9]+ magic=' "the platter dump on $B after its return"

ck "$B completed its lone mount" "$(cnt "$OUT/B_join.txt" '^MOUNTED')" 1
echo "--- $B's account (fence of $A, takeover of the attempt naming its old self, recoveries):"
grep -ah "P236-FENCE-CERTIFIED\|P238-FENCE-TAKEOVER \|P238-FENCE-HOLDER-SLOT\|P163-RECOVERY-COMPLETE\|P163-RECOVERY-PENDING\|P-DEAD-INC\|BOOT_SUCCESSION\|P236-FENCEKIND" "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-175 | head -12
certA=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/B_journal.txt" | grep -ac "victim=$ANODE ")
certAkind=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/B_journal.txt" | grep -a "victim=$ANODE " | grep -oE 'kind=[A-Z_]+' | head -1 | cut -d= -f2)
recA=$(grep -a 'P163-RECOVERY-COMPLETE' "$OUT/B_journal.txt" | grep -ac "slot=${ASLOT:-99} ")
recB=$(grep -a 'P163-RECOVERY-COMPLETE' "$OUT/B_journal.txt" | grep -ac "slot=$BSLOT ")
BNEW=$(grep -ao 'claimed heartbeat slot [0-9]* for node [0-9]*' "$OUT/B_journal.txt" | head -1 | grep -oE '[0-9]+$')
# grep -c exits 1 on a zero count, so an `|| echo 0` fallback would print a
# second 0 (s53d scored "0\n0" != 0); count with the exit status ignored.
selfcert=0; [ -n "$BNEW" ] && selfcert=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/B_journal.txt" | grep -ac "victim=$BNEW " ; true)
if [ "${desc_owner:-0}" = "$ANODE" ]; then
    # the stranded-owner shape: A left owning the attempt, so B must prove A
    # dead (fence) and run A's recovery before it can take the attempt over
    ckge "$B fenced the departed prover $A (certified; kind=${certAkind:-none})" "$certA" 1
    ckge "$B completed the recovery of $A's slot ${ASLOT:-?}" "$recA" 1
else
    # the relinquished shape (measured s67h, 0.89.4): A gave the attempt back
    # UNOWNED at its clean departure and its record went RETIRE_PENDING, so B
    # settles A by the PR-key retirement proof — no fence, no recovery of A's
    # slot — and takes the unowned attempt over on its own account
    ck   "$B did not fence the cleanly departed $A (nothing to prove dead)" "$certA" 0
    ckge "$B settled $A's clean departure by the retire proof (P304-RETIRE-COMPLETED-BY-PEER slot ${ASLOT:-?})" "$(cnt "$OUT/B_journal.txt" "P304-RETIRE-COMPLETED-BY-PEER slot=${ASLOT:-99} ")" 1
    ck   "$A's slot ${ASLOT:-?} is EMPTY after $B's return (consumed, not recovered)" "$(grep -aE "^slot +${ASLOT:-99} " "$OUT/hb_after_B.txt" | grep -ac 'flags=EMPTY')" 1
fi
ckge "$B completed the recovery of its own previous incarnation's slot $BSLOT (the stranded attempt was consumed)" "$recB" 1
ck "$B did not fence its own new incarnation (${BNEW:-unknown})" "$selfcert" 0
ck "$B reads $A's witness after recovery" "$(cnt "$OUT/B_join.txt" "^A-$LABEL-")" 1
ck "$B reads its own previous incarnation's witness after recovery" "$(cnt "$OUT/B_join.txt" "^B-$LABEL-")" 1
ck "$B: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/B_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/B_journal.txt" 'BUG:\|Oops') ))" 0
ck "no FENCING or SNAPSHOTTING descriptor left on the platter after $B's return" "$(grep -a 'desc ' "$OUT/hb_after_B.txt" | grep -ac 'stage=FENCING\|stage=SNAPSHOTTING')" 0
if [ -n "$akey" ]; then
    keys "$B" > "$OUT/keys_after_B.txt"
    capture_require "$OUT/keys_after_B.txt" '^PR keys on .*: [0-9]+ registered$' "the PR key listing on $B after its return"
    ck "$A's key was retired by the fence" "$(keylist "$OUT/keys_after_B.txt" | grep -c "^$(normkey "$akey")$")" 0
fi

# ---- A REJOINS (knob cleared) and reads both witnesses.
rs 20 "$A" "echo 0 > $P/fence_gate_inject_refuse" >/dev/null 2>&1
JMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$A" "T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; cat $MNT/$WA 2>&1; cat $MNT/$WB 2>&1; true" > "$OUT/A_rejoin.txt"
capture_require "$OUT/A_rejoin.txt" '^(MOUNTED|NOT_MOUNTED)$' "the rejoin of $A"
rsx 60 "$A" "journalctl -k --since @$JMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/A_rejoin_journal.txt"
capture_require "$OUT/A_rejoin_journal.txt" 'kernel: ' "the kernel journal on $A across its rejoin"
echo "STAGE $A rejoin rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/A_rejoin.txt" | head -1) wall=$(sed -n 's/^WALL_MS=//p' "$OUT/A_rejoin.txt" | head -1)ms total=$(el)s"
ck "$A rejoined" "$(cnt "$OUT/A_rejoin.txt" '^MOUNTED')" 1
ck "$A was not refused for a predecessor key" "$(cnt "$OUT/A_rejoin_journal.txt" 'P305-PR-PREDECESSOR-KEY-PRESENT\|P-PR-QUARANTINE-REFUSED')" 0
ck "$A reads both witnesses" "$(( $(cnt "$OUT/A_rejoin.txt" "^A-$LABEL-") + $(cnt "$OUT/A_rejoin.txt" "^B-$LABEL-") ))" 2
ck "$A: zero shutdown / BUG / Oops on rejoin" "$(( $(cnt "$OUT/A_rejoin_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/A_rejoin_journal.txt" 'BUG:\|Oops') ))" 0

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails A_state_after_depart=${astate:-?} attempt_owner=${desc_owner:-none} B_mount_ms=${bwall:-?} fenceA_kind=${certAkind:-none} wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
