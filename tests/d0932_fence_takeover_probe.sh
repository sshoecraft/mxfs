#!/bin/bash
# d0932_fence_takeover_probe.sh — the deterministic arm for D-0932 (a certified
# fenced incarnation is never revoked on the ordinary path, so a dead prover's
# fencing attempt is untakeable) and for part (2) of D-0933 (the takeover wrote
# the victim's NODE ID into the descriptor's fence_victim_key, a false durable
# intent naming a key no target ever held).
#
# WHY A NEW ARM.  Both records list the same owed legs as their sibling
# defects, and those legs all pass — but they never enter this code.  Measured
# on chain s583f, both laps, all four journals: P238-FENCE-HOLDER-SLOT = 0,
# verdict=REVOKED = 0, P238-FENCE-TAKEOVER = 0.  Two nodes that crash together
# and return together make every victim a previous boot of a host that is live
# again, so boot-succession proves exclusion immediately and no attempt is ever
# left standing for anyone to take over.  A green chain therefore says nothing
# about the takeover, and closing these records on it would retire a fencing
# defect on evidence that never touched it.
#
# WHAT THE PATH ACTUALLY NEEDS: a descriptor durable at stage FENCING whose
# fence_prover_node is an incarnation that can be PROVED revoked — i.e. a
# prover that died with its attempt standing and nothing issued under it.
#
# HOW THIS PRODUCES IT WITHOUT FORGING ANYTHING.  0.75.90 adds a TEST-ONLY
# knob, dl_fence_postintent_pause_ms, that parks a prover in exactly that
# window: after "P236-FENCE-INTENT ... the PREEMPT AND ABORT may now be
# issued", before it is.  Killing the prover there leaves a REAL descriptor
# written by a real prover in the ordinary way.  Nothing is written to the
# platter by this harness, and no view is injected into any decision.
#
# The knob is 0644, so it is armed on ONE node at runtime through
# /sys/module/mxfs/parameters/ — the two nodes need no different insmod args.
#
# SHAPE
#   prep both -> arm the hold on A -> destroy B (A detects the death, lays a
#   durable intent, parks) -> WAIT FOR P236-FENCE-INTENT-HOLD (if it never
#   comes the arm is not set up and everything after is vacuous) -> destroy A
#   with the attempt standing -> restart both -> concurrent join -> assert.
#
# the budget rule (derived, measured today): prep 48 s (bound 300); B's death detected
# in the 31 x 2 s dead window, ~62 s, plus the intent, so the hold appears
# within ~120 s (bound 180); VM destroy+start+boot 152 s; joins bound 300;
# capture ~30 s.  Whole probe ~760 s; wrapper bound 840 s.  A stage that hits
# its own bound is a FAILURE, not a slow pass.
#
# Usage: tests/d0932_fence_takeover_probe.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS,
#        HOLD_MS (default 120000), JOIN_BOUND (default 300).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# MXFS_DEV: the caller's, else the device of A's live mxfs mount after prep
# (mxfs_dev_resolve; no rig's device path is assumed)
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover that will die mid-attempt
B=${MXFS_NODE_LIST##*,}          # the victim whose slot the attempt guards
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
HOLD_MS=${HOLD_MS:-120000}
JOIN_BOUND=${JOIN_BOUND:-300}
# SOLO=1 -- THE ARM THAT REACHES THE PLATTER FALLBACK.  Default 0 keeps the
# original shape.
#
# The default shape restarts BOTH nodes, and that is exactly why it cannot
# exercise what this record is still open for.  Measured on s567 and on s584a/b
# before it: P238-FENCE-HOLDER-SLOT fires 118 times and answers verdict=UNKNOWN
# 118 times, verdict=REVOKED never.  When the prover's HOST comes back, the
# returning mount is a later incarnation of a live node, so v5_incarnation_state
# proves revocation from the membership view and the platter is never asked --
# the takeover happens by the route that was ALREADY fixed, and the route under
# test is silently skipped.  The lap looks perfect and measures nothing.
#
# SOLO=1 leaves the prover's host DOWN and brings back only the victim, alone.
#
# ⚠ SOLO WAS EXPECTED TO REACH THE PLATTER FALLBACK AND IT DOES NOT.  Measured
# s578h (evidence tests/evidence/20260911T130010Z_d0932_s578h): the setup works
# — a real intent is left standing by a real prover that then dies — and the
# attempt IS taken over, but verdict=REVOKED=0 against verdict=UNKNOWN=56.  The
# revocation came from the membership view, i.e. the route that was already
# fixed.  Two structural reasons, both visible in that lap's own probe lines:
#
#   1. ORDERING.  The judge evaluates standing attempts BEFORE it publishes the
#      dead prover's recovery, and publication is the only thing that zeroes
#      the prover's slot.  So the platter read finds the prover's own record
#      still standing — s578h logged flags=1 (ACTIVE) then flags=3
#      (RECOVERY_GUARD) — and UNKNOWN is the only answer it can give inside a
#      single mount episode.
#
#   2. THE JUDGE IS ALWAYS THE FENCER.  The lone survivor that meets the
#      standing attempt is necessarily also the node that fences the dead
#      prover, so it always has a view answer and the platter is never
#      consulted for that tuple.  At two nodes there is no third party to be
#      the judge, and bringing the prover's host back instead just makes the
#      judge the prover's own successor — the view route again.  The attempt
#      cannot be carried into a later episode either: the first episode takes
#      it over, so nothing stands for a second mount to meet.
#
# Leaving SOLO here because the setup half is sound and reusable.  Do NOT run it
# expecting the verdict=REVOKED assertion to pass — it costs 382 s and cannot
# reach it.  See the D-0932 ledger entry for what is being done instead.
SOLO=${SOLO:-0}
UPSET="$A $B"
PARAM=/sys/module/mxfs/parameters/dl_fence_postintent_pause_ms
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0932_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/cnt/mxfs_dev_resolve (tests/lib/rig.sh):
# every capture a verdict is counted from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
VIRSH="timeout 30 virsh -c qemu:///system"
waitboot() {
    local n w=0
    for n in $UPSET; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait polls=$w"
}
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0932_fence_takeover_probe label=$LABEL A(prover)=$A B(victim)=$B sv=$SV hold=${HOLD_MS}ms $(date -u +%FT%TZ) ==="
s0=$(date +%s)

waitboot
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s0 ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
value_now_into rv1 "$A" 30 "$OUT/rv_rv1_1.txt" '^[0-9A-F]+$' "rv1 on $A" "cat /sys/module/mxfs/srcversion 2>/dev/null"
ck "prep deployed the tree build" "$rv1" "$SV"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL wrong build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "  INFO device=$MXFS_DEV (from $A's live mount)"

# ---- arm the hold on A only, at runtime.
value_now_into armed "$A" 30 "$OUT/rv_armed_2.txt" '^-?[0-9]+$' "armed on $A" "echo $HOLD_MS > $PARAM 2>/dev/null; cat $PARAM"
ck "$A armed the post-intent hold" "$armed" "$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL could not arm evidence=$OUT"; exit 2; }

# ---- kill B; A must detect the death, lay a durable intent, and park.
KMARK="D0932FTP-MARK-$LABEL"
rsx 15 "$A" "echo $KMARK > /dev/kmsg" > /dev/null
AMARK=$(date +%s)
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(( $(date +%s) - s0 ))s — waiting for $A to park on its intent"
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after a kernel marker), so an ssh that never ran
# cannot read as "the line never appeared"
wait_for_into heldw "$A" 180 "$KMARK" "P236-FENCE-INTENT-HOLD"
held=$([ "$heldw" = timeout ] && echo 0 || echo 1); w=$heldw
echo "STAGE A-parked=$held polls=$w wall=$(( $(date +%s) - s0 ))s"
rs 30 "$A" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | grep -a 'P236-FENCE-INTENT' | cut -c1-400" > "$OUT/A_intent.txt"
sed 's/^/    /' "$OUT/A_intent.txt" | cut -c1-200 | head -4
if [ "$held" != 1 ]; then
    echo "  FAIL $A never reached P236-FENCE-INTENT-HOLD — no attempt was left standing"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi

# ---- kill A with the attempt standing.  Nothing has been issued under it.
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE destroyed $A with its fencing attempt standing at +$(( $(date +%s) - s0 ))s"
# SOLO: the prover's host stays down, so nothing alive carries its identity and
# the membership view cannot prove its revocation.  See the SOLO comment above.
[ "$SOLO" = 1 ] && UPSET="$B"
for n in $UPSET; do $VIRSH start "$n" > /dev/null 2>&1; done
waitboot
echo "STAGE vm-restart wall=$(( $(date +%s) - s0 ))s upset='$UPSET' solo=$SOLO"

MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $UPSET; do
    value_now_into got "$n" 150 "$OUT/rv_got_3.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy evidence=$OUT"; exit 2; }

# The platter dump needs a node that is UP, which in SOLO is not the prover.
DUMPN=${UPSET%% *}
measure "$DUMPN" 60 "$OUT/hb_before.txt" '^slot +[0-9]+ magic=' "the platter dump on $DUMPN before the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
echo "STAGE hb-before: $(cnt "$OUT/hb_before.txt" 'flags=') record(s), $(cnt "$OUT/hb_before.txt" 'RECOVERY_GUARD') guarded"

# ---- concurrent rejoin.  Someone must meet the standing attempt.
RMARK=$(date +%s)
# D-0943: a node that PANICS mid-mount comes back with an empty journal, and the
# probe then reports VACUOUS -- which reads as "the arm was not set up" and is
# how a kernel panic hid behind a green-looking verdict once already.  Record the
# boot identity before the join so a reboot is detected as itself.  The node
# journal is volatile and keeps no prior boot, so the dying boot survives only in
# /var/log/libvirt/qemu/<node>-serial.log; the assertion below names that path.
BOOTID_BEFORE=$(rs 25 "$B" 'cat /proc/sys/kernel/random/boot_id 2>/dev/null')
echo "STAGE boot-id before join $B=$BOOTID_BEFORE"
join() {
    echo "MARK=$RMARK" > "$OUT/$2_join.txt"
    rsx $((JOIN_BOUND + 60)) "$1" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/$2_join.txt"
}
if [ "$SOLO" = 1 ]; then
    # Only the victim comes back, and it mounts alone.  A lone mount after a
    # whole-cluster death is the bootstrap path, so JOIN_BOUND still applies.
    : > "$OUT/A_join.txt"
    join "$B" B
else
    join "$A" A & join "$B" B & wait
fi
# the boundary, per node by name: the join list always ends in its mount
# state (a refused mount is NOT_MOUNTED, a verdict); its absence is a failed
# acquisition.  A node held down by design has no join to validate.
[ "$SOLO" = 1 ] || capture_require "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $A"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $B"
echo "STAGE join A rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms B rc=$(field "$OUT/B_join.txt" MOUNT_RC) wall=$(field "$OUT/B_join.txt" WALL_MS)ms total=$(( $(date +%s) - s0 ))s"
# A journal pull from a host that is deliberately DOWN is not a capture failure,
# but an empty file must not read as "the node logged nothing" either: the
# assertions below count across both files, so the absent node contributes zero
# and every count is the surviving node's alone.  That is the intent in SOLO.
: > "$OUT/A_journal.txt"
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    case " $UPSET " in *" $n "*) ;; *) echo "  NOTE $n is down by design (solo=$SOLO); no journal pulled"; continue ;; esac
    measure "$n" 60 "$OUT/${t}_journal.txt" '^JOURNAL_END$' "the kernel journal on $n since the join mark" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
done
# the same captures by name, so the verdicts below read from a path the
# boundary was crossed for (A's is empty by design in SOLO)
[ "$SOLO" = 1 ] || capture_require "$OUT/A_journal.txt" '^JOURNAL_END$' "the kernel journal on $A"
capture_require "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B"
measure "$DUMPN" 60 "$OUT/hb_after.txt" '^slot +[0-9]+ magic=' "the platter dump on $DUMPN after the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"

both() { echo $(( $(cnt "$OUT/A_journal.txt" "$1") + $(cnt "$OUT/B_journal.txt" "$1") )); }

# ---- 0. DID THE NODE SURVIVE?  Asserted BEFORE the vacuity gate, because a
# panicked node produces exactly the same "no evidence" signature as an arm that
# never set up, and the two need opposite responses.
BOOTID_AFTER=$(rs 25 "$B" 'cat /proc/sys/kernel/random/boot_id 2>/dev/null')
echo "--- survival: $B boot_id before=$BOOTID_BEFORE after=$BOOTID_AFTER"
if [ -n "$BOOTID_BEFORE" ] && [ -n "$BOOTID_AFTER" ] && \
   [ "$BOOTID_BEFORE" != "$BOOTID_AFTER" ]; then
    echo "  FAIL $B REBOOTED during the join (boot_id changed) — read the dying boot in /var/log/libvirt/qemu/$B-serial.log, NOT the node journal (volatile, keeps no prior boot)"
    fails=$((fails+1))
else
    echo "  PASS $B did not reboot during the join"
fi
# D-0943 non-vacuity: the deferral only happens if a fence CERTIFIED while we
# were still inside our own mount.  Zero of these means the lap never entered
# the window the panic lived in, whatever else it proves.
echo "    D-0943 window reached: P567-FENCE-RETRY-DEFER=$(both 'P567-FENCE-RETRY-DEFER') ; late-death dispatch after mount: P233-MPHASE-DISPATCH=$(both 'P233-MPHASE-DISPATCH')"

# ---- 1. VACUITY GATE, asserted before any outcome.
hslot=$(both 'P238-FENCE-HOLDER-SLOT')
echo "--- reach: P238-FENCE-HOLDER-SLOT=$hslot"
grep -ah 'P238-FENCE-HOLDER-SLOT\|P238-FENCE-HOLDER-STATE' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -4
if [ "$hslot" -lt 1 ]; then
    echo "  VACUOUS no node evaluated the standing attempt's holder — this lap measured NOTHING about D-0932"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi
ckge "the standing attempt's holder was evaluated (vacuity gate)" "$hslot" 1

# ---- 2. D-0932: the holder must be proved REVOKED and the attempt taken over.
echo "--- outcome: verdict=REVOKED=$(both 'verdict=REVOKED') P238-FENCE-TAKEOVER=$(both 'P238-FENCE-TAKEOVER ')"
grep -ah 'P238-FENCE-TAKEOVER' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -4
# "the holder was proved REVOKED" has TWO routes and only one of them prints a
# verdict= line.  v5_incarnation_state answers from the membership view first;
# v5_holder_slot_state — the only emitter of "verdict=" — is consulted ONLY
# when that view returns UNKNOWN (dlm/v5_mount.c:10743).  So a lap in which the
# view proved revocation directly emits NO verdict= line at all, and requiring
# one asserts a route rather than the fact.  Measured s584a: 118 verdict=UNKNOWN
# lines on the node that could not judge its own previous incarnation, while the
# PEER proved it from the view and took the attempt over.
#
# The fact itself is carried by the takeover line, which sits strictly inside
# `if (hnode && hst == V5_INC_REVOKED)` (dlm/v5_mount.c:10756) and is therefore
# unreachable unless the holder was proved revoked.  Assert the fact, and
# report the route for the record.
echo "    revocation route: verdict=REVOKED lines=$(both 'verdict=REVOKED') verdict=UNKNOWN lines=$(both 'verdict=UNKNOWN')"
ckge "the fencing attempt was TAKEN OVER (only reachable once the holder is proved REVOKED)" \
     "$(both 'P238-FENCE-TAKEOVER ')" 1
# THE ASSERTION THIS RECORD IS ACTUALLY OPEN FOR, and it only makes sense in
# SOLO.  In the default shape the view answers first and no verdict= line is
# emitted at all, so requiring one there would assert a route rather than a
# fact.  In SOLO the view CANNOT answer -- the prover's host is down and nothing
# alive carries its identity -- so v5_holder_slot_state is the only remaining
# route to REVOKED, and its verdict line is the only evidence that it ran.  A
# SOLO lap with zero verdict=REVOKED has not reached the platter fallback,
# however green everything else looks.
if [ "$SOLO" = 1 ]; then
    ckge "SOLO: v5_holder_slot_state proved the dead prover REVOKED from the platter" \
         "$(both 'verdict=REVOKED')" 1
fi
# The negative side of the same decision: every attempt whose holder was NOT
# proved revoked must have been left alone.  Those are the P238-FENCE-HOLDER-
# STATE lines; report them so a lap that took an attempt over from a LIVE
# holder would be visible rather than silent.
echo "    holders left alone (not proved revoked): $(both 'P238-FENCE-HOLDER-STATE')"
grep -ah 'P238-FENCE-HOLDER-STATE' "$OUT"/A_journal.txt "$OUT"/B_journal.txt \
  | grep -ao "state=[A-Z]*" | sort | uniq -c | sed 's/^/      /'

# ---- 3. D-0933 part 2: the taken-over intent must name a REAL PR key, never
# the victim's node id.  On s564 every taken-over descriptor read
# fence_key == the victim node id, a key no target ever held.
echo "--- D-0933(2): intents laid after the takeover"
grep -ah 'P236-FENCE-INTENT slot=' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*disklock: /    /' | cut -c1-190 | sort -u | head -4
badkey=0; nintent=0
while read -r vic key; do
    [ -n "$vic" ] || continue
    nintent=$((nintent + 1))
    [ "$key" = "$vic" ] && badkey=$((badkey + 1))
    [ "$key" = "0" ] && badkey=$((badkey + 1))
done <<EOF
$(grep -aho 'P236-FENCE-INTENT slot=[0-9]* victim=[0-9]* epoch=[0-9]* key=[0-9]*' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*victim=\([0-9]*\).*key=\([0-9]*\)/\1 \2/')
EOF
echo "    intents seen=$nintent with key==victim_node_id or key==0: $badkey"
ckge "at least one fencing intent was laid after the takeover" "$nintent" 1
ck   "no intent names the victim's node id (or 0) as the PR key it removes" "$badkey" 0
ck   "no takeover refused for want of a victim key (P238-FENCE-TAKEOVER-NOKEY)" "$(both 'P238-FENCE-TAKEOVER-NOKEY')" 0

# ---- 4. The cluster must actually come back.  In SOLO only the victim was
# brought back, so only the victim is held to this; asserting a mount on a host
# deliberately left down would manufacture a failure the way the first version
# of the D-0941 injector did.
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    case " $UPSET " in *" $n "*) ;; *) echo "  SKIP $t ($n) held down by design (solo=$SOLO)"; continue ;; esac
    ck "$t completed its mount" "$(grep -ac '^MOUNTED' "$OUT/${t}_join.txt")" 1
    ck "$t: zero 'lock request failed after'" "$(cnt "$OUT/${t}_journal.txt" 'lock request failed after')" 0
    ck "$t: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/${t}_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/${t}_journal.txt" 'BUG:\|Oops') ))" 0
done

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
