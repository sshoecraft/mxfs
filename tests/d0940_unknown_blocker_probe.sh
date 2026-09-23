#!/bin/bash
# d0940_unknown_blocker_probe.sh — the deterministic arm for D-0940: a ledger
# shared holder bit imported while its heartbeat slot was unresolvable becomes
# an MXFS_DLM_NODE_UNKNOWN (0xFFFFFFFF) blocker that nothing can BAST, release
# or retire, and an EX request behind it never completes.
#
# WHY AN INJECTION.  The defect is a race between one node importing a ledger
# page and the peer claiming its heartbeat slot, and it deadlocked BOTH mounts
# on 1 lap in 4 (s584c on 0.75.90; s584d, s584e and two earlier laps passed).
# A defect that appears once in four cannot be verified by laps that pass, and
# "it did not happen again" is not a disposition.
#
# WHAT IS AND IS NOT FAKED.  `dl_inject_import_unresolvable` answers the next N
# shared-bit slot lookups during a page import as unresolvable — exactly what
# the heartbeat table returns when the peer has not yet claimed its slot.  The
# holder bit, its slot, and the page are all real and were written by a real
# mount; only the timing of the table's view is forced, and that timing IS the
# race.  Nothing is written to the ledger by this harness.
#
# THE SHAPE
#   prep both -> a workload so the root inode and its page carry real shared
#   holder bits -> unmount both (the bits stay in the durable ledger) -> arm
#   the injection on A -> remount both -> A imports the bit as an UNKNOWN
#   blocker and its own EX request queues behind it.
#
# EXPECTED, PRE-FIX (0.75.90 and earlier): the blocker is permanent.  A's mount
# loops 'P-LKTIMEOUT-HOLDER ... holder=4294967295 hmode=PR' once a second and
# never returns; the peer then queues behind A and both mounts hang.
#
# EXPECTED, POST-FIX (0.75.91): the first acquire timeout re-asks the slot,
# which by then names its node, and logs
# 'P-TAUTH-IMPORT-RESOLVED-ONTIMEOUT ... -> owner=<node>'.  The bit becomes
# BASTable, the next retry succeeds, and the mount completes.
#
# The probe asserts the FIX'S OWN LINE, not merely that the mount worked: a
# mount can complete because the injection missed, and that would be a vacuous
# pass.  If the injection never fired, the lap is reported VACUOUS.
#
# WHAT THIS SHAPE REACHES ON 0.75.81 AND LATER (measured s58h and s73g on
# 0.89.x, deterministically: blocker imported 0, re-attributed 0, every
# injected lookup answered by P-TAUTH-IMPORT-RETIRE-VACANT-SLOT).  The bits
# the injection hits are the DESTROYED incarnations' — the only shared bits
# on the platter when the returning mounts import — and both of those
# incarnations are fenced and purged by the returning mounts' admission
# barrier.  A shared bit whose slot already carries a recorded purge is
# retired at import, never installed (dlm.c, the D-0935 shape); a bit
# imported a moment BEFORE its slot's purge is recorded (measured s73h: the
# root inode's slot-0 bit, one per lap) is installed as an UNKNOWN blocker
# and dropped by that owner's purge when it runs (P-TAUTH-PURGE-OWNER
# imported_dropped=1, freed from mxfs_dlm_ledger_purge_owner) — the mount
# completed with zero phantom waits.  So the assertion this arm makes is
# the design's: every injected lookup takes a designed exit (retired at
# import, or installed and then dropped by the purge or re-attributed on
# timeout), no UNKNOWN blocker is left standing, the phantom wait stays
# bounded, and both mounts complete inside the whole-cluster-crash return
# bound.  The on-timeout re-attribution itself (P-TAUTH-IMPORT-RESOLVED-
# ONTIMEOUT) is reached only by a bit of a LIVE peer whose slot is not yet
# claimed and never purged; this shape has produced none in three laps, and
# the count is reported, not required.
#
# the budget rule (derived): prep 45 s (bound 300); workload ~10 s (bound 60);
# destroy + restart both ~60-150 s; module copy ~10 s; the joins are a
# WHOLE-CLUSTER-CRASH RETURN: each mount holds admission through the 62 s
# ghost window for the two destroyed incarnations, then fences, seals and
# replays them (measured s73g: A 82.2 s, B 91.8 s; the module's own
# admission bound is 122 s) — bound each join at 130 s, the module's bound
# plus the mount's own tail; a join past it is a finding.  Whole probe
# ~370 s; wrapper 480 s.
#
# Usage: tests/d0940_unknown_blocker_probe.sh <label>
# Env:   MXFS_NODE_LIST, MXFS_DEV, MXFS_MODARGS, INJECT_N (default 4),
#        JOIN_BOUND (default 130), COUNT (default 60).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
INJECT_N=${INJECT_N:-4}
JOIN_BOUND=${JOIN_BOUND:-130}
COUNT=${COUNT:-60}
PARAM=/sys/module/mxfs/parameters/dl_inject_import_unresolvable
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0940_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# ckge: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/cnt (tests/lib/rig.sh): every capture a
# verdict is counted from crosses the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0940_unknown_blocker_probe label=$LABEL A=$A B=$B (both armed) sv=$SV inject_n=$INJECT_N join_bound=${JOIN_BOUND}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)

for n in $A $B; do
    w=0
    until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 24 ]; do w=$((w+1)); sleep 5; done
done
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s0 ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
value_now_into rv1 "$A" 30 "$OUT/rv_rv1_1.txt" '^[0-9A-F]+$' "rv1 on $A" 'cat /sys/module/mxfs/srcversion 2>/dev/null'
ck "the rig runs this build" "$rv1" "$SV"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL wrong build evidence=$OUT"; exit 2; }

# Real shared holder bits on real pages, written by real mounts.
timeout 60 tests/cross_grant_workload.sh "${LABEL}w" "$COUNT" > "$OUT/work.log" 2>&1
echo "STAGE work rc=$? $(grep -a '^RESULT:' "$OUT/work.log" | cut -c1-120)"
# The nodes are DESTROYED, not unmounted.  A clean departure purges this
# node's shared holder bits out of the ledger — which is the whole point of
# the purge — so after a clean unload there is nothing left to import and the
# injection has nothing to act on (measured: lap s585a armed the knob and the
# injection never fired, reported VACUOUS).  The bits that produce this defect
# in the field are exactly the ones a departure purge did NOT reach, so the
# arm has to leave them behind the way a crash does.
for n in $A $B; do timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1; done
for n in $A $B; do timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1; done
for n in $A $B; do
    w=0
    until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do w=$((w+1)); sleep 5; done
done
echo "STAGE destroy+restart wall=$(( $(date +%s) - s0 ))s"
MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_2.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy evidence=$OUT"; exit 2; }

# Remount, with A importing its first INJECT_N shared bits as unresolvable.
# The knob must be set AFTER insmod and BEFORE mount, so the two are split.
join() {  # <node> <tag> <inject>
    rsx $((JOIN_BOUND + 60)) "$1" "M=\$(date +%s); echo MARK=\$M; lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; [ '$3' = 1 ] && { echo $INJECT_N > $PARAM 2>/dev/null; echo ARMED=\$(cat $PARAM 2>/dev/null); }; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
}
# Arm BOTH nodes: whichever wins the page-takeover race is the one
# that imports, and it is not predictable.  Measured s585b: test1 was
# armed but did ZERO imports (P-TAUTH-IMPORT=0) while test2 did all 13,
# so the lap was vacuous for want of arming the right node.  The knob is
# per-node and consumable, so arming both costs nothing.
join "$A" A 1 & join "$B" B 1 & wait
# both join lists always end in their mount state (a refused mount is a
# verdict); an absent state line is a failed acquisition
capture_require "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $A"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $B"
echo "STAGE join A rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms armed=$(field "$OUT/A_join.txt" ARMED) B rc=$(field "$OUT/B_join.txt" MOUNT_RC) wall=$(field "$OUT/B_join.txt" WALL_MS)ms total=$(( $(date +%s) - s0 ))s"
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    m=$(field "$OUT/${t}_join.txt" MARK); require_epoch "$m" "the join mark of $n"
    measure "$n" 60 "$OUT/${t}_journal.txt" '^JOURNAL_END$' "the kernel journal on $n since its join mark" "journalctl -k --since @$m --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
done
capture_require "$OUT/A_journal.txt" '^JOURNAL_END$' "the kernel journal on $A"
capture_require "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B"

# ---- 1. VACUITY GATE: the injection must have fired, or nothing was measured.
both() { echo $(( $(cnt "$OUT/A_journal.txt" "$1") + $(cnt "$OUT/B_journal.txt" "$1") )); }
inj=$(both 'P-TAUTH-IMPORT-INJECT-UNRESOLVABLE')
echo "--- injection: P-TAUTH-IMPORT-INJECT-UNRESOLVABLE=$inj"
grep -ah 'P-TAUTH-IMPORT-INJECT-UNRESOLVABLE' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*mxfs: /    /' | cut -c1-170 | head -3
if [ "$inj" -lt 1 ]; then
    echo "  VACUOUS the injection never fired — no unresolvable bit was imported, so this lap measured NOTHING about D-0940"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi
ckge "the injection fired (vacuity gate)" "$inj" 1

# ---- 2. An injected unresolvable lookup takes one of two designed exits, and
# the harm needs a third that must not exist.  A bit whose slot already
# carries a recorded purge is RETIRED at import (P-TAUTH-IMPORT-RETIRE-
# VACANT-SLOT).  A bit imported BEFORE its slot's purge is recorded (the
# formation race: measured s73h, the root inode's slot-0 bit) is installed as
# an UNKNOWN-owner blocker (P-TAUTH-IMPORT-ACTIVE owner=4294967295) and is
# then DROPPED by that owner's purge when it runs (P-TAUTH-PURGE-OWNER
# imported_dropped=N) or re-attributed by the on-timeout re-ask.  The harm is
# an UNKNOWN blocker that neither exit reaches: it stands, and the mount
# waits behind it for good.
unk=$(both 'P-TAUTH-IMPORT-ACTIVE.*owner=4294967295')
ret=$(both 'P-TAUTH-IMPORT-RETIRE-VACANT-SLOT')
dropped=$(grep -ah 'P-TAUTH-PURGE-OWNER' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | grep -ao 'imported_dropped=[0-9]*' | cut -d= -f2 | awk '{s+=$1} END{print s+0}')
res=$(both 'P-TAUTH-IMPORT-RESOLVED-ONTIMEOUT')
unres=$(both 'P-TAUTH-IMPORT-UNRESOLVED-ONTIMEOUT')
echo "--- import exits: UNKNOWN blockers installed=$unk; retired at import=$ret; dropped by the owner's purge=$dropped; RESOLVED-ONTIMEOUT=$res UNRESOLVED-ONTIMEOUT=$unres"
grep -ah 'P-TAUTH-IMPORT-ACTIVE' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | grep -a '4294967295' | sed 's/.*mxfs: /    /' | cut -c1-170 | head -2
grep -ah 'P-TAUTH-IMPORT-RETIRE-VACANT-SLOT\|imported_dropped=[1-9]\|ONTIMEOUT' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*mxfs: /    /' | cut -c1-170 | head -4
ckge "the injected lookups took a designed exit: retired at import, or installed and then dropped/re-attributed (retired + dropped + resolved >= injections)" "$(( ret + dropped + res ))" "$inj"
ck "every UNKNOWN blocker installed was dropped by its owner's purge or re-attributed on timeout (none left standing)" "$([ "$unk" -le $(( dropped + res )) ] && echo 0 || echo $(( unk - dropped - res )))" 0

# ---- 4. The harm must be gone: both mounts complete, no endless phantom wait.
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    ck "$n completed its mount" "$(grep -ac '^MOUNTED' "$OUT/${t}_join.txt")" 1
    ck "$n returned a mount rc" "$(field "$OUT/${t}_join.txt" MOUNT_RC)" "0"
    ck "$n: zero shutdown / BUG / Oops" \
       "$(( $(cnt "$OUT/${t}_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/${t}_journal.txt" 'BUG:\|Oops') ))" 0
done
# The pre-fix signature is an UNBOUNDED phantom wait behind the UNKNOWN
# owner.  A transient blocker may cost a timeout or two before its owner's
# purge or the re-ask removes it (the fix repairs ON the timeout); a long
# series is the hang.
pw=$(both 'P-LKTIMEOUT-HOLDER.*holder=4294967295')
echo "--- phantom waits behind owner 4294967295: $pw (an unbounded series is the pre-fix hang; a transient blocker costs 1-2)"
if [ "${pw:-0}" -le 4 ]; then echo "  PASS the phantom wait was bounded ($pw <= 4)"
else echo "  FAIL the phantom wait was not bounded got=$pw want<=4"; fails=$((fails+1)); fi

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
