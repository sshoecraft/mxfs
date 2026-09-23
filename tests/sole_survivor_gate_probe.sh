#!/bin/bash
# sole_survivor_gate_probe.sh — the deterministic arm for D-0936, the
# sole-survivor exclusive-write gate that was armed on a stale registrant
# snapshot and de-registered a live joiner mid-log-recovery.
#
# WHAT THE GATE IS.  When a node finds a dead peer whose PR key is already
# absent and cannot prove exclusion any other way, and it believes it is the
# only live member, it issues PREEMPT AND ABORT rk=own sark=0 type=WRITE
# EXCLUSIVE against the all-registrants reservation.  Per SPC-4 5.9.10.4.4
# that removes EVERY other registration and aborts those nexuses' task sets.
# Its whole authority is the claim that nobody else is there.  That claim was
# taken from a READ KEYS snapshot and never re-checked at issue time, so a
# peer that registered in between was silently evicted with its I/O in flight.
#
# WHY THIS PROBE HAD TO BE BUILT.  The obvious arm — restart both nodes with
# the boot-succession proof injected off, so the absent-key verdict stands —
# CANNOT REACH THE GATE, and a lap that does not reach it has measured
# nothing.  Run 20260909T175945Z_ghost_s581a proved that directly: both nodes
# logged, twelve times each,
#     P238-FENCE-GATE-NOTSOLE ... nlive=2 other_live=2 ... the exclusive-write
#     gate is not attempted
# Two nodes brought up together become members of each other before the fence
# runs, so the guard at dlm/v5_mount.c (nlive == 1 && other_live < 0) is false
# and the gate is never tried.  The gate needs a peer that is a REGISTRANT but
# is NOT LIVE — in the field that is a joiner in the window between
# registering its key and claiming a heartbeat slot, which is a race.
#
# HOW THIS PROBE CLOSES IT WITHOUT FAKING ANYTHING.  0.75.87 adds a TEST-ONLY
# modarg, mount_postregister_pause_ms, that holds a mount inside exactly that
# window: after its PR key is registered, published in the ledger and the
# reservation is in force, and before it claims a heartbeat slot.  B is held
# there while A runs its fence.  The other registrant is therefore REAL — a
# genuine registration by a genuine node — not an injected view.  Nothing
# about the gate's own inputs is simulated.
#
# SHAPE.  destroy+start both VMs (leaving frozen ACTIVE heartbeat records and,
# because the QNAP purges a registration with its iSCSI session, absent PR
# keys) -> deploy the tree build -> mount B with the post-register hold ->
# wait until B has actually registered and parked (P238-POSTREG-PAUSE) ->
# mount A with the boot-succession proof injected off, so its absent-key
# verdict stands and it reaches the gate as the only live member -> capture
# both journals -> assert.
#
# EXPECT A'S MOUNT NOT TO COMPLETE.  With boot-succession refused by injection
# and the gate correctly declining, A has no route to prove exclusion, so it
# parks and its mount fails at the bound.  That is the injection working, not
# a defect, and it is not counted as a failure here.  The node under test is
# B: the fixed gate must leave B's registration and its I/O alone.
#
# EXPECT B'S MOUNT TO BE REFUSED, NOT TO HANG.  A's frozen ghost record is
# unfenceable by anyone while the injection holds (A cannot succeed it, and B
# is not the sole registrant), so B's inline replay cannot finish and the
# admission bound refuses B's mount ('MXFS mount ABORTED: slot mask ... still
# requires recovery', 30 s / 34 rounds in s62e) — which is the admission rule
# working.  B then unregisters, and an ISSUE by A AFTER that, naming 0 other
# registrants, is the gate working too.  What the probe forbids: an ISSUE
# naming a live registrant, and a B mount that outlives its own timeout.
#
# the budget rule (derived, not rounded): VM destroy+start+boot ~150 s (measured 152 s
# on s581a) + deploy ~20 s + B's hold PAUSE_MS/1000 (default 100 s, chosen to
# cover A's fence retry series) + A's bounded park + capture ~30 s.  Whole
# probe ~480 s; JOIN_BOUND 300 s bounds each mount.
#
# Usage: tests/sole_survivor_gate_probe.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS,
#        PAUSE_MS (default 100000), JOIN_BOUND (default 300), VM_RESTART=1.
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
A=${MXFS_NODE_LIST%%,*}          # the prover: reaches the gate
B=${MXFS_NODE_LIST##*,}          # the victim: registrant, held pre-claim
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
PAUSE_MS=${PAUSE_MS:-100000}
JOIN_BOUND=${JOIN_BOUND:-300}
VM_RESTART=${VM_RESTART:-1}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ssgate_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
ckge() { if [ "${2:-0}" -ge "$3" ]; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=$2 want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== sole_survivor_gate_probe label=$LABEL A(prover)=$A B(victim)=$B sv=$SV pause=${PAUSE_MS}ms join_bound=${JOIN_BOUND}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)

if [ "$VM_RESTART" = 1 ]; then
    for n in $A $B; do
        timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1
        timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1
    done
    for n in $A $B; do
        w=0
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait node=$n polls=$w"
    done
    echo "STAGE vm-restart wall=$(( $(date +%s) - s0 ))s"
fi

MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_1.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy fails=$fails"; exit 2; }

measure "$A" 60 "$OUT/hb_before.txt" '^slot +[0-9]+ magic=' "the platter dump on $A before the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
echo "STAGE hb-before: $(grep -ac 'flags=ACTIVE' "$OUT/hb_before.txt") ACTIVE record(s)"
grep -a 'flags=ACTIVE' "$OUT/hb_before.txt" | sed 's/^/    /' | cut -c1-120

# ---- B: register, then park before the heartbeat-slot claim.
KMARK="SSGP-MARK-$LABEL"
rsx 15 "$B" "echo $KMARK > /dev/kmsg" > /dev/null
BMARK=$(date +%s)
echo "MARK=$BMARK" > "$OUT/B_join.txt"
( rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS mount_postregister_pause_ms=$PAUSE_MS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/B_join.txt" ) &
bpid=$!

# Wait until B is DEMONSTRABLY parked in the window — never just sleep and
# hope.  If this line never appears the arm is not set up and everything after
# it would be vacuous.
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after the kernel marker echoed before the join), so
# an ssh that never ran cannot read as "the line never appeared"
wait_for_into parkedw "$B" 120 "$KMARK" "P238-POSTREG-PAUSE"
parked=$([ "$parkedw" = timeout ] && echo 0 || echo 1); w=$parkedw
echo "STAGE B-parked=$parked polls=$w wall=$(( $(date +%s) - s0 ))s"
if [ "$parked" != 1 ]; then
    echo "  FAIL B never reached P238-POSTREG-PAUSE — the registrant window was not set up"
    fails=$((fails+1))
    wait $bpid 2>/dev/null
    echo "RESULT: VACUOUS label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi

# ---- A: mount as the only live member, with the boot-succession proof
# injected off so the absent-key verdict stands and the gate is reached.
AMARK=$(date +%s)
echo "MARK=$AMARK" > "$OUT/A_join.txt"
rsx $((JOIN_BOUND + 60)) "$A" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS fence_bootsucc_inject_refuse=1; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/A_join.txt"
wait $bpid 2>/dev/null
# The journals and the platter are captured BEFORE the join lists are judged:
# a join whose ssh wrapper died (s65f: B's mount outlived its own 300 s
# `timeout` by the wrapper's 60 s of grace — a mount that ignores SIGTERM) is
# exactly the lap whose kernel evidence must not be lost, and the next lap in
# the sweep restarts the VMs.  A mount still running on B is stacked by comm
# (never by cmdline).
measure "$A" 60 "$OUT/A_journal.txt" '^JOURNAL_END$' "the kernel journal on $A since its join mark" "journalctl -k --since @$AMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
measure "$B" 60 "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B since its join mark" "journalctl -k --since @$BMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
measure "$B" 30 "$OUT/B_mount_stack.txt" '^STACK_END$' "the stack of any mount still running on $B" "for p in /proc/[0-9]*; do [ \"\$(cat \$p/comm 2>/dev/null)\" = mount ] || continue; echo \"PID=\${p#/proc/} STATE=\$(cut -d' ' -f3 \$p/stat)\"; cat \$p/stack 2>/dev/null; done; echo STACK_END"
measure "$A" 60 "$OUT/hb_after.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
# both join lists always end in their mount state (a refused mount is a
# verdict); an absent state line is a failed acquisition
capture_require "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $A"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $B"

echo "STAGE join A rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms B rc=$(field "$OUT/B_join.txt" MOUNT_RC) wall=$(field "$OUT/B_join.txt" WALL_MS)ms total=$(( $(date +%s) - s0 ))s"

c() { grep -ac "$1" "$2"; }

# ---- 1. VACUITY GATE.  This is asserted BEFORE any outcome, because a lap in
# which the gate was never attempted says nothing about whether the refusal
# works, and reporting such a lap as a pass is how this project has previously
# manufactured evidence for itself.
gtry=$(c 'P238-FENCE-GATE-TRY' "$OUT/A_journal.txt")
gnot=$(c 'P238-FENCE-GATE-NOTSOLE' "$OUT/A_journal.txt")
echo "--- gate reach: P238-FENCE-GATE-TRY=$gtry P238-FENCE-GATE-NOTSOLE=$gnot"
grep -a 'P238-FENCE-GATE' "$OUT/A_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -4
if [ "$gtry" -lt 1 ]; then
    echo "  VACUOUS the sole-survivor gate was never attempted on $A — this lap measured NOTHING about D-0936"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi
ckge "A attempted the gate (vacuity gate)" "$gtry" 1

# ---- 2. The fix's own code path must LOG, by name.  A clean run is not
# evidence that a refusal works; only the refusal speaking is.
notsole=$(c 'P-PR-GATE-NOTSOLE' "$OUT/A_journal.txt")
issue=$(c 'P-PR-GATE-ISSUE' "$OUT/A_journal.txt")
echo "--- gate outcome: P-PR-GATE-NOTSOLE=$notsole P-PR-GATE-ISSUE=$issue"
grep -a 'P-PR-GATE' "$OUT/A_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-190 | sort -u | head -6
ckge "A refused the gate with P-PR-GATE-NOTSOLE" "$notsole" 1
# An ISSUE is the defect only while another registrant exists.  Measured
# s62e: B's mount was refused by the inline-replay admission bound (A's ghost
# slot is unfenceable under the injection), B unregistered, and A's single
# ISSUE came 3 s later naming '0 other registrant(s)' — the gate working.
# What must never appear is an ISSUE that names a registrant it is about to
# evict.
issue_reg=$(grep -a 'P-PR-GATE-ISSUE' "$OUT/A_journal.txt" | grep -avc ' 0 other registrant')
echo "    P-PR-GATE-ISSUE total=$issue, naming another registrant=$issue_reg"
ck   "A issued no PREEMPT AND ABORT while another registrant existed (P-PR-GATE-ISSUE naming >0 other registrants)" "$issue_reg" 0

# The refusal must name a real other registrant; "0 other registrant(s)" would
# mean it refused for some unrelated reason and B was never in its view.
othern=$(grep -ao 'P-PR-GATE-NOTSOLE[^|]*' "$OUT/A_journal.txt" | grep -ao '[0-9]\+ other registrant' | head -1 | cut -d' ' -f1)
ckge "the refusal names a non-zero other registrant count" "${othern:-0}" 1

# ---- 3. The victim must survive intact: this is the defect's actual harm.
eio=$(c 'log recovery write I/O error' "$OUT/B_journal.txt")
tail=$(c 'failed to locate log tail' "$OUT/B_journal.txt")
ck "B took no log-recovery write I/O error (pre-fix signature)" "$eio" 0
ck "B did not fail to locate its log tail (pre-fix signature)" "$tail" 0
# B's mount either completes, or is REFUSED by the admission bound because
# A's ghost slot stays unfenceable under the injection ('MXFS mount ABORTED:
# slot mask ... still requires recovery', s62e at 30 s) — never a mount that
# outlives its own timeout (MOUNT_RC=124, or no MOUNT_RC because the ssh
# wrapper died: s65f).
bmrc=$(field "$OUT/B_join.txt" MOUNT_RC)
bstate=$(grep -ac '^MOUNTED' "$OUT/B_join.txt")
babort=$(c 'MXFS mount ABORTED' "$OUT/B_journal.txt")
echo "    B mount rc=${bmrc:-none} mounted=$bstate admission-refusals=$babort wall=$(field "$OUT/B_join.txt" WALL_MS)ms"
ck "B's mount completed, or was refused by the admission bound inside its timeout (never hung)" "$([ "$bstate" = 1 ] && echo completed || { [ "${bmrc:-none}" != none ] && [ "${bmrc}" != 124 ] && [ "$babort" -ge 1 ] && echo refused-by-admission || echo hung-or-unknown:rc=${bmrc:-none}; })" "$([ "$bstate" = 1 ] && echo completed || echo refused-by-admission)"
ck "B's registration survived (P238-POSTREG-RESUME reached)" "$(c 'P238-POSTREG-RESUME' "$OUT/B_journal.txt")" 1

for t in A B; do
    ck "$t: zero shutdown / BUG / Oops" \
       "$(grep -ac 'shutting down filesystem\|BUG:\|Oops\|WARNING:' "$OUT/${t}_journal.txt")" 0
done

echo "STAGE hb-after: $(grep -ac 'flags=ACTIVE' "$OUT/hb_after.txt") ACTIVE record(s)"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
