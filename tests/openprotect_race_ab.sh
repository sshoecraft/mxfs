#!/bin/bash
# openprotect_race_ab.sh — deterministic exerciser for
# D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO (ledger #23).
#
# THE DEFECT (proven 0.11.482, cache_coherency test23): an open()'s
# admission re-read in mxfs_dlm_open_protect raced the BAST worker's
# terminal release-to-NL store (16us apart) and the fail-closed arm turned
# the benign lost race into -EIO on a live published file.  The sess236
# cold-open restart (0.11.483+) did NOT close it: per the sess238 RULE-5
# ruling, the opener's ilock ride lands in the ms-long post-terminal-store
# tail ({mode=NL, DEMOTING, RELFLUSH set}) where the sess47 relflush-admit
# arm admits it with NO mode check — so every restart lap is re-admitted
# instantly into the same tail and the restart budget burns in µs → -EIO.
#
# THIS HARNESS (0.11.486 build-1) makes the interleave deterministic with
# BOTH knobs on the OPENER node A (A holds the grant; B's append BASTs A,
# so A's bast worker runs the demote):
#   - openprotect_race_delay_ms: open_protect holds BEFORE the ilock ride
#     (1ms polls) until it sees {NL, RELFLUSH} — i.e. rides INSIDE the tail.
#   - openprotect_park_ms: bast_process parks right after the terminal NL
#     store, prolonging the natural tail so the ride reliably lands in it.
# The dlmtr arm stamp (i_mxfs_openprot_arm) then NAMES the admit arm that
# granted the ride: P95-OPEN-PROTECT-RESTART/-FAIL print arm=<line>.
#
# BUILD-1 EXPECTATION (proof of the sess238 interleave + restart
# insufficiency): P95-OPEN-INJECT landed_window=1, restarts with
# arm=<relflush-admit line>, and P95-OPEN-PROTECT-FAIL > 0 → script FAILs.
# BUILD-2 EXPECTATION (epoch-aware wait landed): same injection, zero
# P95-OPEN-PROTECT-FAIL, zero userspace failures → script PASSes.
#
# RULE 0 budgets (derived, not round numbers):
#   arm A: ITERS × (ride-hold ≤1s + gated-restart stalls ≤1s) + 60s infra
#   arm B: 2×ITERS × (0.05s cadence + park 0.5s + flush tail ~0.3s) + 60s
#
# GATE MODE (openprotect_race_ab.sh [iters] gate) — sess238 ruling
# deterministic exercise 2, the PRE-TERMINAL GATE phase: arm the admission
# gate at every open's entry (0.11.488 knob openprotect_arm_gate) and keep
# the pre-ride hold so each open pins the gate armed for up to KNOB_MS.  A
# release reaching its terminal store inside that hold must DEFER
# (P95-OPEN-ADMIT-DEFER: no NL store, grant kept CACHED, 25ms dwork
# re-fire) and demote only after the opens disarm — proven by arm B's
# writes all completing.  PASS = DEF ≥1, zero protect-fail, zero
# userspace failures on both arms.
#
# Usage: openprotect_race_ab.sh [iters] [race|gate]   (default 60 race)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
ITERS="${1:-60}"
MODE="${2:-race}"
KNOB_MS=1000
PARK_MS=500
[ "$MODE" = gate ] && PARK_MS=0   # gate phase: no post-store park; the
                                  # defer must PREVENT the terminal store
A=test1    # opener + demote runner: all injection knobs armed here
B=test2    # writer: append-EX generates BASTs against A's grant
D="$MNT/.opr_race_$(date +%s)"
OUT=$(mktemp -d)
A_BUDGET=$((ITERS * 2 + 60))
B_ITERS=$((ITERS * 2))
# gate mode: B's first write can stall behind deferred demotes for the
# whole of arm A's loop, so B's budget must cover A's too.
B_BUDGET=$((B_ITERS + A_BUDGET + 60))
r()  { local n="$1"; shift; timeout 60 bash "$SSH" "$n" "$*" 2>/dev/null; }
rt() { local t="$1" n="$2"; shift 2; timeout "$t" bash "$SSH" "$n" "$*" 2>/dev/null; }

echo "=== openprotect_race_ab[$MODE]: A=$A (ride ${KNOB_MS}ms, park ${PARK_MS}ms, gate=$([ "$MODE" = gate ] && echo 1 || echo 0)) B=$B iters=$ITERS budgets A=${A_BUDGET}s B=${B_BUDGET}s ==="
r "$A" "mkdir -p $D && echo seed > $D/hot && sync" >/dev/null
r "$A" "echo $KNOB_MS > /sys/module/mxfs/parameters/openprotect_race_delay_ms"
r "$A" "echo $PARK_MS > /sys/module/mxfs/parameters/openprotect_park_ms"
if [ "$MODE" = gate ]; then
    r "$A" "echo 1 > /sys/module/mxfs/parameters/openprotect_arm_gate"
else
    r "$A" "echo 0 > /sys/module/mxfs/parameters/openprotect_arm_gate"
fi
r "$B" "echo 0 > /sys/module/mxfs/parameters/openprotect_race_delay_ms"
r "$B" "echo 0 > /sys/module/mxfs/parameters/openprotect_park_ms"
r "$B" "echo 0 > /sys/module/mxfs/parameters/openprotect_arm_gate"
r "$A" "dmesg --clear"; r "$B" "dmesg --clear"

# Arm B: append-EX loop, 50ms cadence — each append EX-acquires the hot
# inode, BASTing A's cached grant; A's bast worker demotes (and parks).
rt "$B_BUDGET" "$B" "for i in \$(seq 1 $B_ITERS); do echo w\$i >> $D/hot || echo BWRFAIL_\$i; sleep 0.05; done" > $OUT/opr_b.out 2>&1 &
BPID=$!

# Arm A: open/read loop.  Every cat is an open -> open_protect admission.
# Failures print FAIL_<iter>:<errno text>.
rt "$A_BUDGET" "$A" "fails=0; for i in \$(seq 1 $ITERS); do err=\$(cat $D/hot 2>&1 >/dev/null) || { fails=\$((fails+1)); echo FAIL_\$i:\$err; }; done; echo A_DONE fails=\$fails" > $OUT/opr_a.out 2>&1
wait $BPID 2>/dev/null

r "$A" "echo 0 > /sys/module/mxfs/parameters/openprotect_race_delay_ms"
r "$A" "echo 0 > /sys/module/mxfs/parameters/openprotect_park_ms"
r "$A" "echo 0 > /sys/module/mxfs/parameters/openprotect_arm_gate"

echo "--- arm A (opener) result ---"
grep -E "A_DONE|FAIL_" $OUT/opr_a.out
echo "--- arm B (writer) failures ---"
grep -c "BWRFAIL" $OUT/opr_b.out || true
echo "--- probes on $A ---"
INJ=$(r "$A" "dmesg | grep -c 'P95-OPEN-INJECT.*landed_window=1'") || INJ=0
PRK=$(r "$A" "dmesg | grep -c 'P95-OPEN-PARK'") || PRK=0
RST=$(r "$A" "dmesg | grep -c 'P95-OPEN-PROTECT-RESTART'") || RST=0
DEF=$(r "$A" "dmesg | grep -c 'P95-OPEN-ADMIT-DEFER'") || DEF=0
PF=$(r "$A" "dmesg | grep -c 'P95-OPEN-PROTECT-FAIL'") || PF=0
UFAIL=$(grep -c "FAIL_" $OUT/opr_a.out) || UFAIL=0
echo "inject_landed_window=$INJ parks=$PRK restarts=$RST admit_defers=$DEF protect_fail=$PF userspace_fails=$UFAIL"
echo "--- arm attribution (arm=<line> names the admit arm that granted the ride) ---"
r "$A" "dmesg | grep -E 'P95-OPEN-(PROTECT-RESTART|PROTECT-FAIL)' | grep -o 'arm=[0-9]*' | sort | uniq -c"
r "$A" "dmesg | grep -E 'P95-OPEN-(PROTECT-RESTART|ADMIT-DEFER|PROTECT-FAIL)' | tail -12"
if [ "$MODE" = gate ]; then
    BW=$(grep -c "BWRFAIL" $OUT/opr_b.out) || BW=0
    if [ "${DEF:-0}" -ge 1 ] && [ "${PF:-0}" -eq 0 ] && [ "${UFAIL:-0}" -eq 0 ] && [ "${BW:-0}" -eq 0 ]; then
        echo "=== PASS[gate]: terminal-store defers ${DEF}x, zero -EIO, both arms clean (eventual demotion proven by B completing) ==="
        exit 0
    fi
    echo "=== FAIL/INCONCLUSIVE[gate]: see counts above ==="
    exit 1
fi
if [ "${INJ:-0}" -ge 1 ] && [ "${RST:-0}" -ge 1 ] && [ "${PF:-0}" -eq 0 ] && [ "${UFAIL:-0}" -eq 0 ]; then
    echo "=== PASS: window achieved ${INJ}x, restart path exercised ${RST}x, zero -EIO, zero userspace failures ==="
    exit 0
fi
echo "=== FAIL/INCONCLUSIVE: see counts above ==="
exit 1
