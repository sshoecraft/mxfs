#!/bin/bash
# auth_lease_resurrection.sh — once an authority lease has CLOSED, can anything
# bring it back?
#
# WHY THIS EXISTS.  The lease contains a fenced-but-undetecting node by expiring
# on a deadline it set for itself, and the whole value of that depends on
# CLOSED being terminal.  Three ways it could quietly stop being terminal are
# written into the code as invariants, and until this lap none of them had been
# exercised — the harness that proved the defect only ever reaches the moment of
# closure and stops there.
#
#   resume       The heartbeat thread comes back from a stall.  It must find
#                the lease closed and STOP, not resume publishing to a slot
#                this node no longer owns, and the mount must still refuse
#                writes afterwards.  A heartbeat that starts working again is
#                not a grant.
#   resvgone     The heartbeat comes back to a LUN that has stopped refusing
#                anyone — the victim really was fenced, the prover then died,
#                and the appliance purged the last registration and released
#                the reservation with it.  A heartbeat CAS against that LUN
#                SUCCEEDS.  This is the case whose absence would matter most,
#                because a permissive LUN is exactly the state the original
#                defect left behind: if a landed beat renewed authority there,
#                the fix would undo itself the moment the stall ended.
#   latecompletion
#                A beat REACHES THE TARGET and its completion is then withheld.
#                Peers can see that beat and age it while this node waits, so a
#                deadline anchored at COMPLETION would hand this node authority
#                measured from an instant that had already passed for everyone
#                else — the exact mistake the design consult corrected, and the
#                only invariant of the five with no evidence at all until now.
#                The assertion is direct: the closure's deadline minus the
#                instant the beat was ISSUED must be one lease, not one lease
#                plus however long the completion was withheld.
#   staleanchor  A renewal arrives whose beat was ISSUED after authority had
#                already lapsed.  It must close the epoch rather than extend
#                it — a heartbeat CAS succeeds perfectly well against a target
#                that has released its reservation and stopped refusing
#                anyone, which is exactly the state the defect leaves behind,
#                so its success proves nothing about ownership.
#
#                That guard is defence in depth: no live path reaches it,
#                because the pre-issue check stops the heartbeat first.  So
#                this arm arms dbg_hb_skip_auth_check, which takes the primary
#                check away for ONE cycle and lets a stale-anchored renewal
#                actually arrive.  Nothing else is weakened.
#
# Both arms also assert the third invariant: once authority is closed the
# reservation-health tick must not run at all.  Its repair arm RESERVEs and its
# fenced-self arm can re-REGISTER, either of which would be an expired
# incarnation undoing its own fence.
#
# THE FIRST TWO ARMS NEED NO FENCE and that is deliberate.  The question is not
# how the node finds out — that is tests/fence_late_detection.sh — but whether
# what it found out can be forgotten.  A heartbeat parked past the lease reaches
# the same CLOSED state with none of the fencing machinery in the way, which
# makes every failure there unambiguous.  resvgone is the exception: its whole
# subject is the state of the LUN, so it has to build the real one, and it
# leaves the prover destroyed.
#
# the budget rule (derived): prep <= 300 (measured 46-69) + the healthy control
# 20 + the arm 10 + the park, lease 30 + 15 = 45 + closure observation, bound 60
# + waiting out the park 45 + the resume captures 30 + the refusal probe 30 +
# the slot compare 40 + final captures 40 = 620.  Caller bound 660 s per arm.
#
# Usage: tests/auth_lease_resurrection.sh <arm> <label>   arm: resume|staleanchor|resvgone|latecompletion
# Env:   MXFS_NODE_LIST (default test1,test2), PARK_MS (45000)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
ARM=${1:?arm: resume | staleanchor}
LABEL=${2:?label}
case "$ARM" in resume|staleanchor|resvgone|latecompletion) ;; *) echo "arm must be resume, staleanchor, resvgone or latecompletion"; exit 2 ;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}          # the node whose lease is allowed to lapse
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
DUMP=/src/mxfs/tools/disklock_hb_dump.py
CHK=/src/mxfs/tools/chk_mxfs
PARK_MS=${PARK_MS:-45000}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_authres_${ARM}_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="AUTHRES-MARK-$LABEL"
echo "=== auth_lease_resurrection arm=$ARM label=$LABEL B(lease lapses)=$B $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

if [ "$(strings -a mxfs.ko | grep -c 'P290-AUTH-CLOSED')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no authority lease, so there is nothing here to measure"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
if [ "$ARM" = staleanchor ] && [ "$(strings -a mxfs.ko | grep -c 'P-DBG-HB-SKIP-AUTH')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no dbg_hb_skip_auth_check injection, so a"
    echo "       stale-anchored renewal cannot reach the guard and this arm"
    echo "       would measure the pre-issue check a second time instead."
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
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
dump_into() { measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"; }

# ---- 1. the control: B is healthy, mounted and writable.  Every assertion
#         below is that something is REFUSED or DOES NOT HAPPEN, and a lap that
#         has broken its own probe satisfies all of them.
measure "$B" 60 "$OUT/B_pre.txt" '^PRE_END$' "B mounted and writable before the lease lapses" \
    "echo $MARK > /dev/kmsg; d=$MNT/authres_$LABEL; mkdir -p \$d && printf 'pre\n' > \$d/f && sync -f $MNT && echo PRE_OK; echo PRE_END"
ck "control: B accepts work while its lease is live" "$(cnt "$OUT/B_pre.txt" '^PRE_OK$')" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

# ---- 2. arm the injections.  The staleanchor arm ALSO parks the periodic
#         evaluator, because the renewal guard is only reachable while the
#         epoch is still ADMITTED — if the pump has already closed it, the
#         renewal returns at the sticky check above the guard and the lap
#         would grade stickiness a second time instead.
PUMP=0
HEALTH=0
[ "$ARM" = staleanchor ] && PUMP=300000
DELAY=0
if [ "$ARM" = latecompletion ]; then
    # the completion is withheld for longer than the lease, so the deadline
    # derived from the ISSUE instant has already passed when it is delivered
    DELAY=${DELAY_MS:-45000}
    PARK_MS=0
    # park the periodic evaluator: it would close the epoch during the delay on
    # its own, and then stickiness rather than the anchor would be what refused
    # the write — a true result for the wrong reason
    PUMP=300000
fi
if [ "$ARM" = resvgone ]; then
    # long enough for the whole fence-and-purge sequence to happen while B is
    # away: the 62 s dead window, the fence, the prover's death, and the 30-40 s
    # the appliance takes to purge the last registration.
    PARK_MS=${PARK_MS_RESVGONE:-180000}
    # hold the proactive PR check off as well, or B withdraws on SELF_GONE and
    # the lap grades the detection path instead of the lease
    HEALTH=300000
fi
measure "$B" 30 "$OUT/B_arm.txt" '^PARKED=[0-9]+ SKIP=[0-9]+ PUMP=[0-9]+$' "the injections on $B" \
    "echo $PUMP > $PARM/dbg_auth_pump_pause_ms; echo $HEALTH > $PARM/dbg_resv_health_pause_ms; echo $DELAY > $PARM/dbg_hb_completion_delay_ms; $( [ "$ARM" = staleanchor ] && echo "echo 1 > $PARM/dbg_hb_skip_auth_check;" ) echo $PARK_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo PARKED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing') SKIP=\$(cat $PARM/dbg_hb_skip_auth_check) PUMP=\$(cat $PARM/dbg_auth_pump_pause_ms)"
if [ "$ARM" = latecompletion ]; then
    measure "$B" 30 "$OUT/B_delay.txt" '^DELAYED=[0-9]+$' "the withheld completion on $B" \
        "echo DELAYED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-HB-COMPLETION-DELAY node')"
    ck "a landed beat's completion is being withheld" "$(field "$OUT/B_delay.txt" DELAYED)" 1
else
    ck "B's heartbeat is parked, so its lease will lapse" "$(field "$OUT/B_arm.txt" PARKED)" 1
fi
[ "$ARM" != staleanchor ] || ck "the pre-issue authority check will be skipped for one cycle" "$(field "$OUT/B_arm.txt" SKIP)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
dump_into "$A" "$OUT/hb_armed.txt" "the disklock table with B parked"
BSLOT_ARMED=$(grep -a "^slot " "$OUT/hb_armed.txt" | grep -a "$(grep -ao 'node=[0-9]*' "$OUT/hb_armed.txt" | head -1 | cut -d= -f2)" | head -1)

# ---- 2b. resvgone only: build the permissive LUN while B is away.  A declares
#          B dead and PREEMPT AND ABORTs it, then A is destroyed and the
#          appliance purges the last registration and the reservation with it.
if [ "$ARM" = resvgone ]; then
    keys_into() { measure "$1" 40 "$2" '^KEYS_END$' "$3" \
        "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -r $MXFS_DEV 2>&1 | grep -ai 'Key=\|type:\|reservation held' | sed 's/^/RESV /'; echo KEYS_END"; }
    resv_none() { grep -aiq 'RESV.*no reservation held' "$1" && echo yes || echo no; }
    nkeys() { grep -acE '^  0x[0-9a-f]+' "$1"; }
    keys_into "$A" "$OUT/K0.txt" "READ KEYS before the fence"
    ckge "before the fence: the LUN has registrants" "$(nkeys "$OUT/K0.txt")" 1
    w=0
    while [ $w -lt 150 ]; do
        keys_into "$A" "$OUT/K1.txt" "READ KEYS while waiting for the fence"
        [ "$(nkeys "$OUT/K1.txt")" = 1 ] && break
        sleep 5; w=$((w+5))
    done
    echo "STAGE fence: registrants now $(nkeys "$OUT/K1.txt") after ${w}s at +$(el)s"
    if [ "$(nkeys "$OUT/K1.txt")" != 1 ]; then
        echo "  A never fenced B inside 150s, so the LUN cannot be made permissive the honest way"
        echo "RESULT: VACUOUS label=$LABEL stage=no-fence wall=$(el)s evidence=$OUT"; exit 3
    fi
    $VIRSH destroy "$A" > /dev/null 2>&1
    echo "STAGE destroyed $A at +$(el)s — waiting for the purge"
    w=0
    while [ $w -lt 120 ]; do
        keys_into "$B" "$OUT/K2.txt" "READ KEYS from B while waiting for the purge"
        [ "$(resv_none "$OUT/K2.txt")" = yes ] && break
        sleep 5; w=$((w+5))
    done
    echo "STAGE purge: reservation=$(resv_none "$OUT/K2.txt") keys=$(nkeys "$OUT/K2.txt") after ${w}s at +$(el)s"
    if [ "$(resv_none "$OUT/K2.txt")" != yes ]; then
        echo "  the reservation never disappeared, so the LUN never became permissive"
        echo "RESULT: VACUOUS label=$LABEL stage=no-purge wall=$(el)s evidence=$OUT"; exit 3
    fi
    ck "the LUN now refuses nobody: zero registrants" "$(nkeys "$OUT/K2.txt")" 0
fi

# ---- 3. wait out the park.  The lease is 30 s and the park is longer, so the
#         lapse happens inside it; the heartbeat then returns to a closed lease.
if [ "$ARM" = latecompletion ]; then
    echo "STAGE waiting out the ${DELAY}ms withheld completion at +$(el)s"
    sleep $(( DELAY / 1000 + 10 ))
else
    echo "STAGE waiting out the ${PARK_MS}ms park at +$(el)s"
    sleep $(( PARK_MS / 1000 + 5 ))
fi
measure "$B" 30 "$OUT/B_resumed.txt" '^RESUMED=[0-9]+ CLOSED=[0-9]+ HBSTOP=[0-9]+ SKIPPED=[0-9]+$' "what B did when its heartbeat came back" \
    "echo RESUMED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*resumed') CLOSED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P290-AUTH-CLOSED') HBSTOP=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P290-AUTH-HB-STOP') SKIPPED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-HB-SKIP-AUTH')"
RESUMED=$(field "$OUT/B_resumed.txt" RESUMED)
CLOSED=$(field "$OUT/B_resumed.txt" CLOSED)
echo "STAGE resumed=$RESUMED closed=$CLOSED hb_stop=$(field "$OUT/B_resumed.txt" HBSTOP) skipped=$(field "$OUT/B_resumed.txt" SKIPPED) at +$(el)s"
if [ "$ARM" != latecompletion ] && [ "$RESUMED" = 0 ]; then
    echo "  the heartbeat never came back, so nothing had the chance to resurrect anything"
    echo "RESULT: VACUOUS label=$LABEL stage=no-resume wall=$(el)s evidence=$OUT"; exit 3
fi
ckge "the authority lease CLOSED while the heartbeat was away" "$CLOSED" 1
[ "$ARM" != staleanchor ] || ck "the stale-anchored beat was actually issued (the injection fired)" "$(field "$OUT/B_resumed.txt" SKIPPED)" 1

# ---- 4. THE ASSERTIONS.  What must NOT have happened now that the heartbeat
#         is back and running.
measure "$B" 60 "$OUT/B_after.txt" '^JOURNAL_END$' "B's journal after the heartbeat came back" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
# the closure line AFTER the resume, for the staleanchor arm, must name the
# renewal rather than a bare expiry — that is the guard under test speaking
if [ "$ARM" = staleanchor ]; then
    ckge "the stale-anchored renewal CLOSED the epoch instead of extending it" \
        "$(cnt "$OUT/B_after.txt" 'renews nothing')" 1
    echo "    $(grep -a 'renews nothing' "$OUT/B_after.txt" | head -1 | sed 's/.*mxfs: //' | cut -c1-200)"
elif [ "$ARM" != latecompletion ]; then
    ckge "the returning heartbeat found the lease closed and STOPPED" \
        "$(cnt "$OUT/B_after.txt" 'P290-AUTH-HB-STOP')" 1
fi
if [ "$ARM" = latecompletion ]; then
    # THE DIRECT ASSERTION ON THE ANCHOR.  The kernel prints the instant the
    # beat was issued when it starts withholding the completion, and the
    # instant the lease was set to expire when it closes.  The difference
    # between them IS the anchor: one lease means the deadline was derived
    # from the issue, and one lease plus the withheld interval would mean it
    # was derived from the completion — authority this node never proved.
    ISSUED=$(grep -ao 'P-DBG-HB-COMPLETION-DELAY node.*issued_ms=[0-9]*' "$OUT/B_after.txt" | head -1 | grep -ao 'issued_ms=[0-9]*' | cut -d= -f2)
    DEADLINE=$(grep -a 'P290-AUTH-CLOSED' "$OUT/B_after.txt" | head -1 | grep -ao 'deadline_ms=[0-9]*' | cut -d= -f2)
    DELIVERED=$(grep -ao 'P-DBG-HB-COMPLETION-DELAY-END.*delivered_ms=[0-9]*' "$OUT/B_after.txt" | head -1 | grep -ao 'delivered_ms=[0-9]*' | cut -d= -f2)
    echo "STAGE issued_ms=$ISSUED delivered_ms=$DELIVERED deadline_ms=$DEADLINE"
    ck "the completion really was delivered late" \
        "$([ -n "$DELIVERED" ] && [ -n "$ISSUED" ] && [ $(( DELIVERED - ISSUED )) -ge $(( DELAY - 2000 )) ] && echo late || echo prompt)" late
    ck "the lease deadline was derived from the ISSUE instant, not the completion" \
        "$([ -n "$DEADLINE" ] && [ -n "$ISSUED" ] && echo $(( DEADLINE - ISSUED )))" 30000
fi
if [ "$ARM" = resvgone ]; then
    # the whole point of this arm: the LUN would have taken the write.  Nothing
    # was left on it to refuse anyone, and the containment has to come from the
    # node's own lease and from nothing else.
    ck "the LUN was permissive when the heartbeat came back — no registrants, no reservation" \
        "$(resv_none "$OUT/K2.txt")" yes
    ck "no LUN-dependent detector fired: the containment is the lease, not detection" \
        "$(grep -a 'P277-RESV-CONFLICT\|P277-PR-FULLSTATUS\|P277-FENCED-SELF-WITHDRAW\|P305-RESV-SELF-GONE' "$OUT/B_after.txt" 2>/dev/null | grep -avc 'AUTHORITY_LEASE_EXPIRED')" 0
fi
# the reservation-health tick must not have run at all after the closure: its
# repair arm RESERVEs and its fenced-self arm can re-REGISTER
ck "no reservation REPAIR was attempted under a closed lease" "$(cnt "$OUT/B_after.txt" 'P305-RESV-REPAIRED')" 0
ck "B: zero BUG / Oops" "$(cnt "$OUT/B_after.txt" 'BUG:\|Oops')" 0

# the sticky property, measured rather than read: a write AFTER the heartbeat
# is working again must still be refused
PROBE_B64=$(base64 -w0 <<'PY'
import os, sys, errno


def name(e):
    try:
        return errno.errorcode[e]
    except Exception:
        return "E%d" % e


d = sys.argv[1]
rc, err = 0, "-"
try:
    fd = os.open(d + "/f", os.O_WRONLY)
    os.write(fd, b"after-resume\n")
    os.fsync(fd)
    os.close(fd)
except OSError as e:
    rc, err = 1, name(e.errno)
print("AFTER_WRITE rc=%d err=%s" % (rc, err))
print("AFTER_END")
PY
)
measure "$B" 60 "$OUT/B_probe.txt" '^AFTER_END$' "a write from B after its heartbeat resumed" \
    "echo $PROBE_B64 | base64 -d > /run/authres_probe.py; python3 /run/authres_probe.py $MNT/authres_$LABEL"
AW=$(grep -a '^AFTER_WRITE' "$OUT/B_probe.txt" | head -1)
echo "STAGE the write after the resume: $AW"
ck "a write is STILL refused after the heartbeat is working again" \
    "$(echo "$AW" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 1

# and the node itself must still be a working machine
measure "$B" 40 "$OUT/B_live.txt" '^LIVE_END$' "B is still usable" \
    "printf 'alive\n' > /run/authres_$LABEL && cat /run/authres_$LABEL; echo LIVE_END"
ck "B is still serving" "$(cnt "$OUT/B_live.txt" '^alive$')" 1

echo "    $(grep -a 'P290-AUTH-CLOSED' "$OUT/B_after.txt" | head -1 | sed 's/.*mxfs: //' | cut -c1-190)"
grep -a 'P290-AUTH-REFUSED\|P290-AUTH-HB-STOP' "$OUT/B_after.txt" | sed 's/.*mxfs: /    /' | cut -c1-160 | head -3
# RESTORE THE NODE.  This lap leaves B with a closed lease, a mount that
# refuses every write, and — on the staleanchor arm — a parked withdrawal pump,
# so nothing ever drives the shutdown that would let an unmount finish quickly.
# That combination is an artifact of the injections and not a product state:
# with the pump live, a closed-authority mount unmounts in 1 s and its module
# removes in 0 s (tests/auth_lease_unmount.sh).  But leaving it behind costs the
# NEXT lap its entire prep budget on "test2 did not release mxfs" before prep
# power-cycles the node anyway, so do it here where it is cheap and expected.
$VIRSH destroy "$B" > /dev/null 2>&1
$VIRSH start "$B" > /dev/null 2>&1
[ "$ARM" != resvgone ] || $VIRSH start "$A" > /dev/null 2>&1
echo "STAGE restarted the fleet; it needs prep_cluster before the next lap"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) arm=$ARM label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
