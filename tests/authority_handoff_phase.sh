#!/bin/bash
# tests/authority_handoff_phase.sh — the REMOTE BOUNDARY of the authority lease:
# the earliest wall-clock instant a PEER can actually complete a handoff of this
# node's role, measured against this node's own deadline_ms.
# (ledger D-AUTHORITY-LEASE-RESURRECTION-CASES-ARE-UNVERIFIED, its remaining
# item 2; the local half of that item is done by reading and is not re-derived
# here.)
#
# WHY IT EXISTS.  The authority lease is ONE-SIDED.  It bounds how long this
# node keeps writing when it hears nothing — mxfs_authority_ok closes on
# now > deadline_ms from whatever context noticed (dlm/disklock.c:2494-2512) —
# and it does NOT bound how soon a peer may act.  Two of the four revocation
# paths are not lease-derived at all and cannot be: SLOT_TAKEOVER
# (disklock.c:2977-2992) and PR_CONFLICT_FENCED (dlm/v5_mount.c:11558-11577)
# both close authority at the instant THIS node NOTICES an action a peer has
# ALREADY taken.  So the whole safety argument rests on the peer side, and the
# claim that has never been measured is: the peer's earliest handoff action is
# never before this node's deadline_ms.
#
# THE ARITHMETIC THE CLAIM RESTS ON, and why it is not self-evident.  A beat
# that lands at T sets deadline = T + MXFS_DISKLOCK_AUTH_LEASE_MS
# (dlm/disklock.h:181, 30000).  The peer declares death after
# MXFS_DISKLOCK_HB_INTERVAL_MS * dead_threshold (disklock.h:145, 2000; 62 s on
# this rig), counted from ITS OWN last observation of this node's record — and
# that observation can be as much as one heartbeat interval BEFORE T, because
# the peer samples on its own cadence and the two are unsynchronised.  So the
# nominal margin is 62000 - 2000 - 30000 = 30 s, and it SHRINKS with the
# relative phase of the two clocks.  Assuming the margin rather than measuring
# it is exactly what this record refuses.
#
# WHAT IS SWEPT, AND WHAT THE SWEEP CAN HONESTLY CLAIM.  The peer's sampling
# phase is not controllable from here — there is no knob for it and no probe
# that prints it.  What IS controllable is the instant this node's heartbeat
# stops, so each lap arms the pause at a different offset inside one heartbeat
# interval (PHASE_MS) and the relative phase is SAMPLED rather than set.  N laps
# spanning the interval is the coverage claim, and the answer is the MINIMUM
# margin across them, not the margin of any one lap.  A single lap proves
# nothing about the worst case and this harness says so in its own output.
#
# WHAT THE FIRST SWEEP ACTUALLY MEASURED, AND WHY THERE ARE NOW TWO ARMS.
# The s130 sweep (four laps, margins 0.9-1.6 s against a 30 s prediction)
# never reached the peer's dead window at all.  The writer below keeps the
# victim's gate called, so its authority closes at the deadline; the closure
# WITHDRAWS the mount (P290-AUTH-WITHDRAW), the withdrawal stamps the slot
# WITHDRAWN, and the peer's monitor fires on that stamp at its next 2 s pass
# (P163-WITHDRAW-SEEN, then "no longer responding" at 14 checks — the
# equal-sample count at that instant, not a threshold).  On that path the
# peer's action is CAUSED by the victim's own closure, so the margin is one
# monitor pass and positive by construction; it says nothing about the silent
# window.  So:
#   - the default arm (a writer on the victim) measures the COOPERATIVE path
#     and labels its margin path=withdrawn;
#   - SILENT=1 runs no writer, lets the victim's log settle, HOLDS THE
#     VICTIM'S WITHDRAWAL PUMP (dbg_auth_withdraw_pause_ms: the lease still
#     closes on the PR worker's tick, but nothing stamps WITHDRAWN — s146a and
#     s146b showed that with no writer at all the tick closes the lease and
#     the withdrawal still hands the peer its stamp), takes the deadline from
#     the module's P-HB-INJECT-PAUSE line (deadline_ms since 0.89.66), and
#     requires the peer's death to have come from silence (equal samples
#     reaching the threshold) — a lap where the peer fired on a stamp instead
#     is VACUOUS for this arm, never a pass.
# The peer's death line carries, since 0.89.66, the victim's last stamp, the
# peer's own pass that last saw it change, and the declaration instant, so the
# dead window's actual start and length are printed rather than derived from
# the constants.
#
# THE TWO CLOCKS ARE RECONCILED, NOT ASSUMED COMPARABLE.  Every value the
# module prints in a *_ms field comes from mxfs_pal_time_ms(), which is
# ktime_get_boottime_ns()/1e6 (pal/linux/kern.c:2970) — BOOT-RELATIVE, so two
# nodes' numbers are not comparable at all until each is anchored.  Each node is
# anchored by reading /proc/uptime (the same ktime_get_boottime) and the wall
# clock in ONE command, giving wall_at_boot = wall - uptime; a boottime ms value
# then converts to wall as wall_at_boot + ms/1000.  The anchor is checked rather
# than trusted: the victim's own P290-AUTH-CLOSED line carries BOTH a now_ms
# field and a dmesg timestamp prefix, and the lap ABORTs if converting the two
# disagrees by more than ANCHOR_TOL_S — which is the case where the node
# suspended, the clock stepped, or dmesg timestamps are not what this harness
# thinks they are.  A margin computed across an unverified clock conversion is
# not a measurement.
#
# WHAT COUNTS AS "THE PEER COMPLETED A HANDOFF".  The earliest instant at which
# this node could lose exclusion, which is the earliest of the three lines that
# mark a fence having STARTED rather than finished — the same set
# tests/fence_partition_reconnect.sh discriminates on, and for the same reason:
# a certificate is the end of the pipeline and grading on it would credit the
# peer with acting minutes later than it did.
#     P-PR-FENCE preempt-and-aborted   the PREEMPT itself: exclusion is gone
#     P236-FENCE-INTENT                the durable intent (disklock.c:9010)
#     P309-DEATH-FENCE-QUEUED          the death fence entering the queue
#
# WHAT IS ASSERTED, per lap
#   - the pause was actually armed and the module said so (P-HB-INJECT-PAUSE),
#     because a knob whose write returned is not a knob in effect;
#   - the victim's authority CLOSED and the line carries a deadline_ms;
#   - the peer took a handoff action (otherwise the lap measured nothing and
#     says VACUOUS rather than passing on an absence);
#   - THE VERDICT: the peer's earliest handoff action is AFTER the victim's
#     deadline_ms, both in wall clock, with the margin printed;
#   - no BUG or Oops on either node.
# And across the sweep, tests/authority_handoff_phase_sweep.sh prints the
# minimum margin, which is the number the record is asking for.
#
# THE BUDGET (derived; a timeout is a failure and never a safety net):
#   prep 300 (measured 233) + anchors and identities 30 + the phase wait 2 +
#   the pause armed and confirmed 20 + the victim's lease expiring 30 (it is
#   MXFS_DISKLOCK_AUTH_LEASE_MS by construction) + the peer's dead window 62 +
#   the fence starting 30 + captures 60 + cleanup and the heartbeat resuming 40
#   = 574.  Caller bound 600 s, plus up to 150 s of boot when the domains start
#   powered off — caller bound 750 s.  SILENT=1 adds the log-settle wait
#   (SILENT_SETTLE_S, 70: two passes of the 30 s log worker cover an idle
#   log) — caller bound 700 s, 850 s with boot.
#
# Usage: tests/authority_handoff_phase.sh <label> [phase_ms]
# Env:   MXFS_NODE_LIST (default test1,test2 — the SECOND node is the one whose
#        heartbeat is paused), PHASE_MS (0), PAUSE_MS (150000 — it must outlast
#        the 62 s dead window and the fence, or the victim's beat resumes
#        mid-measurement and the lap measures a recovery instead of a handoff),
#        ANCHOR_TOL_S (3), SILENT (0; 1 = no writer, the silent-death arm),
#        SILENT_SETTLE_S (70).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
PHASE_MS=${2:-${PHASE_MS:-0}}
SILENT=${SILENT:-0}
SILENT_SETTLE_S=${SILENT_SETTLE_S:-70}
SILENT_HOLD_MS=${SILENT_HOLD_MS:-900000}    # the withdrawal hold outlasts the lap's bound
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
P=${MXFS_NODE_LIST%%,*}          # the PEER: the node that may complete a handoff
V=${MXFS_NODE_LIST##*,}          # the VICTIM: the node whose heartbeat is paused
[ "$P" = "$V" ] && { echo "ABORT: this lap needs two distinct nodes (MXFS_NODE_LIST=$MXFS_NODE_LIST)"; exit 2; }
PAUSE_MS=${PAUSE_MS:-150000}
ANCHOR_TOL_S=${ANCHOR_TOL_S:-3}
PARM=/sys/module/mxfs/parameters
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ahphase_${PHASE_MS}_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="AHPHASE-MARK-$LABEL-$PHASE_MS"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# The three lines that mark a fence having STARTED.  A certificate is the end
# of the pipeline; grading on it would credit the peer with acting later than
# it did, which is the direction that hides a boundary violation.
HANDOFF='P-PR-FENCE preempt-and-aborted\|P236-FENCE-INTENT\|P309-DEATH-FENCE-QUEUED'

if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== authority_handoff_phase label=$LABEL peer=$P victim=$V phase=${PHASE_MS}ms pause=${PAUSE_MS}ms silent=$SILENT sv=$SV $(date -u +%FT%TZ) ==="
echo "    the peer's sampling phase is SAMPLED by this lap, not set: one lap is one point, and the sweep's minimum is the answer"

waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
# the pause knob is one-shot and long; it is disarmed on EVERY exit path so a
# lap that aborts does not leave the next one's victim silently paused
DISARMED=0
disarm() {
    [ "$DISARMED" = 1 ] && return 0
    DISARMED=1
    # the writer is stopped by the pid it recorded when it started; no
    # process-table search is ever run against these hosts
    rs 30 "$V" "p=\$(cat /run/ahphase_writer.pid 2>/dev/null); [ -n \"\$p\" ] && kill \"\$p\" 2>/dev/null; \
                echo 0 > $PARM/dl_inject_hb_pause_ms 2>/dev/null; echo 0 > $PARM/dbg_auth_withdraw_pause_ms 2>/dev/null; echo 0 > $PARM/dbg_auth_withdraw_thread_pause_ms 2>/dev/null; \
                echo \$(cat $PARM/dl_inject_hb_pause_ms) \$(cat $PARM/dbg_auth_withdraw_pause_ms 2>/dev/null || echo -) \$(cat $PARM/dbg_auth_withdraw_thread_pause_ms 2>/dev/null || echo -)" > "$OUT/V_disarm.txt" 2>/dev/null
    echo "STAGE disarmed the heartbeat pause and both withdrawal holds on $V and stopped its writer (knobs now '$(tail -1 "$OUT/V_disarm.txt" 2>/dev/null || echo '?')') at +$(el)s"
}
trap disarm EXIT

waitboot "$P" "$V"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$P" "$V"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }

# ---- 1. THE CLOCK ANCHORS.  Every *_ms field the module prints is
#         ktime_get_boottime ms; /proc/uptime is the same clock, so reading it
#         beside the wall clock in ONE command gives each node's boot instant
#         in wall time.  Anything else in this lap that compares two nodes goes
#         through these two numbers.
anchor_of() {   # <node> <file> -> prints "<wall_at_boot_float>"
    measure "$1" 30 "$2" '^ANCHOR up=[0-9.]+ wall=[0-9.]+$' "the clock anchor on $1" \
        "printf 'ANCHOR up=%s wall=%s\n' \"\$(cut -d' ' -f1 /proc/uptime)\" \"\$(date +%s.%N)\""
    awk '/^ANCHOR /{for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="up")u=a[2];if(a[1]=="wall")w=a[2]}; printf "%.3f\n", w-u; exit}' "$2"
}
PBOOT=$(anchor_of "$P" "$OUT/P_anchor.txt")
VBOOT=$(anchor_of "$V" "$OUT/V_anchor.txt")
case "$PBOOT$VBOOT" in *[!0-9.-]*|'') echo "ABORT: a clock anchor did not parse (peer='$PBOOT' victim='$VBOOT')"; echo "RESULT: ABORT label=$LABEL stage=anchor evidence=$OUT"; exit 2 ;; esac
echo "STAGE clock anchors: $P booted at $PBOOT, $V booted at $VBOOT (wall seconds) at +$(el)s"
# boottime ms on a node -> wall seconds
wall_of() { awk -v b="$1" -v m="$2" 'BEGIN{printf "%.3f\n", b + m/1000.0}'; }
# the dmesg timestamp prefix of a line -> wall seconds on that node
dmesg_wall() { awk -v b="$2" -v l="$1" 'BEGIN{ if (match(l, /\[ *[0-9]+\.[0-9]+\]/)) { t=substr(l, RSTART, RLENGTH); gsub(/[^0-9.]/,"",t); printf "%.3f\n", b + t } }'; }

# ---- 2. the mark, in both rings, and the identities
for n in "$P" "$V"; do rs 20 "$n" "echo $MARK > /dev/kmsg" >/dev/null 2>&1; done
value_now_into vcl "$V" 30 "$OUT/V_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $V" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
VSLOT=${vcl##* }
echo "STAGE identities: victim $V holds heartbeat slot $VSLOT at +$(el)s"

# ---- 3. a caller for the gate.
# THE LEASE DOES NOT EXPIRE BY ITSELF — IT EXPIRES WHEN SOMEONE ASKS.
# mxfs_authority_ok closes the lease "from whatever context noticed"
# (dlm/disklock.c:2499-2512), which means an IDLE mount can sit past its own
# deadline with the state still reading ADMITTED until something calls the
# gate.  A lap that waited for P290-AUTH-CLOSED on an idle victim would then
# read the close at whatever later instant the peer's fence provoked one, and
# report the peer's own action as the victim's deadline.  So a writer runs on
# the victim for the whole measurement: its only job is to keep calling the
# gate, so the close lands at the deadline rather than at the first thing that
# happened to ask afterwards.  It writes into the SHARED mount, because that is
# the path the gate is on.
# The SILENT arm is the opposite: the victim must call the gate for NOTHING
# during the pause, or its closure withdraws the mount and the peer fires on
# the withdrawn stamp — the cooperative path, which the s130 sweep measured
# four times while reporting it as the silent boundary.  So no writer, and a
# settle wait long enough for the log worker to cover an idle log before the
# pause begins.  Whether the victim stayed silent is CHECKED below from the
# peer's own death line, never assumed from this wait.
if [ "$SILENT" = 1 ]; then
    rs 30 "$V" "sync; echo settled" > "$OUT/V_writer.txt" 2>/dev/null
    echo "STAGE SILENT arm: no writer on $V; letting its log settle for ${SILENT_SETTLE_S}s so nothing of its own calls the gate during the pause, at +$(el)s"
    sleep "$SILENT_SETTLE_S"
    # NO WRITER IS NOT ENOUGH (s146a, s146b: both VACUOUS path=withdrawn).  The
    # PR worker's periodic tick asks the gate every 250 ms precisely so that a
    # node issuing no I/O still closes on time; the closure withdraws the
    # mount, the withdrawal stamps the slot, and the peer fires on the stamp
    # 30.9 s after its last sight of a beat.  A LIVE node therefore never
    # presents the silent path — only a node that cannot run its own tick
    # does (crashed, wedged, cut off from the LUN).  That shape is produced by
    # holding the withdrawal pump alone (dbg_auth_withdraw_pause_ms, 0.89.66):
    # the lease still closes on the tick, nothing stamps WITHDRAWN, and the
    # peer has to wait out its whole dead window.  Held past the lap's bound.
    # the mark goes in BEFORE the knob: the module confirms the hold on its
    # next 250 ms tick, and a mark written after the knob misses it (s147a
    # ABORTed exactly so).  The mark's name does not contain $MARK, so the
    # main window's guard cannot mistake it for the lap's own mark.
    HOLDMARK="AHPHASE-HOLD-$LABEL-$PHASE_MS"
    rs 20 "$V" "echo $HOLDMARK > /dev/kmsg" >/dev/null 2>&1
    # 0.89.67 gave the withdrawal a SECOND consumer, a thread that ignores
    # the pump's knob by design; on such a module the thread stamped 0.3 s
    # after the closure and the arm read path=withdrawn again (s150b, s150c
    # on 0.89.69).  0.89.69 gives the thread its own knob; a module that
    # carries it has both consumers held here, and one that carries the
    # thread but not its knob cannot produce the silent shape at all.
    THREAD_KNOB=0
    if [ "$(strings -a mxfs.ko | grep -c 'dbg_auth_withdraw_thread_pause_ms')" != 0 ]; then
        THREAD_KNOB=1
    elif [ "$(strings -a mxfs.ko | grep -c 'via=withdraw-thread')" != 0 ]; then
        echo "ABORT: this module carries the withdraw thread (via=withdraw-thread) but not dbg_auth_withdraw_thread_pause_ms, so the closure would be stamped by the thread whatever the pump's hold — the silent shape is not producible on it"
        echo "RESULT: ABORT label=$LABEL stage=withdraw-hold evidence=$OUT"; exit 2
    fi
    # The arming command is assembled here, not inside the ssh string: an
    # optional clause substituted into the middle of a `;`-separated command
    # produced `;;` when it was present (s151c/s151d ABORTed on bash's
    # "syntax error near unexpected token `;;'") and `; ;` when it was not.
    ARM_CMD="echo $SILENT_HOLD_MS > $PARM/dbg_auth_withdraw_pause_ms"
    [ $THREAD_KNOB = 1 ] && ARM_CMD="$ARM_CMD; echo $SILENT_HOLD_MS > $PARM/dbg_auth_withdraw_thread_pause_ms"
    value_now_into wh "$V" 20 "$OUT/V_withdraw_hold.txt" '^[0-9]+( [0-9]+)?$' "the withdrawal holds after arming on $V" \
        "$ARM_CMD; echo \$(cat $PARM/dbg_auth_withdraw_pause_ms) \$(cat $PARM/dbg_auth_withdraw_thread_pause_ms 2>/dev/null)"
    wait_for_into held "$V" 20 "$HOLDMARK" 'P-DBG-AUTH-WITHDRAW-PAUSE node'
    if [ "$held" = timeout ]; then
        echo "ABORT: dbg_auth_withdraw_pause_ms reads back '$wh' on $V but the module never logged P-DBG-AUTH-WITHDRAW-PAUSE within 20 s (module older than 0.89.66?), so the withdrawal is NOT known to be held and the peer would fire on the victim's own stamp again"
        echo "RESULT: ABORT label=$LABEL stage=withdraw-hold evidence=$OUT"; exit 2
    fi
    if [ $THREAD_KNOB = 1 ]; then
        wait_for_into theld "$V" 20 "$HOLDMARK" 'P-DBG-AUTH-WITHDRAW-THREAD-PAUSE node'
        if [ "$theld" = timeout ]; then
            echo "ABORT: dbg_auth_withdraw_thread_pause_ms was armed on $V but the withdraw thread never logged P-DBG-AUTH-WITHDRAW-THREAD-PAUSE within 20 s, so the thread is NOT known to be held"
            echo "RESULT: ABORT label=$LABEL stage=withdraw-hold evidence=$OUT"; exit 2
        fi
    fi
    echo "STAGE the withdrawal pump on $V is held (${SILENT_HOLD_MS}ms, confirmed after ${held}s)$([ $THREAD_KNOB = 1 ] && echo " and so is its withdraw thread (confirmed after ${theld}s)"); its lease will still close on the tick but nothing will stamp WITHDRAWN, at +$(el)s"
else
    rs 20 "$V" "mkdir -p $MNT/ahphase_$LABEL; \
        nohup sh -c 'while :; do date +%s.%N >> $MNT/ahphase_$LABEL/tick 2>/dev/null; sync -f $MNT/ahphase_$LABEL/tick 2>/dev/null; sleep 0.5; done' >/dev/null 2>&1 & \
        echo \$! > /run/ahphase_writer.pid; sleep 1; cat /run/ahphase_writer.pid" > "$OUT/V_writer.txt" 2>/dev/null
    echo "STAGE a 2 Hz writer is running on $V so the authority gate is called continuously (pid $(tail -1 "$OUT/V_writer.txt" 2>/dev/null || echo '?')) at +$(el)s"
fi

# ---- 4. arm the pause at this lap's phase offset.
# THE OFFSET IS SPENT BEFORE THE WRITE, not after: the thing being varied is
# the instant the heartbeat stops relative to the peer's unseen sampler, and
# sleeping after arming would vary nothing.
[ "$PHASE_MS" -gt 0 ] && awk -v m="$PHASE_MS" 'BEGIN{system("sleep " m/1000.0)}'
T_ARM=$(date +%s.%N)
rs 20 "$V" "echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms" >/dev/null 2>&1
# A ONE-SHOT INJECTION KNOB IS NOT IN EFFECT WHEN THE WRITE RETURNS.  A beat
# already in flight can satisfy a measurement taken immediately; the module's
# own line is the only thing that says the pause began.  (Measured s103.)
wait_for_into armed "$V" 20 "$MARK" "P-HB-INJECT-PAUSE"
if [ "$armed" = timeout ]; then
    echo "ABORT: the heartbeat pause was written to $PARM/dl_inject_hb_pause_ms on $V but the module never logged P-HB-INJECT-PAUSE, so the heartbeat was never actually paused and nothing about a handoff boundary was measured"
    echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2
fi
echo "STAGE $V's heartbeat paused for ${PAUSE_MS}ms, confirmed by the module after ${armed}s, at +$(el)s (phase offset ${PHASE_MS}ms)"

# ---- 5. wait out the victim's lease and the peer's dead window, then read both
# The bounds are the sum of what must happen and nothing more.  The victim's
# close is MXFS_DISKLOCK_AUTH_LEASE_MS (30 s) by construction plus the writer's
# 0.5 s tick; 60 s.  The peer's dead window is 62 s counted from ITS last
# observation, which can be a heartbeat interval before the pause, and the
# fence start follows it; 130 s.  An overrun is a lap that measured no handoff,
# which is VACUOUS below and never a silent pass.  The SILENT arm expects no
# closure at all and does not wait for one.
closed=none
[ "$SILENT" = 1 ] || wait_for_into closed "$V" 60 "$MARK" "P290-AUTH-CLOSED"
wait_for_into handoff "$P" 130 "$MARK" "$HANDOFF"
echo "STAGE waits: the victim closed after ${closed}s, the peer acted after ${handoff}s (both from the arm) at +$(el)s"
window_into "$OUT/V_win.txt" "$V" 40 "$MARK"
window_into "$OUT/P_win.txt" "$P" 40 "$MARK"

# THE DEADLINE, from the pause line the module wrote when the heartbeat
# stopped: the last landed beat set it, and no beat lands during the pause, so
# it is the deadline whatever the victim does afterwards.  A module that does
# not print it (pre-0.89.66) cannot serve the SILENT arm at all.
PAUSE_LINE=$(grep -a 'P-HB-INJECT-PAUSE' "$OUT/V_win.txt" | grep -a 'ms=' | head -1)
PAUSE_DEADLINE_MS=$(echo "$PAUSE_LINE" | grep -ao 'deadline_ms=[0-9]*' | head -1 | cut -d= -f2)
PAUSE_LAST_OK_MS=$(echo "$PAUSE_LINE" | grep -ao 'last_ok_ms=[0-9]*' | head -1 | cut -d= -f2)
echo "STAGE the pause line on $V: deadline_ms=${PAUSE_DEADLINE_MS:-absent} last_ok_ms=${PAUSE_LAST_OK_MS:-absent}"

CLOSE_LINE=$(grep -a 'P290-AUTH-CLOSED' "$OUT/V_win.txt" | head -1)
V_REASON=$(echo "$CLOSE_LINE" | grep -ao 'reason=[A-Za-z_]*' | head -1 | cut -d= -f2)
if [ "$SILENT" = 1 ]; then
    case "${PAUSE_DEADLINE_MS:-}" in ''|*[!0-9]*|0)
        echo "ABORT: the SILENT arm needs the deadline from $V's P-HB-INJECT-PAUSE line and it carries none (module older than 0.89.66, or the authority was not admitted): [$(echo "$PAUSE_LINE" | cut -c1-200)]"
        echo "RESULT: ABORT label=$LABEL stage=pause-deadline evidence=$OUT"; exit 2 ;;
    esac
    V_DEADLINE_MS=$PAUSE_DEADLINE_MS
    # the anchor check needs a line with BOTH a module now_ms and a dmesg
    # prefix; the victim's P-HB-STAGE-style lines are not guaranteed, so the
    # pause line's own dmesg prefix is checked against last_ok_ms, which the
    # heartbeat set at the last landed beat, at most one interval plus the
    # phase offset earlier — well inside the tolerance.
    V_NOW_MS=$PAUSE_LAST_OK_MS
    ANCHOR_LINE=$PAUSE_LINE
    ANCHOR_WHAT="P-HB-INJECT-PAUSE (last_ok_ms against its dmesg prefix)"
    ANCHOR_SLACK_S=$(awk -v p="$PHASE_MS" 'BEGIN{printf "%.3f\n", 2.0 + p/1000.0}')
else
    if [ -z "$CLOSE_LINE" ]; then
        echo "VACUOUS: $V's authority never CLOSED inside the wait, so this lap has no deadline_ms to measure a peer against"
        echo "RESULT: VACUOUS label=$LABEL stage=no-close wall=$(el)s evidence=$OUT"; exit 3
    fi
    V_DEADLINE_MS=$(echo "$CLOSE_LINE" | grep -ao 'deadline_ms=[0-9]*' | head -1 | cut -d= -f2)
    V_NOW_MS=$(echo "$CLOSE_LINE" | grep -ao 'now_ms=[0-9]*' | head -1 | cut -d= -f2)
    case "${V_DEADLINE_MS:-}${V_NOW_MS:-}" in ''|*[!0-9]*) echo "ABORT: $V's P290-AUTH-CLOSED line carries no usable deadline_ms/now_ms: [$(echo "$CLOSE_LINE" | cut -c1-200)]"; echo "RESULT: ABORT label=$LABEL stage=close-fields evidence=$OUT"; exit 2 ;; esac
    ANCHOR_LINE=$CLOSE_LINE
    ANCHOR_WHAT="P290-AUTH-CLOSED (now_ms against its dmesg prefix)"
    ANCHOR_SLACK_S=0
    # the two sources of the deadline must agree when both exist
    if [ -n "${PAUSE_DEADLINE_MS:-}" ] && [ "$PAUSE_DEADLINE_MS" != 0 ]; then
        ck "the deadline the pause line printed is the deadline the closure enforced (pause $PAUSE_DEADLINE_MS, close $V_DEADLINE_MS)" "$PAUSE_DEADLINE_MS" "$V_DEADLINE_MS"
    fi
fi

# THE ANCHOR IS CHECKED, NOT TRUSTED.  The anchor line carries a module
# boottime ms field and a dmesg timestamp prefix.  Converting both through the
# anchor must land on the same wall instant (within the slack the field's own
# meaning allows); if they do not, the conversion every margin below depends
# on is wrong and no margin may be reported.
V_NOW_WALL=$(wall_of "$VBOOT" "$V_NOW_MS")
V_NOW_DMESG=$(dmesg_wall "$ANCHOR_LINE" "$VBOOT")
if [ -z "$V_NOW_DMESG" ]; then
    echo "ABORT: $V's anchor line has no dmesg timestamp prefix, so the clock conversion this lap's verdict rests on cannot be checked: [$(echo "$ANCHOR_LINE" | cut -c1-200)]"
    echo "RESULT: ABORT label=$LABEL stage=anchor-check evidence=$OUT"; exit 2
fi
SKEW=$(awk -v a="$V_NOW_WALL" -v b="$V_NOW_DMESG" 'BEGIN{d=a-b; if(d<0)d=-d; printf "%.3f\n", d}')
SKEW_TOL=$(awk -v t="$ANCHOR_TOL_S" -v s="$ANCHOR_SLACK_S" 'BEGIN{printf "%.3f\n", t+s}')
echo "STAGE $V deadline_ms=$V_DEADLINE_MS (closure reason=${V_REASON:-none}); anchor cross-check on $ANCHOR_WHAT: |module - dmesg| = ${SKEW}s (tolerance ${SKEW_TOL}s) at +$(el)s"
if awk -v s="$SKEW" -v t="$SKEW_TOL" 'BEGIN{exit !(s>t)}'; then
    echo "ABORT: the module's own ms field and the dmesg timestamp of the SAME line convert to wall instants ${SKEW}s apart, past the ${SKEW_TOL}s tolerance — the clock conversion is unsound and no cross-node margin may be computed from it"
    echo "RESULT: ABORT label=$LABEL stage=anchor-skew evidence=$OUT"; exit 2
fi

HAND_LINE=$(grep -a "$HANDOFF" "$OUT/P_win.txt" | head -1)
if [ -z "$HAND_LINE" ]; then
    echo "VACUOUS: $P took no handoff action inside the wait (none of P-PR-FENCE preempt-and-aborted, P236-FENCE-INTENT, P309-DEATH-FENCE-QUEUED), so this lap measured no boundary at all"
    [ -n "$CLOSE_LINE" ] && echo "  the victim's authority DID close (reason=$V_REASON), so the local half happened and only the remote half is missing"
    echo "RESULT: VACUOUS label=$LABEL stage=no-handoff wall=$(el)s evidence=$OUT"; exit 3
fi
P_HAND_WALL=$(dmesg_wall "$HAND_LINE" "$PBOOT")
if [ -z "$P_HAND_WALL" ]; then
    echo "ABORT: $P's earliest handoff line has no dmesg timestamp prefix, so it cannot be placed on a wall clock: [$(echo "$HAND_LINE" | cut -c1-200)]"
    echo "RESULT: ABORT label=$LABEL stage=handoff-ts evidence=$OUT"; exit 2
fi

# WHICH PATH THE PEER'S DEATH TOOK.  The monitor reaches its death line from
# silence (equal samples at the threshold) or by one of three jumps that need
# no silence at all: the victim's own WITHDRAWN stamp, a peer's certificate,
# an epoch change.  The first of those lines before the death line names the
# path; none of them means silence.  The death line's own fields say how long
# the window really was.
DEATH_LINE=$(grep -a 'no longer responding' "$OUT/P_win.txt" | head -1)
DEATH_LN=$(grep -an 'no longer responding' "$OUT/P_win.txt" | head -1 | cut -d: -f1)
PATH_LINE=$(head -n "${DEATH_LN:-0}" "$OUT/P_win.txt" 2>/dev/null | grep -a 'P163-WITHDRAW-SEEN\|P163-FENCED-SEEN\|has restarted' | tail -1)
case "$PATH_LINE" in
    *WITHDRAW-SEEN*)   DEATH_PATH=withdrawn ;;
    *FENCED-SEEN*)     DEATH_PATH=certificate ;;
    *"has restarted"*) DEATH_PATH=epoch ;;
    '')                DEATH_PATH=$([ -n "$DEATH_LINE" ] && echo silent || echo none) ;;
esac
D_CHECKS=$(echo "$DEATH_LINE" | grep -ao 'after [0-9]* checks' | grep -ao '[0-9]*')
D_THRESH=$(echo "$DEATH_LINE" | grep -ao 'threshold=[0-9]*' | cut -d= -f2)
D_STAMP=$(echo "$DEATH_LINE" | grep -ao 'last_stamp_ms=[0-9]*' | cut -d= -f2)
D_SEEN=$(echo "$DEATH_LINE" | grep -ao 'last_seen_ms=[0-9]*' | cut -d= -f2)
D_NOW=$(echo "$DEATH_LINE" | grep -ao 'now_ms=[0-9]*' | cut -d= -f2)
if [ -n "${D_SEEN:-}" ] && [ -n "${D_NOW:-}" ]; then
    WINDOW_S=$(awk -v a="$D_SEEN" -v b="$D_NOW" 'BEGIN{printf "%.3f\n", (b-a)/1000.0}')
    STAMP_TO_DEADLINE_S=$(awk -v a="$D_STAMP" -v b="$V_DEADLINE_MS" 'BEGIN{printf "%.3f\n", (b-a)/1000.0}')
    echo "STAGE the peer's death: path=$DEATH_PATH checks=${D_CHECKS:-?} threshold=${D_THRESH:-?}; its window ran ${WINDOW_S}s from its last sight of a change (last_seen_ms=$D_SEEN) to the declaration (now_ms=$D_NOW); the victim's stamp it last saw (last_stamp_ms=$D_STAMP, victim clock) sits ${STAMP_TO_DEADLINE_S}s before the victim's deadline"
else
    WINDOW_S=unknown
    echo "STAGE the peer's death: path=$DEATH_PATH checks=${D_CHECKS:-?} (the death line carries no window fields — module older than 0.89.66)"
fi
if [ "$SILENT" = 1 ] && [ "$DEATH_PATH" != silent ]; then
    echo "VACUOUS: the SILENT arm exists to measure the peer's dead window, and this lap's peer did not reach the death through silence — path=$DEATH_PATH: [$(echo "$PATH_LINE" | cut -c1-160)]"
    [ -n "$CLOSE_LINE" ] && echo "  the victim's authority closed (reason=$V_REASON) even with no writer, so something on the victim still called the gate during the pause: [$(echo "$CLOSE_LINE" | cut -c1-160)]"
    echo "RESULT: VACUOUS label=$LABEL stage=not-silent path=$DEATH_PATH wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 6. THE VERDICT
V_DEAD_WALL=$(wall_of "$VBOOT" "$V_DEADLINE_MS")
MARGIN=$(awk -v h="$P_HAND_WALL" -v d="$V_DEAD_WALL" 'BEGIN{printf "%.3f\n", h-d}')
echo "STAGE the boundary: $V's authority deadline at wall $V_DEAD_WALL; $P's earliest handoff action at wall $P_HAND_WALL; MARGIN=${MARGIN}s (path=$DEATH_PATH)"
echo "  the peer's line: $(echo "$HAND_LINE" | cut -c1-200)"
ck "the peer's earliest handoff action is AFTER the victim's own authority deadline (margin ${MARGIN}s, phase ${PHASE_MS}ms, path $DEATH_PATH)" \
   "$(awk -v m="$MARGIN" 'BEGIN{print (m>0)?"after":"BEFORE"}')" "after"
if [ "$SILENT" = 1 ]; then
    # the window the module declares (threshold samples at the heartbeat
    # interval) is what the record's arithmetic assumes; the measured window
    # may not fall short of it by more than one sample, or the threshold is
    # not what the derivation says it is on this transport
    ck "the peer's dead window ran at least (threshold-1) x 2 s (${WINDOW_S}s, threshold ${D_THRESH:-?})" \
       "$(awk -v w="$WINDOW_S" -v t="${D_THRESH:-0}" 'BEGIN{print (w >= (t-1)*2.0)?"yes":"no"}')" "yes"
fi
echo "MARGIN phase=${PHASE_MS} margin_s=${MARGIN} path=$DEATH_PATH window_s=$WINDOW_S reason=${V_REASON:-none} handoff=$(echo "$HAND_LINE" | grep -ao 'P-PR-FENCE preempt-and-aborted\|P236-FENCE-INTENT\|P309-DEATH-FENCE-QUEUED' | head -1)"

# ---- 7. nothing crashed on either node
ck "no BUG or Oops on the peer ($P)" "$(cnt "$OUT/P_win.txt" 'BUG:\|Oops')" 0
ck "no BUG or Oops on the victim ($V)" "$(cnt "$OUT/V_win.txt" 'BUG:\|Oops')" 0

disarm
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL phase=${PHASE_MS} margin_s=${MARGIN} fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL phase=${PHASE_MS} margin_s=${MARGIN} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
