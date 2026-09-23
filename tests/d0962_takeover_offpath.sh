#!/bin/bash
# d0962_takeover_offpath.sh — is the dead peer's bulk page takeover ON or OFF
# the recovery completion's critical path?
#
# THE DEFECT.  After a peer dies the survivor fences it, seals and replays its
# journal slice, and then — still inside the recovery completion — transfers
# every authority-ledger page the dead incarnation owned, one page at a time.
# Measured at ~13 ms a page over 7984 pages: 103-107 s during which
# P163-RECOVERY-COMPLETE has not published, the survivor still holds a
# single-holder Write Exclusive reservation, and the rebooted victim cannot
# rejoin.  The fix moves the pass to the departure worker; the completion
# publishes as soon as the fence, replay and purges are done.
#
# WHY THIS HARNESS EXISTS RATHER THAN A PLAIN DEATH LAP.  The page count is
# workload residue, not a constant.  On a filesystem that has not built any,
# the pass is ~27 pages and finishes in 285 ms — at which point BOTH the fixed
# and unfixed builds publish promptly and the lap proves nothing while looking
# like a pass.  Measured 2026-09-17: cand=27 and cand=28 on two consecutive
# laps of the preserved rig filesystem, against the 7984 the defect was filed
# on.  So this harness BUILDS the residue first and refuses to report a verdict
# unless it got enough of it.
#
# WHAT IT MEASURES, on the survivor's own log:
#   t_replay  'foreign replay of slot N complete'
#   t_p163    P163-RECOVERY-COMPLETE
#   handoff_ms   from P-COMPLETE-RETIRE-TIMING   (NOT P-COMPLETE-TIMING, which
#                carries disklock_purge_ms and no handoff_ms — grepping the
#                wrong one of those two reports an empty field as a pass)
#   the pass itself: P-TAUTH-TAKEOVER cand= / pages_prepared=, and
#   P-DEPART-WORK-RECOVERY-TAKEOVER when it ran off the critical path.
#
# The assertion is (t_p163 - t_replay), which is what the victim waits out.
#
# derived budget: residue build <= 180 s (6000 creates measured 91-100 s; native
# XFS does this in ~2 s, the 2x ceiling does not apply to a clustered create
# storm taking a grant per inode, so this is the infra bound not a perf
# assertion) + the death lap's own documented caller bound 540 s + harvest ~20 s
# => caller bound 760 s.
#
# ARM=control runs the pass INLINE in the completion (the pre-fix shape, via
# dl_recovery_takeover_inline=1) and asserts the defect: the completion IS held
# behind the pass.  ARM=fixed (default) asserts it is not.  Both arms run on one
# build against residue built the same way, because the page count is workload
# residue and a control from a different tree is not a control.
#
# WHAT THIS HARNESS DOES AND DOES NOT ADJUDICATE.  The recovery barrier holds
# two serial per-page ledger passes.  This harness owns exactly one of them —
# the page TAKEOVER, which belongs on the departure worker.  The whole-ledger
# PURGE stays inside the barrier by design (the held-failure gate must see its
# result before the dead slot is republished) and its cost is tracked as its own
# defect.  So the fixed arm asserts handoff_ms, and it REPORTS the total
# replay->P163 gap without charging the remainder to this fix.
#
# Measured matched pair, one build, 6000 creates, 2026-09-17:
#   control  cand=2691  handoff_ms=42843  ledger_ms=12910  replay->P163 56.47s
#   fixed    cand=2703  handoff_ms=0      ledger_ms=12319  replay->P163 14.92s
#
# Usage: tests/d0962_takeover_offpath.sh <label> [creates]      (ARM=fixed|control)
set -u
LABEL=${1:?label}
# 6000, not 12000: 12000 creates measured 174 s against this harness's own
# 180 s residue budget and then missed it on the very next run, failing the arm
# in its FIXTURE.  6000 takes ~90-100 s and still yields ~2700 candidate pages
# against a 1000-page non-vacuity floor (measured: 6000 -> cand 2691 and 2703,
# 6059 held EX records).  The budget was not the thing to change.
CREATES=${2:-6000}
ARM=${ARM:-fixed}
case "$ARM" in fixed) INLINE=0 ;; control) INLINE=1 ;; *) echo "ARM must be fixed|control"; exit 2 ;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
W=${MXFS_NODE_LIST%%,*}          # survivor / writer
V=${MXFS_NODE_LIST##*,}          # victim, the one tcp_death_replay kills
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0962offpath_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
# how many candidate pages make the lap non-vacuous: at the measured ~10.6 ms a
# page the OLD path would have to be held long enough that a prompt completion
# is unambiguous.  1000 pages = ~10.6 s on the critical path.
MINCAND=${MINCAND:-1000}
echo "=== d0962_takeover_offpath label=$LABEL W=$W V=$V sv=$SV creates=$CREATES mincand=$MINCAND $(date -u +%FT%TZ) ==="

fails=0
for n in $W $V; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')
    echo "  INFO $n $st"
    case "$st" in "sv=$SV mnt=1"*) ;; *) echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)) ;; esac
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }

# ---- 1. build the residue ON THE VICTIM ---------------------------------
# The victim must hold the grants, so the pages carry ITS authority and its
# death is what leaves them behind.  A lone mount takes no grants at all, so
# the survivor stays mounted throughout (it is, by the precondition above).
echo "--- residue: $CREATES creates on $V ---"
t0=$(date +%s)
rs 180 "$V" "set -e; rm -rf $MNT/d0962 2>/dev/null; mkdir -p $MNT/d0962
    for d in \$(seq 0 39); do mkdir -p $MNT/d0962/\$d; done
    i=0
    while [ \$i -lt $CREATES ]; do
        printf '' > $MNT/d0962/\$((i % 40))/f\$i
        i=\$((i+1))
    done
    sync
    echo RESIDUE_FILES=\$(ls $MNT/d0962/*/ | grep -c '^f' || true)" > "$OUT/residue.txt" 2>&1
rrc=$?
rwall=$(( $(date +%s) - t0 ))
echo "  residue rc=$rrc wall=${rwall}s $(grep -a 'RESIDUE_FILES' "$OUT/residue.txt" | tail -1)"
if [ $rrc != 0 ]; then
    # A timed-out remote command leaves an EMPTY capture, so pointing at the
    # file says nothing: report the wall against the budget here, where the
    # numbers are, and say which of the two failures this was.
    if [ ! -s "$OUT/residue.txt" ]; then
        why="the capture is EMPTY, which is what a timeout leaves — ${rwall}s against the 180s budget for $CREATES creates"
    else
        why="see $OUT/residue.txt ($(wc -c < "$OUT/residue.txt") bytes)"
    fi
    echo "RESULT: FAIL label=$LABEL residue build rc=$rrc after ${rwall}s — $why."
    echo "  The residue build is FIXTURE, not measurement: if it does not fit the"
    echo "  budget, lower CREATES until it does and check cand stays above MINCAND."
    echo "  Do NOT raise the 180s bound to make it fit."
    exit 2
fi

# The knob lives on the SURVIVOR: it is the node that runs the completion.
# Read it back — a module reload resets runtime knobs, and an arm that silently
# ran the other shape is worse than no arm.
knob=$(rs 25 "$W" "echo $INLINE > /sys/module/mxfs/parameters/dl_recovery_takeover_inline 2>/dev/null; cat /sys/module/mxfs/parameters/dl_recovery_takeover_inline 2>/dev/null")
echo "  ARM=$ARM inline knob on $W reads '$knob' (want $INLINE)"
[ "$knob" = "$INLINE" ] || { echo "RESULT: FAIL label=$LABEL the $ARM arm could not set dl_recovery_takeover_inline (got '$knob') — the lap would have measured the other shape"; exit 2; }

MK="D0962-$LABEL-LAP"
rs 25 "$W" "echo '$MK' > /dev/kmsg"

# ---- 2. the death lap ---------------------------------------------------
echo "--- death lap ---"
t0=$(date +%s)
TDR_FALSE_APPLY=2 tests/tcp_death_replay.sh "$LABEL-lap" > "$OUT/lap.txt" 2>&1
lrc=$?
echo "  lap rc=$lrc wall=$(( $(date +%s) - t0 ))s $(grep -a '^RESULT:' "$OUT/lap.txt" | tail -1)"

# ---- 3. harvest the survivor's timeline ---------------------------------
rs 90 "$W" "dmesg | sed -n '/$MK/,\$p'" > "$OUT/dmesg_$W.txt" 2>&1
lines=$(wc -l < "$OUT/dmesg_$W.txt")
echo "  survivor window lines=$lines"
[ "$lines" -gt 0 ] || { echo "RESULT: FAIL label=$LABEL EMPTY survivor capture — nothing was read, which is not the same as nothing happening"; exit 2; }

ts() { grep -a "$1" "$OUT/dmesg_$W.txt" | head -1 | sed -n 's/^\[ *\([0-9.]*\)\].*/\1/p'; }
t_replay=$(ts 'foreign replay of slot')
t_p163=$(ts 'P163-RECOVERY-COMPLETE')
t_pass=$(ts 'P-DEPART-WORK-RECOVERY-TAKEOVER')
# SCOPE THE PASS TO THE VICTIM.  The lap ends with a cold remount of the
# survivor, and the new incarnation then takes over its OWN predecessor's
# pages — a second, larger P-TAUTH-TAKEOVER line in the same window.  A bare
# `tail -1` reported THAT pass's cand and total_ms as if they were the
# recovery takeover's (measured: cand=2953 total_ms=29197 from the
# post-remount pass, while the recovery pass was cand=2703).  The victim's
# node id is on the completion's own line, so take it from there.
VN=$(grep -a 'P-COMPLETE-RETIRE-TIMING' "$OUT/dmesg_$W.txt" | tail -1 |
     grep -o 'node=[0-9]*' | head -1 | cut -d= -f2)
# The pass either ran to its summary, or was stopped between pages when this
# mount began leaving — both name the victim and carry the page counts.
tko=$(grep -a "P-TAUTH-TAKEOVER departed=${VN:-NOVICTIM}/\|P-TAUTH-TAKEOVER-INTERRUPTED departed=${VN:-NOVICTIM}/" \
      "$OUT/dmesg_$W.txt" | tail -1)
cand=$(echo "$tko" | grep -o 'cand=[0-9]*' | cut -d= -f2)
prep=$(echo "$tko" | grep -o 'pages_prepared=[0-9]*' | cut -d= -f2)
tot=$(echo "$tko" | grep -o 'total_ms=[0-9]*' | cut -d= -f2)
# handoff_ms lives on P-COMPLETE-RETIRE-TIMING; P-COMPLETE-TIMING has none
hoff=$(grep -a 'P-COMPLETE-RETIRE-TIMING' "$OUT/dmesg_$W.txt" | tail -1 | grep -o 'handoff_ms=[0-9]*' | cut -d= -f2)
offpath=$(grep -ac 'P-DEPART-WORK-RECOVERY-TAKEOVER' "$OUT/dmesg_$W.txt")

echo "D0962 label=$LABEL sv=$SV victim=${VN:-NONE} cand=${cand:-NONE} pages_prepared=${prep:-NONE} pass_total_ms=${tot:-NONE} handoff_ms=${hoff:-NONE} offpath_lines=$offpath"
echo "  t_replay=${t_replay:-NONE} t_p163=${t_p163:-NONE} t_pass_ran=${t_pass:-NONE}"

BAD=0; NOTE=""
bad() { BAD=$((BAD+1)); NOTE="$NOTE [$1]"; }
[ -n "${cand:-}" ] || bad "no P-TAUTH-TAKEOVER line on the survivor — the pass never ran"
[ -n "${t_replay:-}" ] || bad "no replay-complete line"
[ -n "${t_p163:-}" ] || bad "no P163-RECOVERY-COMPLETE"
# NON-VACUITY FIRST: without residue both builds pass this trivially.
if [ -n "${cand:-}" ] && [ "${cand:-0}" -lt "$MINCAND" ]; then
    bad "VACUOUS: cand=$cand < $MINCAND — too few pages for the pass to have been worth moving; raise the creates, do NOT lower MINCAND"
fi
gap=NONE
if [ -n "${t_replay:-}" ] && [ -n "${t_p163:-}" ]; then
    gap=$(awk -v a="$t_replay" -v b="$t_p163" 'BEGIN{printf "%.2f", b-a}')
    echo "  GAP replay->P163 = ${gap}s (this is what the returning victim waits out)"
fi
if [ "$ARM" = fixed ]; then
    # THE TAKEOVER IS THE ONLY THING THIS ARM OWNS.  The barrier holds two
    # serial per-page ledger passes, and only one of them was moved: the page
    # TAKEOVER is now on the departure worker, while the whole-ledger PURGE is
    # still inside the barrier and must be — the held-failure gate consumes its
    # result before the dead slot may be republished.  So the assertions below
    # are about handoff_ms and about the pass actually running somewhere else;
    # the leftover gap is reported and attributed, never charged to this fix.
    [ -n "${hoff:-}" ] || bad "no handoff_ms on P-COMPLETE-RETIRE-TIMING — the completion's own timing line is missing, so nothing here is measured"
    if [ -n "${hoff:-}" ] && [ "$hoff" -ge 1000 ]; then
        bad "the takeover is STILL on the critical path: handoff_ms=$hoff (deferring it is an enqueue and a return; the control arm measures tens of seconds here)"
    fi
    [ "$offpath" -gt 0 ] || bad "no P-DEPART-WORK-RECOVERY-TAKEOVER — the pass did not run on the departure worker (deferral skipped, or coalesced away by a dedupe)"
    # ...and it must have run over the VICTIM's pages, not merely have been
    # queued: a request that ran and found nothing proves nothing.
    [ -n "${cand:-}" ] || bad "no P-TAUTH-TAKEOVER/-INTERRUPTED line naming victim ${VN:-NONE} — the deferred pass cannot be shown to have examined its candidate set"
    if [ "$gap" != NONE ]; then
        over=$(awk -v g="$gap" 'BEGIN{print (g>5.0)?1:0}')
        if [ "$over" = 1 ]; then
            echo "  NOTE replay->P163 is ${gap}s, above the 5.0s this harness wants."
            echo "       With handoff_ms=${hoff:-?} the takeover is NOT what is holding it."
            echo "       The remainder is the in-barrier whole-ledger purge (ledger_ms on"
            echo "       P-COMPLETE-RETIRE-TIMING), which is its own open defect and is NOT"
            echo "       dispositioned by this arm.  Do not raise the 5.0s to make this go"
            echo "       away, and do not charge it to the takeover deferral."
        fi
    fi
else
    # the control must REPRODUCE the defect, or it is not a control and the
    # fixed arm's prompt completion says nothing about this filesystem.
    if [ "$gap" != NONE ]; then
        held=$(awk -v g="$gap" 'BEGIN{print (g>10.0)?1:0}')
        [ "$held" = 1 ] || bad "CONTROL DID NOT REPRODUCE: replay->P163 only ${gap}s — the inline pass was not long enough to hold the completion, so the fixed arm proves nothing here"
    fi
    [ "$offpath" = 0 ] || bad "control arm ran the pass on the worker ($offpath lines) — the inline knob did not take"
fi

if [ "$BAD" = 0 ]; then
    if [ "$ARM" = fixed ]; then
        echo "RESULT: PASS label=$LABEL arm=$ARM — the takeover is off the barrier: handoff_ms=${hoff:-NONE}, cand=$cand pages moved by the worker, replay->P163 ${gap}s; evidence=$OUT"
    else
        echo "RESULT: PASS label=$LABEL arm=$ARM — control reproduced: cand=$cand pages held the completion ${gap}s (handoff_ms=${hoff:-NONE}); evidence=$OUT"
    fi
else
    echo "RESULT: FAIL label=$LABEL arm=$ARM bad=$BAD$NOTE evidence=$OUT"
fi
[ "$BAD" = 0 ]
