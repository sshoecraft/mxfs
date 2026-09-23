#!/bin/bash
# tests/stranded_grant_escape.sh — manufacture a STRANDED grant on the TCP
# transport and require the module's escape for that shape to release it.
# (ledger D-THE-ONLY-STRAND-ESCAPE-TCP-HAS-IS-A-U8-COUNTER-TESTED-AGAINST-280)
#
# WHAT A STRAND IS.  The DLM engine granted an inode lock to this node and
# linked the mirror entry; the XFS layer never consumed it (in-core mode still
# NL, state not ACQUIRING) and never released it.  The master believes this
# node holds the lock, this node believes it holds nothing, and every peer
# that wants the inode waits for a release nobody will make.
#
# TWO SHAPES, ONE ESCAPE.  s142a (0.89.63) found that the module discriminates
# the two shapes of the strand by i_dlm_acq_inflight — the slow path's own
# in-flight count, held for the acquire's whole lifetime including its
# internal retries — and s143b (0.89.64) measured what each shape gets:
#   ABANDONED (acq_inflight == 0): the acquirer is gone.  Nobody can consume
#     the grant, so the sess10 arm P15-TCP-ORPH-PROCEED proceeds to the
#     gen-ANCHORED unlock after tcp_orphan_force_ms (500 ms) of continuous
#     orphan shape.  s142a/s143a measured it: B freed in 885/901 ms, unlock
#     on the strand's own gen, both nodes agreeing on the bytes.
#   IN FLIGHT (acq_inflight > 0, state not ACQUIRING): an acquirer still
#     exists.  Every gate upstream of the release pipeline treats the count
#     as a live acquirer to protect — bast_notify PARKS the BAST
#     (P-ACQWIN-PARK) and the dwork's busy check re-arms without a release
#     sample — so nothing reaps the grant while the acquirer lives (s143b:
#     0 pipeline samples across a 20 s hold), and the instant the count
#     drops the strand IS the abandoned shape and the sess10 arm frees it
#     (s143b: 1.4 s after the acquirer's exit).  The same-gen 280-strike
#     counter (P15H-STRANDED-RELEASE), restored to the module in 0.89.63
#     after a uint8_t had made it unbuildable, is never reached in either
#     shape: the abandoned arm fires at about the 5th sample, and the
#     in-flight shape is parked before the sampler.  Hypothesis H1 (the
#     strikes cannot converge under the 1 s backoff cap) was DISPROVED by
#     that lap — not slow convergence, no samples at all.
#
# WHY AN INJECTOR.  The strand has no known producer ("no known producer, but
# real" — the sess15 netpartition wedge).  A lap cannot wait for one.  So the
# module carries a one-shot knob, dbg_strand_ino, that makes the next granted
# slow-path acquire of that inode drop its grant at the point where it would
# publish the mode; with dbg_strand_hold_ms > 0 the acquiring task keeps its
# in-flight count and sleeps for that long before it exits unconsumed (the
# in-flight shape); with 0 it exits at once (the abandoned shape).
# Everything after that is the real pipeline on a real BAST.
#
# THE ARMS.  STRAND_HOLD_MS selects the shape:
#   STRAND_HOLD_MS=0 (default)  — ABANDONED.  Requires P15-TCP-ORPH-PROCEED
#     for the inode, the anchored unlock (P6U-UNLOCK ... gen=<strand gen>),
#     B freed after the 500 ms persistence and inside 3 s, and NO
#     P15H-STRANDED-RELEASE (that escape is for the other shape).
#   STRAND_HOLD_MS=<ms>         — IN FLIGHT.  A's append is launched detached
#     on A and blocks for the hold; B's append is issued while it is held.
#     Requires, by LINE ORDER in A's ring windowed from this lap's injection:
#     no escape line before P-DBG-STRAND-INJECT-END (a live acquirer is
#     protected), the park by name (P-ACQWIN-PARK >= 1), NO
#     P15H-STRANDED-RELEASE, P15-TCP-ORPH-PROCEED AFTER the END line and
#     within 3 s of it (the abandoned arm's own ceiling: 500 ms persistence
#     plus re-arms), the anchored unlock on the strand's gen, and B freed
#     inside hold + 20 s.  The lap prints the sample count and the time
#     from the acquirer's exit to the release so both are measured.
#
# THE SCHEDULE.  A creates F (A holds EX).  B appends (BAST A -> A demotes to
# NL; B holds EX).  A arms the knob and appends: its slow-path acquire is
# granted (B demotes) and DROPPED — the strand stands.  B appends under a
# bound with the wall measured on the node.  Then both nodes read F back and
# must agree on its contents.
#
# THE NEGATIVE CONTROL is the same contention without the knob: A appends (A
# holds EX), B appends (BAST A -> ordinary demote).  B must complete inside the
# ordinary demote time, and neither escape may fire — releasing a live grant
# that a consumer is mid-way through taking is the double-EX the CAW gating
# exists to prevent, and an escape that reaped one would be worse than none.
#
# COUNTING.  Every escape is counted by its own line format with 'ino=<n> '
# (a trailing space, so 131 never matches 1310), never by a bare probe name:
# the injector's own line QUOTES the name P15H-STRANDED-RELEASE, which is how
# s142a's release count read 1 with no release in the capture.
#
# BOUND, derived: prep_cluster 300 (measured 48-137 s on this rig; given what
# the other laps here give it) + setup (create, two appends, ssh 20 s bounds,
# ~5 s actual) 60 + arm 20 (abandoned) or hold+20 (in flight) + the
# strand-blocked append (abandoned: 3 s x2 + ssh = 20; in flight: hold + 20)
# + reads 20 + control 40 + dmesg captures (five, 20 s each as measurements)
# 20 = 480 s abandoned, 500 + 2 x hold in flight (560 s at hold 20000).
#
# Usage: [STRAND_HOLD_MS=<ms>] tests/stranded_grant_escape.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
HOLD_MS=${STRAND_HOLD_MS:-0}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST#*,}; B=${B%%,*}
MNT=/mnt/shared
KNOB=/sys/module/mxfs/parameters/dbg_strand_ino
HKNOB=/sys/module/mxfs/parameters/dbg_strand_hold_ms
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_strand_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
if [ "$HOLD_MS" -gt 0 ]; then ARM=inflight; else ARM=abandoned; fi

if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL arm=$ARM stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== stranded_grant_escape label=$LABEL arm=$ARM hold_ms=$HOLD_MS A=$A B=$B sv=$SV $(date -u +%FT%TZ) ==="

# THE BUILD GATE COMES FIRST.  A probe that is not a string in mxfs.ko is a
# guaranteed silence; the escape this lap measures was exactly such a silence
# for weeks, and the injector is new in this version.
for p in P15H-STRANDED-RELEASE P15H-STRIKES P15-TCP-ORPH-PROCEED P-DBG-STRAND-INJECT P-DBG-STRAND-INJECT-END; do
    if ! strings -a mxfs.ko 2>/dev/null | grep -q "$p"; then
        echo "ABORT: $p is not a string in mxfs.ko — this lap cannot measure it"
        echo "RESULT: ABORT label=$LABEL arm=$ARM stage=build-gate evidence=$OUT"; exit 2
    fi
done
echo "  PASS the two escapes, the strike census and the injector's two lines are in the built module"

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ "$prc" = 0 ] || { echo "RESULT: ABORT label=$LABEL arm=$ARM stage=prep evidence=$OUT"; exit 2; }

rsx 20 "$A" "test -f $KNOB && test -f $HKNOB && echo KNOB_OK; echo $HOLD_MS > $HKNOB; echo hold=\$(cat $HKNOB); echo end=1" > "$OUT/knob.txt" 2>&1
capture_require "$OUT/knob.txt" '^KNOB_OK$' "the dbg_strand_ino and dbg_strand_hold_ms knobs on $A's running module"
ck "the hold knob on $A reads the arm's value" "$(grep -ao '^hold=[0-9]*' "$OUT/knob.txt" | cut -d= -f2)" "$HOLD_MS"

F=$MNT/strand_$LABEL

# 1. A creates F and holds its lock EX.
rsx 20 "$A" "echo seed > $F && sync && stat -c 'ino=%i' $F; echo end=1" > "$OUT/create.txt" 2>&1
capture_require "$OUT/create.txt" '^ino=[0-9]+$' "the file's inode number on $A"
INO=$(grep -ao '^ino=[0-9]*' "$OUT/create.txt" | head -1 | cut -d= -f2)
echo "STAGE $F is inode $INO, created on $A at +$(el)s"

# 2. B appends: the BAST demotes A to NL and B holds EX.
rsx 30 "$B" "echo b1 >> $F && sync && echo B1_OK; echo end=1" > "$OUT/b1.txt" 2>&1
capture_require "$OUT/b1.txt" '^B1_OK$' "B's first append"

# The escape census before the arm.  Each count is the escape's OWN format for
# THIS inode; the deltas below are the measurement.
census() {   # census <node> <file>: one line per counter, always an integer
    rsx 20 "$1" "for p in 'P15H-STRANDED-RELEASE ino=$INO ' 'P15-TCP-ORPH-PROCEED ino=$INO ' 'P135-ORPHAN-RELEASE ino=$INO ' 'P15-REL-ABORT ino=$INO ' 'P279-RELAB-BACKOFF ino=$INO ' 'P15H-STRIKES ino=$INO ' 'P-ACQWIN-PARK ino=$INO ' 'P-DBG-STRAND-INJECT-END ino=$INO '; do n=\$(dmesg | grep -aF \"\$p\" | wc -l); echo \"\${p%% ino=*}=\$n\"; done; echo end=1" > "$2" 2>&1
    capture_require "$2" '^end=1$' "the escape census on $1"
}
cnt() { grep -ao "^$1=[0-9]*" "$2" | head -1 | cut -d= -f2; }
census "$A" "$OUT/census_pre.txt"

# 3. Arm the knob on A and make A acquire: the grant is dropped and the strand
#    stands.  The knob is read back to show the one-shot was consumed by THIS
#    acquire and not left armed.  In the in-flight arm the append is launched
#    detached, because it blocks for the hold, and the injector's own line is
#    polled for under a bound so B is not issued before the strand exists.
if [ "$ARM" = abandoned ]; then
    rsx 40 "$A" "echo $INO > $KNOB && echo ARMED=\$(cat $KNOB); (echo a1 >> $F) 2>/dev/null; echo a1_rc=\$?; sleep 1; echo knob_now=\$(cat $KNOB); echo inj=\$(dmesg | grep -aF 'P-DBG-STRAND-INJECT ino=$INO ' | wc -l); dmesg | grep -aF 'P-DBG-STRAND-INJECT ino=$INO ' | tail -1 | cut -c1-220; echo end=1" > "$OUT/arm.txt" 2>&1
    capture_require "$OUT/arm.txt" '^a1_rc=[0-9]+$' "A's append under the armed knob"
    a1rc=$(grep -ao '^a1_rc=[0-9]*' "$OUT/arm.txt" | cut -d= -f2)
else
    rsx 20 "$A" "rm -f /run/strand_a1_rc; echo $INO > $KNOB && echo ARMED=\$(cat $KNOB); nohup setsid bash -c '(echo a1 >> $F) 2>/dev/null; echo a1_rc=\$? > /run/strand_a1_rc' > /dev/null 2>&1 & for i in \$(seq 1 100); do n=\$(dmesg | grep -aF 'P-DBG-STRAND-INJECT ino=$INO ' | wc -l); [ \"\$n\" -ge 1 ] && break; sleep 0.1; done; echo knob_now=\$(cat $KNOB); echo inj=\$n; dmesg | grep -aF 'P-DBG-STRAND-INJECT ino=$INO ' | tail -1 | cut -c1-220; echo end=1" > "$OUT/arm.txt" 2>&1
    a1rc=pending
fi
capture_require "$OUT/arm.txt" '^inj=[0-9]+$' "the injector count on $A"
inj=$(grep -ao '^inj=[0-9]*' "$OUT/arm.txt" | cut -d= -f2)
knobnow=$(grep -ao '^knob_now=[0-9]*' "$OUT/arm.txt" | cut -d= -f2)
GEN=$(grep -a 'P-DBG-STRAND-INJECT' "$OUT/arm.txt" | grep -ao 'gen=[0-9]*' | head -1 | cut -d= -f2)
grep -a 'P-DBG-STRAND-INJECT' "$OUT/arm.txt" | sed 's/^.*mxfs: /    /' | cut -c1-200
ckge "the injector fired on inode $INO (P-DBG-STRAND-INJECT)" "${inj:-0}" 1
ck "the one-shot knob was consumed by that acquire (reads 0)" "${knobnow:-x}" 0
if [ "${inj:-0}" -lt 1 ]; then
    echo "VACUOUS: the injector never fired, so no strand was produced and nothing below measures the escape (a1_rc=$a1rc knob_now=$knobnow)"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=arm evidence=$OUT"; exit 3
fi
[ "$ARM" = abandoned ] && ckge "A's own write failed rather than proceeding without the grant it dropped" "${a1rc:-0}" 1
echo "STAGE the strand stands on $A at +$(el)s: inode $INO granted to $A by the DLM on gen ${GEN:-?}, unconsumed in core ($ARM)"

# 4. B appends under a bound.  The wall is measured ON B, around the write
#    alone, so the ssh setup cost is not in it.  The bound is the arm's:
#    abandoned 20 s (3 s ceiling x2 + ssh); in flight hold + 20 s, because a
#    strand that outlives the held acquirer is freed by the abandoned arm at
#    the acquirer's exit and THAT is the outcome H1 predicts and this lap
#    must be able to see.
if [ "$ARM" = abandoned ]; then bbound=20; else bbound=$(( HOLD_MS / 1000 + 20 )); fi
rsx "$bbound" "$B" "t0=\$(date +%s%N); echo b2 >> $F; rc=\$?; t1=\$(date +%s%N); echo b2_rc=\$rc b2_ms=\$(( (t1 - t0) / 1000000 )); echo end=1" > "$OUT/b2.txt" 2>&1
capture_require "$OUT/b2.txt" '^b2_rc=[0-9]+ b2_ms=[0-9]+$' "B's append against the strand (bound ${bbound}s: a timeout is the strand never being freed)"
b2rc=$(grep -ao 'b2_rc=[0-9]*' "$OUT/b2.txt" | cut -d= -f2)
b2ms=$(grep -ao 'b2_ms=[0-9]*' "$OUT/b2.txt" | cut -d= -f2)
echo "STAGE B's append against the strand: rc=$b2rc wall=${b2ms}ms at +$(el)s"
ck "B's append completed (the strand was released, not waited out forever)" "${b2rc:-x}" 0

# 5. A's own account: WHICH escape fired for THIS inode, and when.  In the
#    in-flight arm the held acquirer must first exit so its END line is in
#    the ring and its count is dropped before the control runs.
if [ "$ARM" = inflight ]; then
    rsx $(( HOLD_MS / 1000 + 15 )) "$A" "for i in \$(seq 1 $(( HOLD_MS / 100 + 100 ))); do [ -f /run/strand_a1_rc ] && break; sleep 0.1; done; cat /run/strand_a1_rc 2>/dev/null; rm -f /run/strand_a1_rc; echo end=1" > "$OUT/a1_end.txt" 2>&1
    capture_require "$OUT/a1_end.txt" '^a1_rc=[0-9]+$' "the held acquirer's exit on $A"
    a1rc=$(grep -ao '^a1_rc=[0-9]*' "$OUT/a1_end.txt" | cut -d= -f2)
    ckge "A's own write failed rather than proceeding without the grant it dropped" "${a1rc:-0}" 1
fi
census "$A" "$OUT/census_post.txt"
# The window opens at THIS lap's injector line: the ring outlives a module
# reload, every lap's file lands on the same inode number after its mkfs, and
# grant gens repeat across laps, so ino+gen alone can name an earlier lap's
# lines.  Ordering verdicts below read this window, never the raw ring.
rsx 20 "$A" "dmesg | grep -aF 'ino=$INO ' | grep -a 'P15H-\|P15-TCP-ORPH-PROCEED\|P135-ORPHAN-RELEASE\|P6U-UNLOCK\|P-DBG-STRAND\|P279-RELAB\|P15-REL-ABORT\|P-ACQWIN-PARK' | awk '/P-DBG-STRAND-INJECT ino=/{buf=\"\"} {buf=buf \$0 \"\\n\"} END{printf \"%s\", buf}' | tail -60 | cut -c1-230; echo end=1" > "$OUT/a_escape.txt" 2>&1
capture_require "$OUT/a_escape.txt" '^end=1$' "the escape lines for inode $INO on $A"
ck "the window opens at this lap's injection (P-DBG-STRAND-INJECT is its first line)" "$(head -1 "$OUT/a_escape.txt" | grep -ac 'P-DBG-STRAND-INJECT ino=')" 1
d() { echo $(( $(cnt "$1" "$OUT/census_post.txt") - $(cnt "$1" "$OUT/census_pre.txt") )); }
d_p15h=$(d P15H-STRANDED-RELEASE); d_tcp=$(d P15-TCP-ORPH-PROCEED); d_p135=$(d P135-ORPHAN-RELEASE)
d_abort=$(d P15-REL-ABORT); d_backoff=$(d P279-RELAB-BACKOFF); d_strikes=$(d P15H-STRIKES); d_park=$(d P-ACQWIN-PARK)
echo "STAGE escapes for ino $INO on $A: P15H-STRANDED-RELEASE=$d_p15h P15-TCP-ORPH-PROCEED=$d_tcp P135-ORPHAN-RELEASE=$d_p135 P15-REL-ABORT=$d_abort P279-RELAB-BACKOFF=$d_backoff P15H-STRIKES=$d_strikes P-ACQWIN-PARK=$d_park"
grep -a 'P15H-\|P15-TCP-ORPH-PROCEED\|P279-RELAB\|P-DBG-STRAND-INJECT-END' "$OUT/a_escape.txt" | sed 's/^.*mxfs: /    /' | cut -c1-170
anchored=$(grep -aF "P6U-UNLOCK ino=$INO " "$OUT/a_escape.txt" | grep -ac "gen=${GEN:-none} ")
if [ "$ARM" = abandoned ]; then
    if [ "${b2ms:-0}" -ge 500 ] && [ "${b2ms:-0}" -le 3000 ]; then
        echo "  PASS B waited out the abandoned arm's 500 ms persistence and was freed inside 3 s (${b2ms} ms)"
    else
        echo "  FAIL B's wall ${b2ms} ms is outside [500, 3000]: under 500 ms nothing waited on a strand, over 3 s the abandoned arm did not free it"
        fails=$((fails+1))
    fi
    ckge "P15-TCP-ORPH-PROCEED fired on $A for the strand (the abandoned arm)" "$d_tcp" 1
    ck "P15H-STRANDED-RELEASE did NOT fire (it is the in-flight shape's escape, not this one's)" "$d_p15h" 0
    ckge "the unlock that freed it was anchored on the strand's own gen ${GEN:-?} (P6U-UNLOCK)" "$anchored" 1
else
    # THE DESIGN, by line order in the window.  While the acquirer lives the
    # BAST is parked for it and no escape may reap the grant; when it exits
    # the strand is abandoned and the sess10 arm frees it inside its own
    # ceiling.  Timestamps are the ring's own [seconds] on A, so the interval
    # is one node's clock and needs no anchoring.
    ts1() { sed -n 's/^\[ *\([0-9.]*\)\].*/\1/p' | head -1; }
    ck "the held acquirer's exit is in the window (P-DBG-STRAND-INJECT-END)" "$(grep -acF "P-DBG-STRAND-INJECT-END ino=$INO " "$OUT/a_escape.txt")" 1
    pre_end=$(awk -v e="P-DBG-STRAND-INJECT-END ino=$INO " 'index($0,e){exit} /P15-TCP-ORPH-PROCEED ino=|P15H-STRANDED-RELEASE ino=|P15H-STRAND-TIMEOUT ino=|P15H-PEER-STARVE-TIMEOUT ino=/{n++} END{print n+0}' "$OUT/a_escape.txt")
    ck "no escape reaped the grant while its acquirer was in flight (escape lines before the END line)" "$pre_end" 0
    ck "the strike escape did not fire (a live acquirer is parked, and after it exits the grant is abandoned, not struck)" "$d_p15h" 0
    ckge "the park that protects a live acquirer fired by name on $A (P-ACQWIN-PARK)" "$d_park" 1
    post_end=$(awk -v e="P-DBG-STRAND-INJECT-END ino=$INO " -v p="P15-TCP-ORPH-PROCEED ino=$INO " 'index($0,e){seen=1; next} seen && index($0,p){n++} END{print n+0}' "$OUT/a_escape.txt")
    ckge "the abandoned arm freed the strand once the acquirer had exited (P15-TCP-ORPH-PROCEED after the END line)" "$post_end" 1
    end_ts=$(grep -aF "P-DBG-STRAND-INJECT-END ino=$INO " "$OUT/a_escape.txt" | ts1)
    proceed_ts=$(awk -v e="P-DBG-STRAND-INJECT-END ino=$INO " -v p="P15-TCP-ORPH-PROCEED ino=$INO " 'index($0,e){seen=1; next} seen && index($0,p){print; exit}' "$OUT/a_escape.txt" | ts1)
    if [ -n "$end_ts" ] && [ -n "$proceed_ts" ]; then
        free_ms=$(awk -v a="$end_ts" -v b="$proceed_ts" 'BEGIN{printf "%d", (b - a) * 1000}')
        if [ "$free_ms" -ge 500 ] && [ "$free_ms" -le 3000 ]; then
            echo "  PASS the abandoned arm freed the strand ${free_ms} ms after the acquirer's exit (500 ms persistence, inside its 3 s ceiling)"
        else
            echo "  FAIL the abandoned arm's release came ${free_ms} ms after the acquirer's exit, outside [500, 3000]: under 500 ms it did not wait out its persistence, over 3 s the strand outlived the acquirer"
            fails=$((fails+1))
        fi
    else
        free_ms=none
        echo "  FAIL the exit-to-release interval could not be measured (END ts='${end_ts}' PROCEED ts='${proceed_ts}')"
        fails=$((fails+1))
    fi
    ckge "the unlock that freed it was anchored on the strand's own gen ${GEN:-?} (P6U-UNLOCK)" "$anchored" 1
    echo "NOTE: cadence — $d_abort pipeline samples aborted on the strand, $d_backoff at the 1 s backoff cap, $d_strikes strike-census lines, B's wall ${b2ms} ms against a ${HOLD_MS} ms hold, release ${free_ms} ms after the acquirer's exit"
fi

# 6. Both nodes read F back and agree: the seed, b1 and b2 in order.  A's a1
#    is recorded either way; it is not asserted, because whether the failed
#    open or the failed write dropped it is not this record's question.
rsx 20 "$A" "tr '\n' ',' < $F; echo; echo end=1" > "$OUT/read_a.txt" 2>&1
rsx 20 "$B" "tr '\n' ',' < $F; echo; echo end=1" > "$OUT/read_b.txt" 2>&1
capture_require "$OUT/read_a.txt" '^end=1$' "A's read-back"
capture_require "$OUT/read_b.txt" '^end=1$' "B's read-back"
ra=$(grep -a ',' "$OUT/read_a.txt" | head -1); rb=$(grep -a ',' "$OUT/read_b.txt" | head -1)
echo "STAGE read-back: A=[$ra] B=[$rb]"
ck "A reads seed, b1, b2 in order" "$(echo "$ra" | grep -ac '^seed,b1,\(a1,\)\?b2,')" 1
ck "B reads the same bytes A does" "$([ "$ra" = "$rb" ] && echo same || echo differ)" same

# 7. Negative control: the same contention, no knob.  A appends (A holds EX);
#    B appends (BAST A -> ordinary demote).  No strand, no escape.
rsx 30 "$A" "echo 0 > $HKNOB; echo a2 >> $F && echo A2_OK; echo end=1" > "$OUT/a2.txt" 2>&1
capture_require "$OUT/a2.txt" '^A2_OK$' "A's control append"
rsx 60 "$B" "t0=\$(date +%s%N); echo b3 >> $F; rc=\$?; t1=\$(date +%s%N); echo b3_rc=\$rc b3_ms=\$(( (t1 - t0) / 1000000 )); echo end=1" > "$OUT/b3.txt" 2>&1
capture_require "$OUT/b3.txt" '^b3_rc=[0-9]+ b3_ms=[0-9]+$' "B's control append"
b3rc=$(grep -ao 'b3_rc=[0-9]*' "$OUT/b3.txt" | cut -d= -f2)
b3ms=$(grep -ao 'b3_ms=[0-9]*' "$OUT/b3.txt" | cut -d= -f2)
census "$A" "$OUT/census_ctl.txt"
echo "STAGE control: B's append against a LIVE grant rc=$b3rc wall=${b3ms}ms at +$(el)s"
ck "control: B's append completed" "${b3rc:-x}" 0
if [ "${b3ms:-99999}" -lt 3000 ]; then
    echo "  PASS control: an ordinary demote freed B in ${b3ms} ms (< 3000)"
else
    echo "  FAIL control: B waited ${b3ms} ms behind a grant A was actively holding — that is not a demote"
    fails=$((fails+1))
fi
ck "control: the strike escape did NOT reap the live grant (P15H-STRANDED-RELEASE unchanged)" "$(( $(cnt P15H-STRANDED-RELEASE "$OUT/census_ctl.txt") - $(cnt P15H-STRANDED-RELEASE "$OUT/census_post.txt") ))" 0
ck "control: the abandoned arm did NOT reap the live grant (P15-TCP-ORPH-PROCEED unchanged)" "$(( $(cnt P15-TCP-ORPH-PROCEED "$OUT/census_ctl.txt") - $(cnt P15-TCP-ORPH-PROCEED "$OUT/census_post.txt") ))" 0

# 8. Nothing crashed or shut down on either node.
for n in "$A" "$B"; do
    rsx 20 "$n" "echo bad=\$(dmesg | grep -ac 'BUG:\|Oops\|Kernel panic'); echo sd=\$(dmesg | grep -ac 'shutting down filesystem\|Filesystem has been shut down'); echo end=1" > "$OUT/bad_$n.txt" 2>&1
    capture_require "$OUT/bad_$n.txt" '^end=1$' "the crash scan on $n"
    ck "$n logged no BUG, Oops or panic" "$(grep -ao '^bad=[0-9]*' "$OUT/bad_$n.txt" | cut -d= -f2)" 0
    ck "$n did not shut the filesystem down" "$(grep -ao '^sd=[0-9]*' "$OUT/bad_$n.txt" | cut -d= -f2)" 0
done

echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM ino=$INO gen=${GEN:-?} strand_ms=$b2ms control_ms=$b3ms p15h=$d_p15h tcp_orph=$d_tcp samples=$d_abort fails=0 wall=$(el)s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL arm=$ARM ino=$INO gen=${GEN:-?} strand_ms=$b2ms control_ms=$b3ms p15h=$d_p15h tcp_orph=$d_tcp samples=$d_abort fails=$fails wall=$(el)s evidence=$OUT"
fi
exit $(( fails > 0 ))
