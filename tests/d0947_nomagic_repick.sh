#!/bin/bash
# d0947_nomagic_repick.sh — does a candidate whose home reads clean with no
# inode magic still fail the create, or is it cooled down and re-picked?
#
# D-DIALLOC-VALIDATOR-TREATS-UNWRITTEN-INODE-CHUNK-AS-UNREADABLE-ALL-CREATES-EIO-0947.
# Measured on 0.75.117 (tests/evidence/sess572_create_eio): ONE candidate,
# ino 95168, whose home read clean with no dinode magic, was picked by every
# create in turn and answered 'P-DIALLOC-VALIDATE-EIO ... candidate home
# unreadable twice; failing the create cleanly' — 600 of 600 creates failed on
# a filesystem 7% full, because the reader used the same value for 'the read
# failed' and 'the read succeeded and no dinode is there'.  0.75.118-0.75.120
# separated the two: a read failure is still -EIO; a magic-less home kicks the
# owed publication writes, cools the candidate down (500-1000 ms) and the
# allocator re-picks, with nothing dirtied and nothing waited on under the AG
# grant.  That arm has never been measured, because a healthy carve leaves no
# magic-less home behind (the chunk is FUA-initialised and read back before
# its ICREATE record is logged), and the one rig instance was a foreign
# directory block (D-0948), not an un-destaged chunk.
#
# So the condition is injected at the validator, on a healthy two-node mount
# with the validator enabled (both nodes mounted), by two test-only knobs:
#   dbg_validate_nomagic_n=N     the next N candidates read as magic-less
#   dbg_validate_nomagic_ino=X   ONE number always reads as magic-less — the
#                                sess572 shape, a persistent bad home
# Three phases, each with its own kernel-log window:
#   1. countdown N=NINJ, FILES creates: every create must succeed, the arm
#      must fire exactly N times (P947-VALIDATE-NOMAGIC injected=1), no
#      P-DIALLOC-VALIDATE-EIO, no storm, no shutdown, the files present on
#      both nodes.
#   2. persistent: X = the number the allocator hands out next (learned by a
#      create, an unlink and a sync so X is the lowest published free
#      number), then FILES creates with X refused on every visit: every
#      create must succeed, X must never have been allocated (absent from
#      the directory), the arm fired at least once per cooldown expiry.
#   3. storm (observational): countdown N=NSTORM (> the allocator's 64
#      restarts) with a few creates — what the progress rule does when
#      EVERY candidate in the AG is magic-less.  Reported, and asserted only
#      not to shut the filesystem down; a failed create here is a finding
#      about the storm path, not about this record.
# All knobs are cleared at the end and on abort.  Exit 0 PASS, 1 FAIL, 2 ABORT.
#
# derived time budget: a create with one extra platter read is ~5 ms; 2 x
# FILES creates at 200 = ~2 s; the persistent phase adds one validator read
# per create; the storm phase is bounded by the allocator's restart cap
# (64 x a platter read) per create.  Whole run bounded at 240 s.
set -u
LABEL=${1:?label}
FILES=${2:-200}
NINJ=${3:-8}
NSTORM=${4:-200}
STORMFILES=${5:-20}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0947nomagic_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
clear_knobs() { rs 20 "$A" "echo 0 > $P/dbg_validate_nomagic_n; echo 0 > $P/dbg_validate_nomagic_ino" >/dev/null; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0947_nomagic_repick label=$LABEL files=$FILES ninj=$NINJ nstorm=$NSTORM sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) k=\$(test -w $P/dbg_validate_nomagic_n && test -w $P/dbg_validate_nomagic_ino && echo 1 || echo 0)" | tr -d '\n')
    echo "  INFO $n $st"
    [[ "$st" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV ($st)"; exit 2; }
    [[ "$st" == *"mnt=1"* ]]  || { echo "ABORT: $n not mounted ($st)"; exit 2; }
    [[ "$st" == *"k=1"* ]]    || { echo "ABORT: $n has no writable dbg_validate_nomagic knobs (build older than 0.84.16)"; exit 2; }
done
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0947probe.$$ 2>&1 && rmdir $MNT/.d0947probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
[[ "$wprobe" == *WRITABLE* ]] && [[ "$wprobe" != *NOTWRITABLE* ]] || { echo "ABORT: $A mounted but not writable: $wprobe"; exit 2; }
clear_knobs

# The window function: every count below reads THIS phase's kernel log,
# from its own marker, never the whole ring.
# counts_into <var> <marker>: the P947 counts from <marker> on A, across the
# boundary (window run to its end, mark present) and counted locally
counts_into() {
    local f=$OUT/win_${2//[^A-Za-z0-9._-]/_}.txt cn ci cr
    window_into "$f" "$A" 40 "$2"
    count_file_into cn "$f" 'P947-VALIDATE-NOMAGIC'; count_file_into ci "$f" 'P947-VALIDATE-NOMAGIC .*injected=1'; count_file_into cr "$f" 'P947-VALIDATE-NOMAGIC .*injected=0'
    # every field a verdict below reads, from the same window (s58h-H15: the
    # summary carried three fields, the verdicts read nine, and the harness
    # printed FAILs with got= — the library's ck now ABORTs on that)
    local veio pst dst dl sh co
    count_file_into veio "$f" 'P-DIALLOC-VALIDATE-EIO'; count_file_into pst "$f" 'P946-DIALLOC-PUBPEND-STORM'
    count_file_into dst "$f" 'P-DIALLOC-DISKLIVE-STORM'; count_file_into dl "$f" 'P-DIALLOC-DISKLIVE'
    count_file_into sh "$f" 'Shutting down filesystem\|P-WITHDRAW\|P163-WITHDRAW-STAMP'; count_file_into co "$f" 'Corruption of\|corruption detected\|P-DIALLOC-CORRUPT'
    # D-DIALLOC-REPICK-STORM (0.87.23): a create's transaction pays for ONE
    # inode-chunk carve; a second carve in one allocation (grows>1) and the
    # reservation overrun it produced are both verdict fields now.
    local ovr g2 cb
    count_file_into ovr "$f" 'P-TRANS-BLKRES-OVERRUN'; count_file_into g2 "$f" 'P-DIALLOC-GROW-RES .*grows=\([2-9]\|[1-9][0-9]\)'; count_file_into cb "$f" 'P-DIALLOC-CARVE-BOUND'
    printf -v "$1" '%s' "NOMAGIC=$cn NOMAGIC_INJ=$ci NOMAGIC_REAL=$cr VEIO=$veio PSTORM=$pst DSTORM=$dst DISKLIVE=$((dl - dst)) SHUT=$sh CORRUPT=$co OVERRUN=$ovr GROWS2=$g2 CARVEBOUND=$cb
$(grep -a 'P947-VALIDATE-NOMAGIC\|Shutting down\|Corruption of\|P-WITHDRAW' "$f" | head -4 | cut -c1-200)"
}
fld() { echo "$1" | grep -ao "$2=[0-9]*" | head -1 | cut -d= -f2; }

# ---- phase 1: countdown ----------------------------------------------------
MK1="D0947-P1-$LABEL-$$"
D1=$MNT/d0947_${LABEL}_p1
measure "$A" 120 "$OUT/p1.txt" '^sync_rc=' "phase 1 on $A" "echo '$MK1' > /dev/kmsg; mkdir -p $D1 || exit 1
    echo $NINJ > $P/dbg_validate_nomagic_n
    t0=\$(date +%s%N); cerr=0
    for i in \$(seq 1 $FILES); do : > $D1/f\$i 2>/dev/null || cerr=\$((cerr+1)); done
    t1=\$(date +%s%N)
    echo P1 cerr=\$cerr ms=\$(( (t1-t0)/1000000 )) knob_left=\$(cat $P/dbg_validate_nomagic_n) present=\$(ls $D1 | grep -c '^f') mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)
    sync -f $MNT; echo sync_rc=\$?"; p1=$(cat "$OUT/p1.txt")
echo "  INFO phase 1 (countdown $NINJ): $(echo "$p1" | tr '\n' ' ') at +$(el)s"
counts_into c1 "$MK1"; echo "$c1" | sed 's/^/       /'
echo "$p1" > "$OUT/phase1.txt"; echo "$c1" >> "$OUT/phase1.txt"
value_now_into p1b "$B" 60 "$OUT/rv_p1b_1.txt" '^present_on_B=' "p1b on $B" "echo 3 > /proc/sys/vm/drop_caches; echo present_on_B=\$(ls $D1 2>/dev/null | grep -c '^f')"
echo "  INFO phase 1: $p1b (cold on $B) at +$(el)s"
ck "phase 1: every create succeeded with $NINJ candidates injected magic-less (cerr)" "$(fld "$p1" cerr)" "0"
ck "phase 1: all $FILES files present on $A" "$(fld "$p1" present)" "$FILES"
ck "phase 1: all $FILES files present on $B, cold" "$(fld "$p1b" present_on_B)" "$FILES"
ck "phase 1: the countdown was consumed (knob_left)" "$(fld "$p1" knob_left)" "0"
ck "phase 1: the no-magic arm fired once per injected candidate (P947-VALIDATE-NOMAGIC injected=1)" "$(fld "$c1" NOMAGIC_INJ)" "$NINJ"
ck "phase 1: no create failed as unreadable (P-DIALLOC-VALIDATE-EIO)" "$(fld "$c1" VEIO)" "0"
ck "phase 1: no allocation storm" "$(( $(fld "$c1" PSTORM) + $(fld "$c1" DSTORM) ))" "0"
ck "phase 1: no live-platter quarantine (the injected candidates were re-picked, not condemned)" "$(fld "$c1" DISKLIVE)" "0"
ck "phase 1: no shutdown or withdraw on $A" "$(fld "$c1" SHUT)" "0"
ck "phase 1: no corruption verdict on $A" "$(fld "$c1" CORRUPT)" "0"
ck "phase 1: $A still mounted" "$(fld "$p1" mounted)" "1"

# ---- phase 2: one persistent magic-less number (the sess572 shape) --------
MK2="D0947-P2-$LABEL-$$"
D2=$MNT/d0947_${LABEL}_p2
# Learn X: create, record its inode number, unlink, publish the free.  The
# allocator hands out the lowest free number in the AG it picks, so X is
# what the next create in the same directory would get.
x=$(rs 60 "$A" "mkdir -p $D2 || exit 1; : > $D2/probe; x=\$(stat -c %i $D2/probe); rm -f $D2/probe; sync -f $MNT; echo X=\$x")
X=$(fld "$x" X)
[ -n "$X" ] && [ "$X" -gt 0 ] || { echo "ABORT: could not learn the next free inode number ($x)"; clear_knobs; exit 2; }
measure "$A" 120 "$OUT/p2.txt" '^sync_rc=' "phase 2 on $A" "echo '$MK2' > /dev/kmsg
    echo $X > $P/dbg_validate_nomagic_ino
    t0=\$(date +%s%N); cerr=0
    for i in \$(seq 1 $FILES); do : > $D2/f\$i 2>/dev/null || cerr=\$((cerr+1)); done
    t1=\$(date +%s%N)
    echo P2 X=$X cerr=\$cerr ms=\$(( (t1-t0)/1000000 )) present=\$(ls $D2 | grep -c '^f') x_allocated=\$(ls -i $D2 | awk -v x=$X '\$1==x' | wc -l) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)
    echo 0 > $P/dbg_validate_nomagic_ino
    sync -f $MNT; echo sync_rc=\$?"; p2=$(cat "$OUT/p2.txt")
echo "  INFO phase 2 (persistent ino $X): $(echo "$p2" | tr '\n' ' ') at +$(el)s"
counts_into c2 "$MK2"; echo "$c2" | sed 's/^/       /'
echo "$p2" > "$OUT/phase2.txt"; echo "$c2" >> "$OUT/phase2.txt"
value_now_into p2b "$B" 60 "$OUT/rv_p2b_2.txt" '^present_on_B=' "p2b on $B" "echo 3 > /proc/sys/vm/drop_caches; echo present_on_B=\$(ls $D2 2>/dev/null | grep -c '^f')"
echo "  INFO phase 2: $p2b (cold on $B) at +$(el)s"
ck "phase 2: every create succeeded with ino $X persistently magic-less (cerr)" "$(fld "$p2" cerr)" "0"
ck "phase 2: all $FILES files present on $A" "$(fld "$p2" present)" "$FILES"
ck "phase 2: all $FILES files present on $B, cold" "$(fld "$p2b" present_on_B)" "$FILES"
ck "phase 2: the magic-less number was never handed out (no file carries ino $X)" "$(fld "$p2" x_allocated)" "0"
ck "phase 2: the arm fired for the persistent number at least once" "$([ "$(fld "$c2" NOMAGIC_INJ)" -ge 1 ] && echo 1 || echo 0)" "1"
ck "phase 2: no create failed as unreadable (P-DIALLOC-VALIDATE-EIO)" "$(fld "$c2" VEIO)" "0"
ck "phase 2: no allocation storm" "$(( $(fld "$c2" PSTORM) + $(fld "$c2" DSTORM) ))" "0"
ck "phase 2: no shutdown or withdraw on $A" "$(fld "$c2" SHUT)" "0"
ck "phase 2: $A still mounted" "$(fld "$p2" mounted)" "1"
# After the knob is cleared X is an ordinary published free number again and
# the next create must be able to take it: the refusal left no mark.
value_now_into p2c "$A" 60 "$OUT/rv_p2c_3.txt" '^after_ino=' "p2c on $A" ": > $D2/after; echo after_ino=\$(stat -c %i $D2/after)"
echo "  INFO phase 2: with the knob cleared the next create got $p2c (X was $X) at +$(el)s"
ck "phase 2: once the knob is cleared the number is allocatable again (the refusal was transient, not a quarantine)" "$(fld "$p2c" after_ino)" "$X"

# ---- phase 3: the storm, observed ----------------------------------------
MK3="D0947-P3-$LABEL-$$"
D3=$MNT/d0947_${LABEL}_p3
measure "$A" 180 "$OUT/p3.txt" '^sync_rc=' "phase 3 on $A" "echo '$MK3' > /dev/kmsg; mkdir -p $D3 || exit 1
    echo $NSTORM > $P/dbg_validate_nomagic_n
    t0=\$(date +%s%N); cerr=0
    for i in \$(seq 1 $STORMFILES); do : > $D3/f\$i 2>/dev/null || cerr=\$((cerr+1)); done
    t1=\$(date +%s%N)
    echo P3 cerr=\$cerr ms=\$(( (t1-t0)/1000000 )) knob_left=\$(cat $P/dbg_validate_nomagic_n) present=\$(ls $D3 | grep -c '^f') mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)
    echo 0 > $P/dbg_validate_nomagic_n
    sync -f $MNT; echo sync_rc=\$?"; p3=$(cat "$OUT/p3.txt")
echo "  INFO phase 3 (storm: $NSTORM injected, $STORMFILES creates): $(echo "$p3" | tr '\n' ' ') at +$(el)s"
counts_into c3 "$MK3"; echo "$c3" | sed 's/^/       /'
echo "$p3" > "$OUT/phase3.txt"; echo "$c3" >> "$OUT/phase3.txt"
echo "  INFO phase 3 READ: with every candidate magic-less the allocator $( [ "$(fld "$p3" cerr)" = 0 ] && echo "still completed every create" || echo "FAILED $(fld "$p3" cerr) of $STORMFILES creates" ) — storms: pubpend=$(fld "$c3" PSTORM) disklive=$(fld "$c3" DSTORM), wall $(fld "$p3" ms) ms"
ck "phase 3: no shutdown or withdraw on $A under the storm" "$(fld "$c3" SHUT)" "0"
ck "phase 3: no corruption verdict on $A under the storm" "$(fld "$c3" CORRUPT)" "0"
ck "phase 3: $A still mounted" "$(fld "$p3" mounted)" "1"
ck "phase 3: the storm was reported as owed writes, never as a corruption verdict (no P-DIALLOC-DISKLIVE-STORM)" "$(fld "$c3" DSTORM)" "0"
ck "phase 3: the creates under the storm did not fail (the progress rule converged)" "$(fld "$p3" cerr)" "0"
ck "phase 3: no allocation carved a second inode chunk against a one-chunk reservation (P-DIALLOC-GROW-RES grows>1)" "$(fld "$c3" GROWS2)" "0"
ck "phase 3: no transaction consumed more blocks than it reserved (P-TRANS-BLKRES-OVERRUN)" "$(fld "$c3" OVERRUN)" "0"
echo "  INFO phase 3: second-carve refusals under the storm (P-DIALLOC-CARVE-BOUND) = $(fld "$c3" CARVEBOUND)"

clear_knobs
value_now_into kn "$A" 20 "$OUT/rv_kn_4.txt" '^n=' "kn on $A" "echo n=\$(cat $P/dbg_validate_nomagic_n) ino=\$(cat $P/dbg_validate_nomagic_ino)"
ck "both knobs cleared at the end ($kn)" "$kn" "n=0 ino=0"
rs 60 "$A" "rm -rf $D1 $D2 $D3; sync -f $MNT" >/dev/null
rs 40 "$A" "dmesg | awk '/$MK1/{f=1} f'" > "$OUT/dmesg_${A}.txt"
echo "=== d0947_nomagic_repick $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" = 0 ] && exit 0 || exit 1
