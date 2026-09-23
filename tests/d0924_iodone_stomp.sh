#!/bin/bash
# tests/d0924_iodone_stomp.sh
#
# D-STALE-AGMETA-BTREE-BUFFER-LEAKS-..., candidate route (a): the b_iodone slot.
#
# mxfs_ag_meta_track arms a one-shot token on an AG-metadata buffer and puts
# mxfs_dlm_ag_meta_iodone in bp->b_iodone to consume it at writeback.  The slot
# holds ONE function and is not chained, and every other writer assigns it
# unconditionally.  If one of them lands between the track and the writeback,
# the completion runs their callback, nothing consumes the token, and the
# buffer hold plus the AG's pending count leak with no probe firing at the
# time -- the first sign is the tripwire in mxfs_ag_meta_track a whole dirty
# epoch later, by which point the route is gone.
#
# Reading the tree says the writers are disjoint: mxfs_buf_is_ag_metadata
# matches AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/rmapbt/refcountbt b_ops, and
# the other writers tag inode and dquot buffers.  But a buffer can change what
# it IS between lives.  Free a btree block and let its blocks come back as an
# inode chunk and ONE xfs_buf meets both writers -- so this workload does
# exactly that, on purpose, rather than trusting the disjointness argument.
#
# WHAT THIS MEASURES, and why the denominator is half of it: the module
# exports agmeta_iodone_installs (every foreign write of the slot) beside
# agmeta_iodone_stomps (those that landed on a buffer whose AG-meta token was
# still armed).  A zero numerator means nothing without a non-zero
# denominator -- it reads identically to a probe that is never called.
#
# The other verdict is the tripwire itself: the WARN in mxfs_ag_meta_track
# finding a token already armed on a fresh dirty epoch.  It is WARN_ON_ONCE,
# so taint bit 9 (512) is the reliable per-boot detector and the log line is
# not.
#
# Usage: tests/d0924_iodone_stomp.sh <label> [ROUNDS=4] [FILES=2000]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default per rig)
set -u
LABEL=${1:?label}
ROUNDS=${2:-4}
FILES=${3:-2000}
cd "$(dirname "$0")/.." || exit 2
NODES=${MXFS_NODE_LIST:-test1,test2}
A=${NODES%%,*}
B=${NODES##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/d0924_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0924stomp_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
# knob_into <var> <node> <name>: a counter read across the boundary; a node
# that did not answer is an ABORT, never an empty value arithmetic reads as 0
knob() { rs 25 "$1" "cat /sys/module/mxfs/parameters/$2 2>/dev/null" | tr -d '\r\n'; }   # progress lines and the build guard only; never feeds a verdict
knob_into() { value_now_into "$1" "$2" 25 "$OUT/knob_$2_$3.txt" '^-?[0-9]+$' "the counter $3 on $2" "cat /sys/module/mxfs/parameters/$3"; }

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0924_iodone_stomp label=$LABEL A=$A B=$B rounds=$ROUNDS files=$FILES sv=$SV $(date -u +%FT%TZ) ==="

for n in "$A" "$B"; do
    sv=$(rs 25 "$n" "cat /sys/module/mxfs/srcversion" | tr -d '\r\n')
    value_now_into m "$n" 25 "$OUT/rv_m_1.txt" '^[0-9]+$' "m on $n" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
    echo "  INFO $n sv=$sv mounted=$m"
    [ "$sv" = "$SV" ] || { echo "FATAL: $n runs $sv, tree builds $SV — deploy first"; exit 2; }
    [ "$m" = 1 ] || { echo "FATAL: $n is not mounted"; exit 2; }
done

i0A=$(knob "$A" agmeta_iodone_installs); s0A=$(knob "$A" agmeta_iodone_stomps)
i0B=$(knob "$B" agmeta_iodone_installs); s0B=$(knob "$B" agmeta_iodone_stomps)
echo "  INFO baseline A installs=$i0A stomps=$s0A | B installs=$i0B stomps=$s0B"
case "$i0A" in ''|*[!0-9]*) echo "FATAL: $A does not export agmeta_iodone_installs — wrong build"; exit 2 ;; esac
case "$(knob "$A" agmeta_acquires)" in ''|*[!0-9]*) echo "FATAL: $A does not export the conservation counters — wrong build"; exit 2 ;; esac

# ---------------------------------------------------------------------------
# The workload.  Each round, in one directory so the allocator keeps returning
# to the same AG:
#   1. create FILES small files   -> inode chunk allocation: inobt/finobt
#      splits (AG metadata, tracked) AND inode cluster buffers (the foreign
#      writer, via xfs_trans_inode_alloc_buf).
#   2. fallocate + punch alternate blocks -> bnobt/cntbt grow and SPLIT.  The
#      record notes every previous lap aimed at the COLLAPSE side; the
#      tripwire's own stack is a split inside xfs_free_ag_extent.
#   3. delete the files -> inode chunks freed, btree blocks freed, and their
#      blocks become available for the NEXT round's inode chunks.  That
#      recycling is the whole point: it is how one buffer meets both writers.
# Budget, derived: 1024 punches measured at 2.2 s on this rig; FILES creates
# at ~1.5 ms each clustered; rm of FILES at ~1 ms each.  A round is therefore
# ~3 s + 2.2 s + 2 s ~= 8 s, and ROUNDS=4 is ~32 s.  Bound each round at 90 s
# so a round that goes 10x over is a failure rather than a longer wait.
# ---------------------------------------------------------------------------
rs 30 "$A" "mkdir -p $D" >/dev/null
r=1
while [ "$r" -le "$ROUNDS" ]; do
    measure "$A" 90 "$OUT/round_$r.txt" '^READ_RC=[0-9]+$' "round $r on $A" "s=\$(date +%s%N);
        i=0; while [ \$i -lt $FILES ]; do : > $D/f.\$i; i=\$((i+1)); done;
        sync -f $MNT;
        fallocate -l 8M $D/big || echo BIG_ERR;
        h=0; while [ \$h -lt 1024 ]; do fallocate -p -o \$(( h * 8192 )) -l 4096 $D/big 2>/dev/null || echo PUNCH_ERR h=\$h; h=\$((h+1)); done;
        sync -f $MNT;
        rm -f $D/big; i=0; while [ \$i -lt $FILES ]; do rm -f $D/f.\$i; i=\$((i+1)); done;
        sync -f $MNT;
        e=\$(date +%s%N); echo ROUND_OK wall_ms=\$(( (e - s) / 1000000 )); printf '\nREAD_RC=%s\n' \$?"; out=$(grep -av '^READ_RC=' "$OUT/round_$r.txt")
    echo "  INFO round $r $(echo "$out" | tr '\n' ' ')"
    case "$out" in *ROUND_OK*) ;; *) ck "round $r completed inside its 90 s bound" 0 1 ;; esac
    # A peer touch each round, so the AG actually changes hands and the
    # release/reacquire pipeline runs over the churned metadata.
    rs 60 "$B" "mkdir -p $D.b && : > $D.b/t.$r && sync -f $MNT && rm -f $D.b/t.$r" >/dev/null
    r=$((r+1))
done

rs 40 "$A" "sync -f $MNT; rm -rf $D" >/dev/null 2>&1
rs 40 "$B" "rm -rf $D.b" >/dev/null 2>&1

i1A=$(knob "$A" agmeta_iodone_installs); s1A=$(knob "$A" agmeta_iodone_stomps)
i1B=$(knob "$B" agmeta_iodone_installs); s1B=$(knob "$B" agmeta_iodone_stomps)
dIA=$(( i1A - i0A )); dSA=$(( s1A - s0A ))
dIB=$(( i1B - i0B )); dSB=$(( s1B - s0B ))

for n in "$A" "$B"; do
    rs 40 "$n" "dmesg | grep -E 'P-AGMETA-IODONE-STOMP|P-AGMETA-IODONE-MISSED|mxfs_ag_meta_track|P55-STUCKMETA|P-AGMETA-RELSE-OUTSTANDING' | tail -30" \
        > "$OUT/probes_$n.txt" 2>&1
done
tA=$(rs 25 "$A" "cat /proc/sys/kernel/tainted" | tr -d '\r\n')
tB=$(rs 25 "$B" "cat /proc/sys/kernel/tainted" | tr -d '\r\n')
wA=$(rs 25 "$A" "dmesg | grep -c 'mxfs_ag_meta_track'" | tr -d '\r\n')
wB=$(rs 25 "$B" "dmesg | grep -c 'mxfs_ag_meta_track'" | tr -d '\r\n')

echo "D0924-STOMP-MEASURE $LABEL A[installs=$dIA stomps=$dSA tripwire=$wA taint=$tA] B[installs=$dIB stomps=$dSB tripwire=$wB taint=$tB]"

# The denominator assertion comes FIRST: without it the stomp count is not a
# measurement of anything.
[ "$dIA" -gt 0 ]; ck "the probe was actually exercised on $A (foreign b_iodone writers ran)" "$?" "0"

# ---------------------------------------------------------------------------
# CONSERVATION.  The tripwire only fires when a NEW dirty epoch finds the
# previous epoch's token still armed, so it detects a strand on a buffer that
# happens to be logged again and is silent about one that strands and is never
# touched again -- which is the shape this leak actually has.  Count the
# obligation instead of waiting for that coincidence.
#
# Everything above ended with sync -f and the files deleted, so this is a
# quiescent point: every acquire should have been returned by exactly one of
# the two consumers.  The difference is the number of outstanding buffer holds
# and the sum of every AG's pending count.
# ---------------------------------------------------------------------------
for n in "$A" "$B"; do
    knob_into aq "$n" agmeta_acquires;          knob_into af "$n" agmeta_arm_failures
    knob_into ri "$n" agmeta_returns_iodone;    knob_into rr "$n" agmeta_returns_reclaim
    knob_into cm "$n" agmeta_consume_misses
    outstanding=$(( aq - ri - rr ))
    echo "  CONSERVATION $n acquires=$aq returns_iodone=$ri returns_reclaim=$rr outstanding=$outstanding arm_failures=$af consume_misses=$cm"
    # A zero acquire count would make the identity below vacuously true.
    [ "$aq" -gt 0 ]; ck "$n: AG-meta obligations were actually taken (denominator)" "$?" "0"
    ck "$n: every AG-meta obligation was returned at rest (acquires - returns)" "$outstanding" "0"
    ck "$n: no failed arm (a token still armed on a fresh dirty epoch)" "$af" "0"
done

# taint bit 9 (512) is the reliable per-boot tripwire detector; the WARN_ON_ONCE
# log line is not, because it prints once per boot however often it fires.
twA=$(( tA & 512 )); twB=$(( tB & 512 ))
ck "no AG-meta track tripwire on $A (taint bit 9)" "$twA" "0"
ck "no AG-meta track tripwire on $B (taint bit 9)" "$twB" "0"

for n in "$A" "$B"; do
    window_into "$OUT/rv_sp_1.txt" "$n" 25; sp=$(cat "$OUT/rv_sp_1.txt" | grep -acE 'BUG:|Oops|general protection|kernel NULL|Corruption of in-memory|Shutting down filesystem' | tr -d '\r\n')
    ck "kernel health $n" "$sp" "0"
    value_now_into m "$n" 25 "$OUT/rv_m_2.txt" '^[0-9]+$' "m on $n" "grep -c ' $MNT mxfs ' /proc/mounts || [ \$? = 1 ]"
    ck "$n still mounted" "$m" "1"
done

echo
echo "  The stomp count is the ROUTE question, and either answer is a result:"
echo "    stomps>0  -> route (a) is real and named; the dmesg line says which site."
echo "    stomps=0 with installs>0 -> route (a) is eliminated for this workload,"
echo "                                and the hunt moves to the next candidate."
echo "evidence=$OUT"
[ "$fails" = 0 ] && echo "RESULT: PASS label=$LABEL" || echo "RESULT: FAIL label=$LABEL fails=$fails"
exit "$fails"
