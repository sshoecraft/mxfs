#!/bin/bash
# hot_writer_peer_reader_2node.sh — one node overwrites a 64 KiB file in
# place with a single write() per iteration, alternating two byte patterns,
# while the peer reads the whole file back in a tight loop.  Every read the
# peer completes must be ALL of one pattern: local XFS guarantees a buffered
# read never interleaves with a buffered write (IOLOCK shared vs exclusive),
# and the cluster inode lock (PR for the reader, EX for the writer) must
# give the peer the same guarantee.  A read that is part 'a' and part 'b',
# a read that is short, or a read of bytes the writer never wrote (zeros,
# an older incarnation) is a data-integrity defect.
#
# A: dd if=<pattern> of=f bs=64k count=1 conv=notrunc, pattern alternating
#    'a'/'b' each iteration; then creates $D/done.
# B: until $D/done exists (cap 5000 reads): cat f > local scratch (ONE read()
#    of a 64 KiB file), classify the bytes offline: all-a, all-b, short, torn.
#    The first torn/short read is kept as evidence.
#
# Pace (derived): every write is at worst one cross-node EX hand-off of the
# inode against the reader's PR; the hand-off path measured 82-94 ms per op
# after D-0917 (sess523), so 100 ms per write is the bound the design
# claims.  A_loop_wall_ms <= ITERS * 100.
#
# Measured s525h-j (0.75.44, 2/tcp QNAP): 23.9-28.2 ms per write, 292-318
# reads overlapping 300 writes, 0 torn, 0 short.  One cycle from the merged
# realns timeline (s525h): writer EX acquire -> BAST processed at +0.2 ms,
# release complete at +7.5 ms (P138 median 7.1 ms: sb 2.0 drain, sc 1.2,
# unlock on the wire sx 3.4 ms) -> reader PR acquire, read, release at
# +4.5 ms -> writer self-demote 3 ms -> dd spawn + next grant 6.5 ms.
# P7B inter-arrival min 17.6 / median 23.6 / p90 31.3 ms: continuous, no
# sleep cadence.
#
# the budget rule (derived): prep 55 s measured (2/tcp QNAP) + loop <= ITERS*0.1 s
# + capture 10 s; ITERS=300 -> ~100 s; chain bound 300 (prep manifest) + 150.
#
# Usage: tests/hot_writer_peer_reader_2node.sh <label> [ITERS=300]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2; A = writer, B = reader),
#        NOPREP=1 to reuse the current mount.
set -u
LABEL=${1:?label}
ITERS=${2:-300}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/hotrw_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_hotrw_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every
# capture a verdict is taken from is proven to hold its tool's shape first;
# a failed acquisition is an ABORT, never a count of zero.  A loop that hits
# its derived bound (status 124) is the pace FAIL below, not an ABORT.
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
LOOP_BOUND_MS=$(( ITERS * 100 ))
LOOP_TO=$(( LOOP_BOUND_MS / 1000 + 30 ))
SZ=65536

echo "=== hot_writer_peer_reader_2node label=$LABEL A=$A B=$B iters=$ITERS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -z "${NOPREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat /sys/module/mxfs/parameters/force_transport)" | tr -d '\n')"
done
for n in $A $B; do
    measure "$n" 20 "$OUT/${n}_mounted.txt" '^[0-9]+$' "the mount count on $n" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes mounted on the tree's build" "$(cat "$OUT/${A}_mounted.txt" "$OUT/${B}_mounted.txt" | tr -d '\n')" "11"
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
MK="HOTRW-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

value_now_into ino "$A" 30 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $A" "mkdir -p $D && rm -f $D/done && dd if=/dev/zero bs=$SZ count=1 status=none | tr '\\0' a > /dev/shm/pa && dd if=/dev/zero bs=$SZ count=1 status=none | tr '\\0' b > /dev/shm/pb && dd if=/dev/shm/pa of=$D/f bs=$SZ count=1 status=none && sync -f $MNT && stat -c %i $D/f"
echo "  INFO A created f ino=$ino size=$SZ pattern=a"
ckge "A created f" "$ino" 1
value_now_into rv2 "$B" 20 "$OUT/rv_rv2_2.txt" '^[0-9]+$' "rv2 on $B" "stat -c %s $D/f"
ck "B sees the initial file at full size before the loops" "$rv2" "$SZ"
( rsx $LOOP_TO "$A" "s=\$(date +%s%N); i=0; while [ \$i -lt $ITERS ]; do i=\$((i+1)); if [ \$((i % 2)) = 1 ]; then p=/dev/shm/pb; else p=/dev/shm/pa; fi; dd if=\$p of=$D/f bs=$SZ count=1 conv=notrunc status=none || echo A_WRITE_ERR i=\$i; done; e=\$(date +%s%N); touch $D/done; echo A_LOOP done iters=\$i wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/loop_$A.txt"; echo $? > "$OUT/loop_$A.rc" ) &
LPID=$!
rsx $(( LOOP_TO + 30 )) "$B" "reads=0; a=0; b=0; torn=0; short=0; s=\$(date +%s%N); while [ ! -e $D/done ] && [ \$reads -lt 5000 ]; do reads=\$((reads+1)); cat $D/f > /dev/shm/r; n=\$(stat -c %s /dev/shm/r); if [ \$n != $SZ ]; then short=\$((short+1)); [ \$short = 1 ] && cp /dev/shm/r /dev/shm/short_read; continue; fi; if [ \$(tr -d a < /dev/shm/r | wc -c) = 0 ]; then a=\$((a+1)); elif [ \$(tr -d b < /dev/shm/r | wc -c) = 0 ]; then b=\$((b+1)); else torn=\$((torn+1)); [ \$torn = 1 ] && cp /dev/shm/r /dev/shm/torn_read; fi; done; e=\$(date +%s%N); echo B_READS reads=\$reads all_a=\$a all_b=\$b torn=\$torn short=\$short wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/loop_$B.txt"; brc=$?
wait $LPID
loop_require "$(cat "$OUT/loop_$A.rc")" "$OUT/loop_$A.txt" '^A_LOOP done ' "A's writer loop"
loop_require "$brc" "$OUT/loop_$B.txt" '^B_READS ' "B's reader loop"
echo "  INFO $(cat "$OUT/loop_$A.txt" | tr '\n' ' ')"
echo "  INFO $(cat "$OUT/loop_$B.txt" | tr '\n' ' ')"
bv() { grep -ao "$1=[0-9]*" "$OUT/loop_$B.txt" | head -1 | cut -d= -f2; }
wallA=$(grep -ao 'wall_ms=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
reads=$(bv reads); alla=$(bv all_a); allb=$(bv all_b); torn=$(bv torn); short=$(bv short); wallB=$(bv wall_ms)
if [ "${torn:-1}" != 0 ]; then
    rs 20 "$B" "od -An -c /dev/shm/torn_read | tr -s ' ' | uniq -c | head -8" > "$OUT/torn_read_$B.txt"
    echo "  INFO first torn read (run-length of od -c): $(tr '\n' ';' < "$OUT/torn_read_$B.txt" | cut -c1-200)"
fi
if [ "${short:-1}" != 0 ]; then
    rs 20 "$B" "stat -c %s /dev/shm/short_read" > "$OUT/short_read_$B.txt"
    echo "  INFO first short read size: $(cat "$OUT/short_read_$B.txt")"
fi
# Final content: both nodes must see the LAST pattern A wrote, whole.
last=$( [ $(( ITERS % 2 )) = 1 ] && echo b || echo a )
fin=$(for n in $A $B; do rs 20 "$n" "echo \$(stat -c %s $D/f) \$(tr -d $last < $D/f | wc -c)" | tr '\n' ' '; done)
echo "  INFO final views (size non-${last}-bytes) A,B: $fin"
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
underflow=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P71-UNDERFLOW')
lkwait=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKWAIT-LIVE')
bastA=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$A.txt")
bastB=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$B.txt")
meanA=$(python3 -c "print(round(${wallA:-0}/$ITERS, 1))"); meanB=$(python3 -c "print(round(${wallB:-0}/max(${reads:-0},1), 1))")
echo "  HOTRW-MEASURE $LABEL iters=$ITERS A_loop_wall_ms=${wallA:-?} mean_per_write_ms=$meanA B_reads=${reads:-?} all_a=${alla:-?} all_b=${allb:-?} torn=${torn:-?} short=${short:-?} mean_per_read_ms=$meanB bound_ms=$LOOP_BOUND_MS A_basts=$bastA B_basts=$bastB lock_timeouts=$lkto underflow=$underflow lkwait_live=$lkwait"
ck "A's loop ran to completion" "$(grep -ac "A_LOOP done iters=$ITERS" "$OUT/loop_$A.txt")" "1"
ck "no write returned an error" "$(grep -ac 'A_WRITE_ERR' "$OUT/loop_$A.txt")" "0"
ck "B's reader reported" "$(grep -ac 'B_READS' "$OUT/loop_$B.txt")" "1"
ckge "overlap: B completed at least 10 reads while A wrote" "${reads:-0}" 10
ck "overlap: B saw both patterns" "$( [ "${alla:-0}" -gt 0 ] && [ "${allb:-0}" -gt 0 ] && echo 1 || echo 0)" "1"
ck "integrity: no torn read (every read all-a or all-b)" "${torn:-?}" "0"
ck "integrity: no short read" "${short:-?}" "0"
ck "coherency: both nodes' final view is the whole last pattern ($last)" "$fin" "$SZ 0 $SZ 0 "
ck "pace: A's loop within ITERS*100 ms ($LOOP_BOUND_MS)" "$( [ "${wallA:-999999}" -le $LOOP_BOUND_MS ] && echo 1 || echo 0)" "1"
ck "no DLM request deadline expired on either node" "$lkto" "0"
ck "no hold-count underflow on either node" "$underflow" "0"
ck "no live-holder lock wait on either node" "$lkwait" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
