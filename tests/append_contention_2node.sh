#!/bin/bash
# append_contention_2node.sh — both nodes append to ONE file at the same
# time, on the two-node TCP rig, and the result must be exactly the union
# of what each node wrote.
#
# Each node runs an unpaced `echo X$i >> f` loop (open O_APPEND, write,
# close) for ITERS iterations, A writing "A<i>" lines and B writing "B<i>".
# O_APPEND places every write at the CLUSTER-WIDE end of file; a node whose
# cached size is stale writes over the peer's line instead of after it, and
# the loss shows as a short line count, a merged or torn line, or a missing
# sequence number.  Afterwards both nodes read the file back and the two
# views must be byte-identical.
#
# Integrity assertions (the point of the harness):
#   - line count == 2*ITERS, byte size == sum of both nodes' lines
#   - every line matches ^[AB][0-9]+$ (no empty, torn, or merged line)
#   - A's lines are exactly 1..ITERS in order, once each; same for B
#   - A's and B's read-back md5 are identical, and equal to the writer-side
#     expectation
#
# Pace (derived): every append is a cross-node EX hand-off of the inode at
# worst; the release/hand-off path measured 82-94 ms per unlink after
# D-0917 (sess523), so 100 ms per append is the bound the design itself
# claims.  loop_wall_ms <= ITERS * 100 per node.  The mean is reported so
# the budget can be tightened toward the measurement.
#
# Both loops start behind a barrier on the shared filesystem (each node
# announces a ready file and waits for the other's) so they overlap; the
# harness asserts the overlap and reports it.  Measured s525e-g (0.75.44,
# ITERS=300, no barrier): 0.3-0.7 ms per append, 3 BASTs, no overlap.
#
# the budget rule (derived): prep 55 s measured (2/tcp QNAP) + loop <= ITERS*0.1 s
# + read-back 5 s + capture 10 s; ITERS=1000 -> <= 170 s worst case; chain
# bound 300 (prep manifest) + 180.
#
# REC>0 (D-APPEND-MULTIPAGE-64K-RECORD-LOST-WITH-LOCK-TIMEOUT-0921): every
# append is ONE write(2) of exactly REC bytes (dd oflag=append iflag=fullblock
# from a generated record "<tag><i>xxx…"), so a multi-page record cannot be
# split by the peer at stdio granularity and the verifier splits the file into
# REC-byte records instead of lines.  The 2026-09-05 multipage arm (100 x
# 65536 B per node) lost one of B's records with a DLM deadline in the lap.
#
# Usage: tests/append_contention_2node.sh <label> [ITERS=1000] [REC=0]
# Env:   MXFS_DEV (default: the device of A's live mxfs mount after prep,
#        resolved by mxfs_dev_resolve — no rig's device path is assumed),
#        MXFS_NODE_LIST (default test1,test2), NOPREP=1 to reuse the
#        current mount.
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted: a
# failed acquisition is an ABORT, never a count of zero.  A loop that hits
# its derived bound (status 124) is the pace FAIL below, not an ABORT.
set -u
LABEL=${1:?label}
ITERS=${2:-1000}
REC=${3:-0}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/append_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_append_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
offset_ms() {
    local t0 tr t1
    t0=$(date +%s%N); tr=$(rs 15 "$1" "date +%s%N" | tr -dc 0-9); t1=$(date +%s%N)
    python3 -c "print(int(($tr - ($t0 + $t1) / 2) / 1e6))"
}
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
LOOP_BOUND_MS=$(( ITERS * 100 ))

echo "=== append_contention_2node label=$LABEL A=$A B=$B iters=$ITERS rec=$REC sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
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
MK="APPEND-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

measure "$A" 30 "$OUT/create_$A.txt" '^ino=[0-9]+$' "the creation of f on $A" "mkdir -p $D && : > $D/f && sync -f $MNT && echo ino=\$(stat -c %i $D/f)"
ino=$(grep -ao '^ino=[0-9]*' "$OUT/create_$A.txt" | cut -d= -f2)
echo "  INFO A created empty f ino=$ino"
measure "$B" 20 "$OUT/size0_$B.txt" '^size=[0-9]+$' "the initial size of f seen from $B" "echo size=\$(stat -c %s $D/f)"
ck "B sees the empty file before the loops" "$(grep -ao '^size=[0-9]*' "$OUT/size0_$B.txt" | cut -d= -f2)" "0"
LOOP_TO=$(( LOOP_BOUND_MS / 1000 + 40 ))
offA=$(offset_ms "$A"); offB=$(offset_ms "$B")
# Start barrier on the shared filesystem: each node announces itself with a
# file, then waits (<= 20 s) until both announcements exist, so the two
# loops actually overlap instead of running back to back behind two ssh
# session set-ups (s525e-g: B's 300 appends finished in 17 ms, 3 BASTs).
for n in $A $B; do
    tag=$( [ "$n" = "$A" ] && echo A || echo B )
    if [ "$REC" -gt 0 ]; then
        # one write(2) of exactly REC bytes per append; the record is
        # "<tag><i>" padded with x to REC bytes (no newline).  printf's
        # width padding + tr ' ' x needs no backslash: s528c/d showed the
        # earlier tr '\\0' x losing its escape through ssh and padding with
        # NUL bytes, which the verifier then reported as 201 torn records.
        body="h=$tag\$i; printf \"%-${REC}s\" \"\$h\" | tr ' ' x | dd of=$D/f oflag=append conv=notrunc bs=$REC count=1 iflag=fullblock status=none || echo ${tag}_WRITE_ERR i=\$i rc=\$?"
    else
        body="echo $tag\$i >> $D/f || echo ${tag}_WRITE_ERR i=\$i rc=\$?"
    fi
    ( rsx $LOOP_TO "$n" ": > $D/ready_$tag; w=0; while { [ ! -e $D/ready_A ] || [ ! -e $D/ready_B ]; } && [ \$w -lt 400 ]; do w=\$((w+1)); sleep 0.05; done; s=\$(date +%s%N); i=0; while [ \$i -lt $ITERS ]; do i=\$((i+1)); $body; done; e=\$(date +%s%N); echo ${tag}_LOOP done iters=\$i wall_ms=\$(( (e - s) / 1000000 )) barrier_waits=\$w start=\$s end=\$e" > "$OUT/loop_$n.txt"; echo $? > "$OUT/loop_$n.rc" ) &
done
wait
# the boundary, per node by name: a loop whose ssh failed is an ABORT; one
# that ran out its derived bound (124) is the pace FAIL below
loop_require "$(cat "$OUT/loop_$A.rc")" "$OUT/loop_$A.txt" '^A_LOOP done ' "A's append loop"
loop_require "$(cat "$OUT/loop_$B.rc")" "$OUT/loop_$B.txt" '^B_LOOP done ' "B's append loop"
echo "  INFO $(cat "$OUT/loop_$A.txt" | tr '\n' ' ')"
echo "  INFO $(cat "$OUT/loop_$B.txt" | tr '\n' ' ')"
lv() { grep -ao "$2=[0-9]*" "$OUT/loop_$1.txt" | head -1 | cut -d= -f2; }
wallA=$(lv "$A" wall_ms); wallB=$(lv "$B" wall_ms)
overlap_ms=$(python3 -c "
sa=($(lv "$A" start 2>/dev/null || echo 0) - $offA*1e6)/1e6; ea=($(lv "$A" end 2>/dev/null || echo 0) - $offA*1e6)/1e6
sb=($(lv "$B" start 2>/dev/null || echo 0) - $offB*1e6)/1e6; eb=($(lv "$B" end 2>/dev/null || echo 0) - $offB*1e6)/1e6
print(int(min(ea, eb) - max(sa, sb)))" 2>/dev/null)
werr=$(cat "$OUT/loop_$A.txt" "$OUT/loop_$B.txt" | grep -ac '_WRITE_ERR')

# Read-back from both nodes, verified on clyde.  base64 on one line so the
# ssh banner filter (line-oriented grep) cannot add or drop a byte: s528c/d
# read back 13107201 bytes of a 13107200-byte file through a plain cat.
for n in $A $B; do
    # the sentinel is the shape, so a file MXFS emptied still decodes (to
    # nothing) and reaches the integrity verdict instead of an ABORT
    measure "$n" 60 "$OUT/readback_b64_$n.txt" '^B64_END$' "the base64 read-back of f on $n" "base64 -w0 $D/f; echo; echo B64_END"
    grep -av '^B64_END$' "$OUT/readback_b64_$n.txt" | tr -d '\n' | base64 -d > "$OUT/readback_$n.txt"
    measure "$n" 20 "$OUT/stat_$n.txt" '^size=[0-9]+ md5=[0-9a-f]{32}$' "the on-node size and md5 of f on $n" "echo size=\$(stat -c %s $D/f) md5=\$(md5sum < $D/f | cut -d' ' -f1)"
done
echo "  INFO $A $(cat "$OUT/stat_$A.txt")  $B $(cat "$OUT/stat_$B.txt")"
verdict=$(python3 - "$OUT/readback_$A.txt" "$OUT/readback_$B.txt" "$ITERS" "$REC" <<'EOF'
import sys, re, hashlib
fa, fb, n, rec = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
da = open(fa, 'rb').read(); db = open(fb, 'rb').read()
if rec > 0:
    # fixed-size records: "<tag><i>" padded with x to exactly rec bytes
    exp_size = 2 * n * rec
    lines = [da[i:i + rec] for i in range(0, len(da), rec)]
    pat = rb'[AB][0-9]+x*'
    bad = [l for l in lines if len(l) != rec or not re.fullmatch(pat, l)]
else:
    exp_size = sum(len(f"A{i}\n") for i in range(1, n+1)) + sum(len(f"B{i}\n") for i in range(1, n+1))
    lines = da.split(b'\n')
    if lines and lines[-1] == b'': lines = lines[:-1]
    pat = rb'[AB][0-9]+'
    bad = [l for l in lines if not re.fullmatch(pat, l)]
seq = {'A': [], 'B': []}
for l in lines:
    if l not in bad and re.fullmatch(pat, l): seq[chr(l[0])].append(int(l[1:].rstrip(b'x')))
want = list(range(1, n+1))
missing = {k: sorted(set(want) - set(v))[:5] for k, v in seq.items()}
dups = {k: len(v) - len(set(v)) for k, v in seq.items()}
out = (f"lines={len(lines)} size={len(da)} exp_size={exp_size} bad_lines={len(bad)} "
       f"A_seq_ok={int(seq['A']==want)} B_seq_ok={int(seq['B']==want)} "
       f"A_count={len(seq['A'])} B_count={len(seq['B'])} A_dups={dups['A']} B_dups={dups['B']} "
       f"A_missing_first={missing['A']} B_missing_first={missing['B']} "
       f"views_identical={int(da==db)} md5A={hashlib.md5(da).hexdigest()} md5B={hashlib.md5(db).hexdigest()}")
if bad:
    out += f" first_bad={bad[0][:40]!r}"
print(out.replace(', ', ','))
EOF
)
echo "  INFO verify: $verdict"
v() { echo " $verdict" | grep -ao " $1=[^ ]*" | head -1 | cut -d= -f2; }
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
# the same two captures by name, so the per-node verdicts below read from a
# path the boundary was crossed for
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
underflow=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P71-UNDERFLOW')
lkwait=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKWAIT-LIVE')
bastA=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$A.txt")
bastB=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$B.txt")
meanA=$(python3 -c "print(round(${wallA:-0}/$ITERS, 1))"); meanB=$(python3 -c "print(round(${wallB:-0}/$ITERS, 1))")
echo "  APPEND-MEASURE $LABEL iters=$ITERS loop_wall_ms A=${wallA:-?} B=${wallB:-?} overlap_ms=${overlap_ms:-?} mean_per_append_ms A=$meanA B=$meanB bound_ms=$LOOP_BOUND_MS lines=$(v lines) size=$(v size) bad_lines=$(v bad_lines) A_basts=$bastA B_basts=$bastB lock_timeouts=$lkto underflow=$underflow lkwait_live=$lkwait"
ck "both loops ran to completion" "$(grep -ac "A_LOOP done iters=$ITERS" "$OUT/loop_$A.txt")$(grep -ac "B_LOOP done iters=$ITERS" "$OUT/loop_$B.txt")" "11"
ck "overlap: the two loops ran concurrently for at least half of the shorter loop" "$(python3 -c "print(1 if ${overlap_ms:-0} * 2 >= min(${wallA:-999999}, ${wallB:-999999}) else 0)")" "1"
ck "no write returned an error" "$werr" "0"
ck "integrity: line count == 2*ITERS" "$(v lines)" "$(( 2 * ITERS ))"
ck "integrity: byte size == sum of both nodes' lines" "$(v size)" "$(v exp_size)"
ck "integrity: no empty, torn, or merged line" "$(v bad_lines)" "0"
ck "integrity: A's lines are exactly 1..$ITERS in order" "$(v A_seq_ok)" "1"
ck "integrity: B's lines are exactly 1..$ITERS in order" "$(v B_seq_ok)" "1"
ck "coherency: A's and B's read-back are byte-identical" "$(v views_identical)" "1"
ck "coherency: on-node md5 A == B" "$( [ "$(grep -ao 'md5=[0-9a-f]*' "$OUT/stat_$A.txt")" = "$(grep -ao 'md5=[0-9a-f]*' "$OUT/stat_$B.txt")" ] && echo 1 || echo 0)" "1"
ck "harness: A's read-back md5 equals A's on-node md5 (transport exact)" "$( [ "md5=$(v md5A)" = "$(grep -ao 'md5=[0-9a-f]*' "$OUT/stat_$A.txt")" ] && echo 1 || echo 0)" "1"
ck "pace: A's loop within ITERS*100 ms ($LOOP_BOUND_MS)" "$( [ "${wallA:-999999}" -le $LOOP_BOUND_MS ] && echo 1 || echo 0)" "1"
ck "pace: B's loop within ITERS*100 ms ($LOOP_BOUND_MS)" "$( [ "${wallB:-999999}" -le $LOOP_BOUND_MS ] && echo 1 || echo 0)" "1"
ck "no DLM request deadline expired on either node" "$lkto" "0"
ck "no hold-count underflow on either node" "$underflow" "0"
ck "no live-holder lock wait on either node" "$lkwait" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
for n in $A $B; do
    measure "$n" 20 "$OUT/${n}_mounted_after.txt" '^[0-9]+$' "the mount count on $n after the lap" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes still mounted" "$(cat "$OUT/${A}_mounted_after.txt" "$OUT/${B}_mounted_after.txt" | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
