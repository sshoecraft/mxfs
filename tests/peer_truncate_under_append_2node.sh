#!/bin/bash
# peer_truncate_under_append_2node.sh — the peer truncates a file this node
# is appending to, on the two-node TCP rig.  End-of-file coherence test.
#
# A runs an unpaced `echo A$i >> f` loop (open O_APPEND, write, close) for
# ITERS iterations.  B truncates f to zero TRUNCS times, spaced 0.2 s apart,
# starting 0.2 s in (A's loop runs ~1.2-2.8 s, so the last truncate lands mid-loop).  O_APPEND places every write at the cluster-wide end
# of file, so after the LAST truncate the file must be exactly the lines A
# wrote after it: A<k>, A<k+1>, ..., A<ITERS> with k > 1, contiguous,
# complete, and with no NUL byte anywhere.  A NUL byte or a line that starts
# somewhere other than offset 0 means A appended at a cached size the
# peer's truncate had already retired, leaving a zero-filled hole — the
# data-integrity defect this exists to catch.  Both nodes must read back the
# same bytes.
#
# Pace: A's appends against a peer that only touches the file TRUNCS times
# are ~native (0.3-0.7 ms each measured s525e-g); each truncate is one EX
# hand-off (<= 100 ms by the design's own claim).  A_loop_wall_ms <=
# ITERS*2 + TRUNCS*100 ms.
#
# the budget rule (derived): prep 55 s measured (2/tcp QNAP) + loop <= 3 s + capture
# 10 s; ~70 s; chain bound 300 (prep manifest) + 120.
#
# Usage: tests/peer_truncate_under_append_2node.sh <label> [ITERS=4000] [TRUNCS=3]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2; A = writer, B = peer),
#        NOPREP=1 to reuse the current mount.
set -u
LABEL=${1:?label}
ITERS=${2:-20000}
TRUNCS=${3:-3}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# MXFS_DEV: the caller's, else prep_cluster's per-transport rig default
# (no other rig's device path is assumed here)
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/trunc_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_trunc_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.  A loop that hits its
# derived bound (status 124) is the pace FAIL below, not an ABORT.
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
LOOP_BOUND_MS=$(( ITERS * 2 + TRUNCS * 100 ))

echo "=== peer_truncate_under_append_2node label=$LABEL A=$A B=$B iters=$ITERS truncs=$TRUNCS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
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
MK="TRUNC-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

ino=$(rs 30 "$A" "mkdir -p $D && : > $D/f && sync -f $MNT && stat -c %i $D/f" | tail -1 | tr -d '\n')
echo "  INFO A created empty f ino=$ino"
value_now_into rv1 "$B" 20 "$OUT/rv_rv1_1.txt" '^[0-9]+$' "rv1 on $B" "stat -c %s $D/f"
ck "B sees the empty file before the loop" "$rv1" "0"
LOOP_TO=$(( LOOP_BOUND_MS / 1000 + 40 ))
# Start barrier on the shared filesystem (as in append_contention_2node.sh):
# each node announces itself with a file and waits until both exist, so B's
# truncates land while A is appending.  Measured s527c/s527g (0.75.45): A's
# appends take ~40-55 us each against an idle peer and B's FIRST truncate
# blocks ~320 ms behind A's hot EX grant, so the default loop is 20000
# appends (~1 s), B starts 20 ms after the barrier and spaces its truncates
# 100 ms apart: every truncate lands while A is still appending.
( rsx $LOOP_TO "$A" ": > $D/ready_A; w=0; while { [ ! -e $D/ready_A ] || [ ! -e $D/ready_B ]; } && [ \$w -lt 400 ]; do w=\$((w+1)); sleep 0.05; done; s=\$(date +%s%N); i=0; while [ \$i -lt $ITERS ]; do i=\$((i+1)); echo A\$i >> $D/f || echo A_WRITE_ERR i=\$i rc=\$?; done; e=\$(date +%s%N); echo A_LOOP done iters=\$i wall_ms=\$(( (e - s) / 1000000 )) barrier_waits=\$w" > "$OUT/loop_$A.txt"; echo $? > "$OUT/loop_$A.rc" ) &
LPID=$!
rsx $LOOP_TO "$B" ": > $D/ready_B; w=0; while { [ ! -e $D/ready_A ] || [ ! -e $D/ready_B ]; } && [ \$w -lt 400 ]; do w=\$((w+1)); sleep 0.05; done; sleep 0.02; t=0; while [ \$t -lt $TRUNCS ]; do t=\$((t+1)); s=\$(date +%s%N); truncate -s 0 $D/f; rc=\$?; e=\$(date +%s%N); echo B_TRUNC n=\$t rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) size_after=\$(stat -c %s $D/f); sleep 0.1; done; echo B_barrier_waits=\$w" > "$OUT/trunc_$B.txt"; brc=$?
wait $LPID
loop_require "$(cat "$OUT/loop_$A.rc")" "$OUT/loop_$A.txt" '^A_LOOP done ' "A's append loop"
loop_require "$brc" "$OUT/trunc_$B.txt" '^B_barrier_waits=' "B's truncate loop"
echo "  INFO $(cat "$OUT/loop_$A.txt" | tr '\n' ' ')"
echo "  INFO $(cat "$OUT/trunc_$B.txt" | tr '\n' ' ')"
wallA=$(grep -ao 'wall_ms=[0-9]*' "$OUT/loop_$A.txt" | head -1 | cut -d= -f2)
trunc_ok=$(grep -ac 'B_TRUNC n=[0-9]* rc=0' "$OUT/trunc_$B.txt")
trunc_max=$(grep -ao 'wall_ms=[0-9]*' "$OUT/trunc_$B.txt" | cut -d= -f2 | sort -n | tail -1)
werr=$(grep -ac 'A_WRITE_ERR' "$OUT/loop_$A.txt")

for n in $A $B; do
    # base64 on one line with a sentinel: the banner filter cannot add or drop
    # a byte, and a file the truncates emptied still decodes (to nothing) and
    # reaches the integrity verdict instead of an ABORT
    measure "$n" 30 "$OUT/readback_b64_$n.txt" '^B64_END$' "the base64 read-back of f on $n" "base64 -w0 $D/f; echo; echo B64_END"
    grep -av '^B64_END$' "$OUT/readback_b64_$n.txt" | tr -d '\n' | base64 -d > "$OUT/readback_$n.txt"
    measure "$n" 20 "$OUT/stat_$n.txt" '^size=[0-9]+ md5=[0-9a-f]{32}$' "the on-node size and md5 of f on $n" "echo size=\$(stat -c %s $D/f) md5=\$(md5sum < $D/f | cut -d' ' -f1)"
done
echo "  INFO $A $(cat "$OUT/stat_$A.txt")  $B $(cat "$OUT/stat_$B.txt")"
verdict=$(python3 - "$OUT/readback_$A.txt" "$OUT/readback_$B.txt" "$ITERS" <<'EOF'
import sys, re, hashlib
fa, fb, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
da = open(fa, 'rb').read(); db = open(fb, 'rb').read()
nuls = da.count(b'\0')
lines = da.split(b'\n')
if lines and lines[-1] == b'': lines = lines[:-1]
bad = [l for l in lines if not re.fullmatch(rb'A[0-9]+', l)]
seq = [int(l[1:]) for l in lines if re.fullmatch(rb'A[0-9]+', l)]
first = seq[0] if seq else 0
contig = int(bool(seq) and seq == list(range(first, first + len(seq))))
ends_at_n = int(bool(seq) and seq[-1] == n)
exp_size = sum(len(f"A{i}\n") for i in range(first, n + 1)) if seq else 0
print(f"lines={len(lines)} size={len(da)} exp_size={exp_size} nuls={nuls} bad_lines={len(bad)} "
      f"first={first} contiguous={contig} ends_at_iters={ends_at_n} views_identical={int(da==db)} "
      f"md5A={hashlib.md5(da).hexdigest()} md5B={hashlib.md5(db).hexdigest()}"
      + (f" first_bad={bad[0][:40]!r}" if bad else ""))
EOF
)
echo "  INFO verify: $verdict"
v() { echo " $verdict" | grep -ao " $1=[^ ]*" | head -1 | cut -d= -f2; }
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
underflow=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P71-UNDERFLOW')
lkwait=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKWAIT-LIVE')
bastA=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$A.txt")
echo "  TRUNC-MEASURE $LABEL iters=$ITERS truncs=$TRUNCS A_loop_wall_ms=${wallA:-?} trunc_max_ms=${trunc_max:-?} bound_ms=$LOOP_BOUND_MS lines=$(v lines) first=$(v first) size=$(v size) nuls=$(v nuls) A_basts=$bastA lock_timeouts=$lkto underflow=$underflow lkwait_live=$lkwait"
ck "A's loop ran to completion" "$(grep -ac "A_LOOP done iters=$ITERS" "$OUT/loop_$A.txt")" "1"
ck "no write returned an error" "$werr" "0"
ck "B's $TRUNCS truncates all returned rc=0" "$trunc_ok" "$TRUNCS"
ck "the last truncate landed after A had started (first surviving line > A1)" "$( [ "$(v first)" -gt 1 ] 2>/dev/null && echo 1 || echo 0)" "1"
ck "integrity: no NUL byte (no zero-filled hole from a stale end-of-file)" "$(v nuls)" "0"
ck "integrity: no empty, torn, or merged line" "$(v bad_lines)" "0"
ck "integrity: surviving lines are contiguous" "$(v contiguous)" "1"
ck "integrity: surviving lines end at A$ITERS" "$(v ends_at_iters)" "1"
ck "integrity: byte size == exactly the surviving lines" "$(v size)" "$(v exp_size)"
ck "coherency: A's and B's read-back are byte-identical" "$(v views_identical)" "1"
ck "pace: A's loop within ITERS*2 + TRUNCS*100 ms ($LOOP_BOUND_MS)" "$( [ "${wallA:-999999}" -le $LOOP_BOUND_MS ] && echo 1 || echo 0)" "1"
ck "pace: every truncate under the hot appender inside 100 ms" "$( [ "${trunc_max:-99999}" -le 100 ] && echo 1 || echo 0)" "1"
ck "no DLM request deadline expired on either node" "$lkto" "0"
ck "no hold-count underflow on either node" "$underflow" "0"
ck "no live-holder lock wait on either node" "$lkwait" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
