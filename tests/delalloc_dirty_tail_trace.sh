#!/bin/bash
# tests/delalloc_dirty_tail_trace.sh — the reproducer of
# tests/delalloc_dirty_tail_race.c on NATIVE XFS (a loop device on a spare
# node), one pass, under the kernel's own xfs/iomap/filemap tracepoints, so the
# lost pages can be followed by file offset: which write allocated their
# delalloc, what punched it, what the page fault mapped, and what writeback
# saw at that offset.
#
# WHY.  tests/delalloc_dirty_tail_loop_control.sh (s139a, s139b) showed native
# 6.8 XFS losing the same class of page the 2-node MXFS lap lost: a contiguous
# run of ~10 mmap-dirtied (odd) pages read back as zeros after a remount while
# every write()-page survives.  The run's position varies (pages 1..19 in one
# lap, 3235..3253 in another) and the loss is racy (secs=0: 1 of 3 runs;
# secs=1: 2 of 2).  Reading the code has not found it; the trace will.
#
# The subject is a page, so the trace is filtered to the file's inode and the
# pass is kept short (SECS, default 1).  The reproducer's file is created FIRST
# so its inode number is known before tracing starts; the program opens it
# O_TRUNC and keeps the inode.
#
# ATTEMPTS: the loss is racy, so up to ATTEMPTS passes are run and the first
# one that loses a page is the one reported; a lap where none loses anything
# is VACUOUS (the race did not occur), not a pass.
#
# BOUND, derived:
#   loop setup + mkfs                30 s
#   gcc of one file                  60 s
#   per attempt: run SECS + msync    (SECS + 20) s
#                trace dump          30 s   (~50k lines over ssh)
#                unmount + remount   30 s
#                verify              30 s
#              = (110 + SECS) s, x ATTEMPTS (3)  = 333 s at the defaults
#   teardown                         20 s
#                                  ------
#                                  443 s + 3 x SECS  (= 446 at the defaults)
#
# Usage: [SECS=1] [REQ_KB=256] [ATTEMPTS=3] tests/delalloc_dirty_tail_trace.sh <label> <node>
set -u
LABEL=${1:?label}
NODE=${2:?spare node, e.g. test3 — NEVER a node of a running queue}
cd "$(dirname "$0")/.." || exit 2
SECS=${SECS:-1}
REQ_KB=${REQ_KB:-256}
ATTEMPTS=${ATTEMPTS:-3}
IMG=/var/tmp/ddtt_$LABEL.img
DEV=/dev/loop6
MNT=/mnt/ddtt
F=$MNT/t.dat
BIN=/tmp/ddtt_$LABEL
SRC=/src/mxfs/tests/delalloc_dirty_tail_race.c
TR=/sys/kernel/tracing
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddtt_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

case "$NODE" in
    test1|test2) echo "ABORT: $NODE is a queue node; this lap runs only on a spare"; exit 2 ;;
esac
echo "=== delalloc_dirty_tail_trace label=$LABEL node=$NODE secs=$SECS req_kb=$REQ_KB attempts=$ATTEMPTS $(date -u +%FT%TZ) ==="

rsx 60 "$NODE" "mountpoint -q /src || { mkdir -p /src && mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; mountpoint -q /src && echo SRC_OK; uname -r; grep -c ' mxfs ' /proc/mounts; echo end=1" > "$OUT/node.txt" 2>&1
capture_require "$OUT/node.txt" '^SRC_OK$' "the /src export on $NODE"
echo "NODE $NODE kernel=$(grep -a '^[0-9]' "$OUT/node.txt" | head -1)"

rsx 90 "$NODE" "gcc -O2 -pthread -o $BIN $SRC 2>&1 && umount $MNT 2>/dev/null; umount $DEV 2>/dev/null; losetup -d $DEV 2>/dev/null; rm -f $IMG; mkdir -p $MNT; truncate -s 2G $IMG && losetup $DEV $IMG && mkfs.xfs -f -q $DEV && mount -t xfs $DEV $MNT && : > $F && stat -c 'INO=%i' $F && grep ' $MNT ' /proc/mounts | awk '{print \$3}'" > "$OUT/setup.txt" 2>&1
capture_require "$OUT/setup.txt" '^xfs$' "the native XFS loop mount on $NODE"
INO=$(grep -ao '^INO=[0-9]*' "$OUT/setup.txt" | cut -d= -f2)
[ -n "$INO" ] || { echo "ABORT: no inode number for $F"; echo "RESULT: ABORT label=$LABEL stage=setup evidence=$OUT"; exit 2; }
echo "STAGE xfs: $DEV mounted at $MNT, subject file $F ino=$INO at +$(el)s"

# The events.  Each is enabled only if this kernel has it, and each one that
# carries an ino is filtered to the subject.  What is asked of each:
#   xfs_iomap_alloc / xfs_iomap_found   which mapping each write and fault got
#   xfs_bmap_pre_update / post_update   every extent change: the punch and the
#                                       writeback conversion, by file offset
#   iomap_iter                          every iomap_begin: pos, length, flags
#                                       (WRITE|FAULT tells a fault from a write)
#   iomap_writepage_map                 what writeback mapped at each offset
#   mm_filemap_add_to_page_cache        each folio's arrival (index, order)
EVS="xfs/xfs_iomap_alloc xfs/xfs_iomap_found xfs/xfs_bmap_pre_update xfs/xfs_bmap_post_update xfs/xfs_delalloc_enospc iomap/iomap_iter iomap/iomap_writepage_map iomap/iomap_writepage iomap/iomap_invalidate_folio iomap/iomap_release_folio filemap/mm_filemap_add_to_page_cache filemap/mm_filemap_delete_from_page_cache"
rsx 60 "$NODE" "echo 0 > $TR/tracing_on; echo > $TR/trace; echo nop > $TR/current_tracer; echo 65536 > $TR/buffer_size_kb; for e in $EVS; do d=$TR/events/\$e; [ -d \$d ] || { echo MISSING \$e; continue; }; if grep -q '^field:.* ino;' \$d/format; then echo \"ino == $INO\" > \$d/filter; fi; echo 1 > \$d/enable && echo ENABLED \$e; done; echo end=1" > "$OUT/events.txt" 2>&1
capture_require "$OUT/events.txt" '^end=1$' "the tracepoint setup on $NODE"
echo "STAGE events: $(grep -ac '^ENABLED' "$OUT/events.txt") enabled, missing: $(grep -a '^MISSING' "$OUT/events.txt" | sed 's/MISSING //' | tr '\n' ' ')"

found=0
for a in $(seq 1 "$ATTEMPTS"); do
    rsx $(( SECS + 30 )) "$NODE" "echo > $TR/trace; echo 1 > $TR/tracing_on; echo DDTT-RUN-$LABEL-$a > $TR/trace_marker; $BIN $F $SECS $REQ_KB; rc=\$?; echo 0 > $TR/tracing_on; echo rc=\$rc" > "$OUT/race_$a.txt" 2>&1
    capture_require "$OUT/race_$a.txt" '^SHORT=[0-9]+ ' "the reproducer's summary line (attempt $a) on $NODE"
    SUM=$(grep -aoE '^SHORT=.*ERR=[0-9]+' "$OUT/race_$a.txt" | head -1)
    VHI=$(echo "$SUM" | grep -ao 'VERIFY_HI=[0-9]*' | cut -d= -f2)
    echo "STAGE attempt $a reproducer: $SUM"
    rsx 60 "$NODE" "cat $TR/trace; echo TRACE_END" > "$OUT/trace_$a.txt" 2>&1
    capture_require "$OUT/trace_$a.txt" '^TRACE_END$' "the trace dump (attempt $a) on $NODE"
    rsx 60 "$NODE" "umount $MNT && mount -t xfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount_$a.txt" 2>&1
    capture_require "$OUT/remount_$a.txt" 'REMOUNT_OK' "the unmount/remount (attempt $a) on $NODE"
    rsx 60 "$NODE" "python3 /src/mxfs/tests/ddtr_verify.py $F $VHI 64" > "$OUT/verify_$a.txt" 2>&1
    capture_require "$OUT/verify_$a.txt" '^CHECKED=[0-9]+ BAD=[0-9]+ BAD_WRITER=[0-9]+ BAD_TOUCHER=[0-9]+ TOUCHED=[0-9]+ UNTOUCHED=[0-9]+$' "the post-remount content check (attempt $a) on $NODE"
    BAD=$(grep -ao ' BAD=[0-9]*' "$OUT/verify_$a.txt" | head -1 | cut -d= -f2)
    BADP=$(grep -ao '^  page=[0-9]*' "$OUT/verify_$a.txt" | cut -d= -f2 | tr '\n' ',' | sed 's/,$//')
    echo "STAGE attempt $a post-remount: BAD=$BAD pages=[$BADP] trace_lines=$(grep -ac '' "$OUT/trace_$a.txt") at +$(el)s"
    if [ "${BAD:-0}" -ge 1 ]; then found=$a; break; fi
done

rsx 60 "$NODE" "for e in $EVS; do d=$TR/events/\$e; [ -d \$d ] && { echo 0 > \$d/enable; echo 0 > \$d/filter; }; done; echo > $TR/trace; echo 1 > $TR/tracing_on; umount $MNT; losetup -d $DEV; rm -f $IMG $BIN; echo TEARDOWN_OK" > "$OUT/teardown.txt" 2>&1
capture_require "$OUT/teardown.txt" 'TEARDOWN_OK' "the teardown on $NODE"

if [ "$found" = 0 ]; then
    echo "VACUOUS: no attempt lost a page, so there is no lost page to follow in the trace"
    echo "RESULT: VACUOUS label=$LABEL reason=race-not-produced attempts=$ATTEMPTS wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- follow the first lost page and its neighbours through the trace
T=$OUT/trace_$found.txt
first=$(echo "$BADP" | cut -d, -f1)
last=$(echo "$BADP" | tr ',' '\n' | tail -1)
lo=$(( (first - 1) * 4096 )); hi=$(( (last + 2) * 4096 ))
echo "STAGE following lost pages $first..$last (bytes [$lo,$hi)) through $T"
python3 - "$T" "$lo" "$hi" "$INO" > "$OUT/followed.txt" <<'EOF'
import re, sys
t, lo, hi, ino = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
# Every line whose byte range (offset/count, pos/length, startoff/blockcount in
# 512-byte or 4096-byte units, or a page index) intersects [lo, hi).
BS = 4096
def spans(line):
    out = []
    m = re.search(r'offset (0x[0-9a-f]+|\d+) count (0x[0-9a-f]+|\d+)', line)
    if m: out.append((int(m.group(1), 0), int(m.group(2), 0)))
    m = re.search(r'pos (0x[0-9a-f]+|\d+) length (0x[0-9a-f]+|\d+)', line)
    if m: out.append((int(m.group(1), 0), int(m.group(2), 0)))
    m = re.search(r'fileoff (0x[0-9a-f]+|\d+) startblock .* fsbcount (0x[0-9a-f]+|\d+)', line)
    if m: out.append((int(m.group(1), 0) * BS, int(m.group(2), 0) * BS))
    m = re.search(r'ofs=(\d+) order=(\d+)', line)
    if m: out.append((int(m.group(1)), BS << int(m.group(2))))
    m = re.search(r'ofs=(\d+)', line)
    if m and not out: out.append((int(m.group(1)), BS))
    return out
n = 0
for line in open(t, errors='replace'):
    if 'tracing_mark_write' in line:
        print(line.rstrip()); continue
    if ino not in line: continue
    hit = False
    for (s, l) in spans(line):
        if s < hi and s + l > lo: hit = True
    if hit:
        print(line.rstrip()); n += 1
print('FOLLOWED=%d' % n)
EOF
echo "STAGE $(grep -a '^FOLLOWED=' "$OUT/followed.txt") lines touch the lost range; first 80:"
grep -av '^FOLLOWED=' "$OUT/followed.txt" | head -80 | cut -c1-230 | sed 's/^/    /'
echo "STAGE done at +$(el)s"
echo "RESULT: TRACED label=$LABEL attempt=$found bad=$BAD first=$first last=$last wall=$(el)s evidence=$OUT"
