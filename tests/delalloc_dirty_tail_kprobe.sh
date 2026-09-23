#!/bin/bash
# tests/delalloc_dirty_tail_kprobe.sh — the reproducer of
# tests/delalloc_dirty_tail_race.c on NATIVE XFS (loop device, spare node), one
# pass, with KPROBES on the 6.8 iomap/xfs functions that own a folio's
# per-block dirty state, so the first folio's bitmap can be read at every
# transition instead of inferred.
#
# WHY.  tests/delalloc_dirty_tail_trace.sh (s139d) followed the lost pages
# through the tracepoints and found: the 256 KiB folio at offset 0 was written
# back once, at the end of the pass, and that writeback mapped NOTHING — no
# dirty range in its per-block state — although the pass had written its even
# blocks and the mmap toucher had dirtied its odd ones.  The tracepoints cannot
# say why; the per-block state itself is not traced.  These probes read it.
#
# WHAT IS PROBED (6.8 signatures; x86-64 SysV: di si dx cx r8).  Every probe
# on a folio records its index (struct folio +0x20), its flags (+0x0) and its
# private pointer (+0x28, the iomap_folio_state), and where the ifs is
# dereferenced, its two state words (+0x10 uptodate bits, +0x18 dirty bits, for
# a 64-block folio).  Every folio probe is filtered to index 0 — the folio the
# lap follows — so the trace stays small.
#   ifs_alloc(inode, folio, flags)                    the state is created
#   ifs_set_range_dirty(folio, ifs, off, len)         a range is dirtied
#   ifs_clear_range_dirty.constprop.0(folio, ifs, off, len)   cleared (writeback)
#   iomap_dirty_folio(mapping, folio)                 the aops dirty hook
#   __iomap_write_begin(iter, pos, len, folio)        the write's begin
#   iomap_write_end(iter, pos, len, copied, folio)    the write's end
#   folio_clear_dirty_for_io(folio) + return          writeback's first step
#   iomap_do_writepage(folio, wbc, data)              writeback of the folio
#   iomap_writepage_map(wpc, wbc, inode, folio, end)  the per-block walk
#   iomap_page_mkwrite(vmf, ops)                      the fault (no folio arg)
#   iomap_write_delalloc_release(inode, start, end, punch)   the punch scan
#   xfs_bmap_punch_delalloc_range(ip, start, end)     each punch
# The flags word decodes as: bit0 locked, bit1 writeback, bit3 uptodate,
# bit4 dirty, bit14 private.
#
# ATTEMPTS: up to ATTEMPTS passes; the first that loses a page is reported;
# none losing is VACUOUS.
#
# BOUND, derived:  30 (setup) + 60 (gcc) + 20 (probes) + ATTEMPTS x (110 + SECS)
#                  + 20 (teardown) = 463 + 3 x SECS  (= 466 at the defaults)
#
# Usage: [SECS=1] [REQ_KB=256] [ATTEMPTS=3] tests/delalloc_dirty_tail_kprobe.sh <label> <node>
set -u
LABEL=${1:?label}
NODE=${2:?spare node, e.g. test3 — NEVER a node of a running queue}
cd "$(dirname "$0")/.." || exit 2
SECS=${SECS:-1}
REQ_KB=${REQ_KB:-256}
ATTEMPTS=${ATTEMPTS:-3}
IMG=/var/tmp/ddtk_$LABEL.img
DEV=/dev/loop6
MNT=/mnt/ddtk
F=$MNT/t.dat
BIN=/tmp/ddtk_$LABEL
SRC=/src/mxfs/tests/delalloc_dirty_tail_race.c
TR=/sys/kernel/tracing
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddtk_$LABEL
mkdir -p "$OUT"
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

case "$NODE" in
    test1|test2) echo "ABORT: $NODE is a queue node; this lap runs only on a spare"; exit 2 ;;
esac
echo "=== delalloc_dirty_tail_kprobe label=$LABEL node=$NODE secs=$SECS req_kb=$REQ_KB attempts=$ATTEMPTS $(date -u +%FT%TZ) ==="

rsx 60 "$NODE" "mountpoint -q /src || { mkdir -p /src && mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; mountpoint -q /src && echo SRC_OK; uname -r; grep -c ' mxfs ' /proc/mounts; echo end=1" > "$OUT/node.txt" 2>&1
capture_require "$OUT/node.txt" '^SRC_OK$' "the /src export on $NODE"
echo "NODE $NODE kernel=$(grep -a '^[0-9]' "$OUT/node.txt" | head -1)"

rsx 90 "$NODE" "gcc -O2 -pthread -o $BIN $SRC 2>&1 && umount $MNT 2>/dev/null; umount $DEV 2>/dev/null; losetup -d $DEV 2>/dev/null; rm -f $IMG; mkdir -p $MNT; truncate -s 2G $IMG && losetup $DEV $IMG && mkfs.xfs -f -q $DEV && mount -t xfs $DEV $MNT && : > $F && stat -c 'INO=%i' $F && grep ' $MNT ' /proc/mounts | awk '{print \$3}'" > "$OUT/setup.txt" 2>&1
capture_require "$OUT/setup.txt" '^xfs$' "the native XFS loop mount on $NODE"
INO=$(grep -ao '^INO=[0-9]*' "$OUT/setup.txt" | cut -d= -f2)
[ -n "$INO" ] || { echo "ABORT: no inode number for $F"; echo "RESULT: ABORT label=$LABEL stage=setup evidence=$OUT"; exit 2; }
echo "STAGE xfs: $DEV mounted at $MNT, subject file $F ino=$INO at +$(el)s"

# The probes.  Written to kprobe_events one per line; a definition this kernel
# rejects is reported (MISSING) rather than fatal, so the reader knows which
# columns are absent.  Folio probes carry the same fields under the same names.
FOLIO='idx=+0x20(%FOLIO%):u64 flags=+0x0(%FOLIO%):x64 priv=+0x28(%FOLIO%):x64 upd=+0x10(+0x28(%FOLIO%)):x64 dirty=+0x18(+0x28(%FOLIO%)):x64'
probe() { # name symbol folio-register extra-args
    local n=$1 s=$2 r=$3 x=${4:-}
    local f=${FOLIO//%FOLIO%/$r}
    [ -n "$r" ] || f=''
    echo "p:ddtk/$n $s $f $x"
}
{
probe ifs_alloc ifs_alloc '%si' 'iflags=%dx:x32'
probe ifs_set_dirty ifs_set_range_dirty '%di' 'off=%dx:u64 len=%cx:u64'
probe ifs_clear_dirty ifs_clear_range_dirty.constprop.0 '%di' 'off=%dx:u64 len=%cx:u64'
probe dirty_folio iomap_dirty_folio '%si'
probe write_begin __iomap_write_begin '%cx' 'pos=%si:u64 len=%dx:u64'
probe write_end iomap_write_end '%r8' 'pos=%si:u64 len=%dx:u64 copied=%cx:u64'
probe clear_for_io folio_clear_dirty_for_io '%di'
probe do_writepage iomap_do_writepage '%di'
probe writepage_map iomap_writepage_map '%cx' 'end_pos=%r8:u64'
probe mkwrite iomap_page_mkwrite '' 'vmf=%di:x64'
probe delalloc_release iomap_write_delalloc_release '' 'start=%si:u64 end=%dx:u64'
probe punch xfs_bmap_punch_delalloc_range '' 'start=%si:u64 end=%dx:u64'
echo 'r:ddtk/clear_for_io_ret folio_clear_dirty_for_io ret=$retval:u32'
# s139e read the bitmap as ALL dirty on entry to iomap_writepage_map and clear
# on exit, with no block mapped in between.  These follow that walk inside:
#   xfs_map_blocks(wpc, inode, offset) and its return value
#   xfs_convert_blocks(wpc, ip, whichfork, offset)  the delalloc conversion
#   iomap_add_to_ioend(inode, pos, folio, ifs, wpc, wbc, list)
#   xfs_discard_folio(folio, pos)                    the error path
#   folio_end_writeback(folio)                       the "nothing written" exit
#   xfs_iomap_write_unwritten(ip, offset, count, update)  completion's conversion
probe map_blocks xfs_map_blocks '' 'off=%dx:u64 wpc=%di:x64'
echo 'r:ddtk/map_blocks_ret xfs_map_blocks ret=$retval:s32'
probe convert_blocks xfs_convert_blocks '' 'fork=%dx:u32 off=%cx:u64'
probe add_to_ioend iomap_add_to_ioend '%dx' 'pos=%si:u64'
probe discard_folio xfs_discard_folio '%di' 'pos=%si:u64'
probe end_writeback folio_end_writeback '%di'
probe write_unwritten xfs_iomap_write_unwritten '' 'off=%si:u64 count=%dx:u64'
} > "$OUT/kprobes.def"
# rsx closes the remote stdin, so the definitions travel inside the command:
# one `echo "<def>" >> kprobe_events` per probe, each reporting DEFINED or
# MISSING by name.
DEFS=$(sed 's/\$/\\$/g' "$OUT/kprobes.def" | awk '{printf "echo \"%s\" >> '"$TR"'/kprobe_events 2>/dev/null && echo DEFINED %s || echo MISSING %s; ", $0, $1, $1}')
rsx 60 "$NODE" "echo 0 > $TR/tracing_on; echo > $TR/trace; echo nop > $TR/current_tracer; echo 65536 > $TR/buffer_size_kb; echo 0 > $TR/events/ddtk/enable 2>/dev/null; echo > $TR/kprobe_events 2>/dev/null; $DEFS for d in $TR/events/ddtk/*/; do n=\$(basename \$d); case \$n in mkwrite|clear_for_io_ret|map_blocks_ret) ;; delalloc_release|punch) echo 'start < 0x40000' > \$d/filter;; map_blocks|convert_blocks|write_unwritten) echo 'off < 0x40000' > \$d/filter;; *) echo 'idx == 0' > \$d/filter;; esac; done; echo 1 > $TR/events/ddtk/enable && echo ENABLED; echo end=1" > "$OUT/probes.txt" 2>&1
capture_require "$OUT/probes.txt" '^ENABLED$' "the kprobe setup on $NODE"
echo "STAGE probes: $(grep -ac '^DEFINED' "$OUT/probes.txt") defined, missing: $(grep -a '^MISSING' "$OUT/probes.txt" | awk '{print $2}' | tr '\n' ' ')"

found=0
for a in $(seq 1 "$ATTEMPTS"); do
    rsx $(( SECS + 30 )) "$NODE" "echo > $TR/trace; echo 1 > $TR/tracing_on; echo DDTK-RUN-$LABEL-$a > $TR/trace_marker; $BIN $F $SECS $REQ_KB check; rc=\$?; echo 0 > $TR/tracing_on; echo rc=\$rc" > "$OUT/race_$a.txt" 2>&1
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

rsx 60 "$NODE" "echo 0 > $TR/events/ddtk/enable; echo > $TR/kprobe_events; echo > $TR/trace; echo 1 > $TR/tracing_on; umount $MNT; losetup -d $DEV; rm -f $IMG $BIN; echo TEARDOWN_OK" > "$OUT/teardown.txt" 2>&1
capture_require "$OUT/teardown.txt" 'TEARDOWN_OK' "the teardown on $NODE"

if [ "$found" = 0 ]; then
    echo "VACUOUS: no attempt lost a page, so there is no lost folio to read in the trace"
    echo "RESULT: VACUOUS label=$LABEL reason=race-not-produced attempts=$ATTEMPTS wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- the first folio's story in the closing pass: everything from the LAST
#      full-folio write at offset 0 (the closing pass's first write) to the end.
#      Return probes carry no folio, so each is kept only when the same task's
#      previous line was its entry probe for this folio.
T=$OUT/trace_$found.txt
python3 - "$T" > "$OUT/story.txt" <<'EOF'
import re, sys
ev = []
for line in open(sys.argv[1], errors='replace'):
    m = re.match(r'\s*(\S+)\s+\[(\d+)\]\s+\S+\s+([\d.]+): (\S+): (.*)', line)
    if m:
        task, cpu, ts, name, rest = m.groups()
        ev.append((ts, task.rsplit('-', 1)[-1], name.replace('ddtk/', ''), rest))
starts = [i for i, (ts, pid, n, r) in enumerate(ev) if n == 'write_begin' and 'pos=0 len=262144' in r]
if not starts:
    print('NO_ANCHOR'); sys.exit(0)
anchor = starts[-1]
print('ANCHOR line=%d ts=%s' % (anchor + 1, ev[anchor][0]))
prev = {}
for ts, pid, n, r in ev[max(anchor - 2, 0):]:
    if n.endswith('_ret') and prev.get(pid) != n[:-4]:
        continue
    prev[pid] = n
    fm = re.search(r'flags=0x([0-9a-f]+)', r)
    if fm:
        fl = int(fm.group(1), 16)
        r = r.replace(fm.group(0), 'flags=' + ''.join(c if fl >> b & 1 else '-' for b, c in ((0, 'L'), (1, 'W'), (3, 'U'), (4, 'D'), (14, 'P'))))
    r = re.sub(r'\(\S+\+0x[0-9a-f]+/0x[0-9a-f]+(?: <- \S+)?\) ', '', r)
    r = r.replace('priv=0x', 'p=').replace('upd=0x', 'U=').replace('dirty=0x', 'D=')
    print('%s %s %-16s %s' % (ts, pid, n, r))
EOF
echo "STAGE the closing pass's folio at index 0 ($(head -1 "$OUT/story.txt")); flags: L=locked W=writeback U=uptodate D=dirty P=private"
echo "    lines: $(wc -l < "$OUT/story.txt")"
echo "    the reproducer's own markers:"
grep -a 'tracing_mark_write' "$OUT/story.txt" | cut -c1-160 | sed 's/^/    /'
echo "    the 45 lines before the checker's DDTR-ZERO marker (the instant the page-cache copy read back wrong):"
awk '/DDTR-ZERO/{n=NR} END{print n}' "$OUT/story.txt" | { read -r n; [ -n "$n" ] && tail -n +$(( n > 45 ? n - 45 : 1 )) "$OUT/story.txt" | head -46 | cut -c1-210 | sed 's/^/    /'; }
echo "    the writeback (from the last clear_for_io on):"
awk '/ clear_for_io /{n=NR} END{print n}' "$OUT/story.txt" | { read -r n; [ -n "$n" ] && tail -n +"$n" "$OUT/story.txt" | head -12 | cut -c1-210 | sed 's/^/    /'; }
echo "    ... (full story in $OUT/story.txt)"
echo "STAGE done at +$(el)s"
echo "RESULT: TRACED label=$LABEL attempt=$found bad=$BAD pages=[$BADP] wall=$(el)s evidence=$OUT"
