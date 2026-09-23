#!/bin/bash
# tests/delalloc_dirty_tail_durability.sh — when a short buffered write releases
# the delalloc it did not use, does a DIRTY folio in that range keep its
# reservation, and does its data survive?
# (ledger D-THE-DELALLOC-RELEASE-SHIM-PUNCHES-UNDER-DIRTY-FOLIOS-BELOW-6-12)
#
# WHAT WAS WRONG.  Below 6.12 this fork replaced upstream's
# iomap_write_delalloc_release() with a one-line macro that punched the ENTIRE
# unwritten tail of a short write in a single blind call.  Upstream's function
# exists precisely to not do that: it scans the page cache and punches only the
# gaps BETWEEN dirty folios, because — in its own words — folios with "dirty
# data still pending in the page cache ... are going to be written and so must
# still retain the delalloc backing for writeback", and failing to hold the
# range "can leave dirty pages with no space reservation in the cache".
# 0.89.60 backports the scan.
#
# WHY THE SUBJECT IS HARD TO REACH, AND HOW tests/delalloc_dirty_tail_race.c
# REACHES IT.  xfs_buffered_write_iomap_end() punches only when the mapping is
# IOMAP_DELALLOC, is IOMAP_F_NEW (created by THIS write), and the write was
# SHORT.  The reproducer satisfies all three deliberately: it writes into holes,
# it re-punches the file to holes between passes so every mapping is new again,
# and its source buffer is one readable page followed by PROT_NONE so every
# write is short at a boundary we choose rather than by a race.  A second thread
# then dirties pages inside the tail the writer is about to release, chasing the
# writer rather than leading it — a store that lands FIRST allocates the
# delalloc itself, the mapping is then not NEW, and nothing is punched at all.
#
# THE TWO THINGS THIS LAP MUST NOT CONFUSE.
#   * P313-DELALLOC-KEEP counts how often the scan DECIDED to keep a dirty
#     folio's reservation.  Zero means the subject never occurred, and that is
#     VACUOUS — not a pass.  This is the same trap that let four earlier laps in
#     this directory report a clean result from a workload that never produced
#     its subject.
#   * The data check must be read from a FRESH mount.  The bytes are in the page
#     cache either way; only a remount says whether they reached the platter.
#
# ORACLE.  The two threads write disjoint pages and the expected content is a
# pure function of the page index: page i's first byte must be (i & 0xff), for
# every even page below the VERIFY_HI the reproducer prints and for every odd
# page its manifest (<file>.touched) marks as stored during the closing pass.
# Even pages came from write(), odd pages from the mmap store — so a failure
# also says WHICH writer lost its data.  The manifest is not optional: the
# toucher does not reach every odd page (see tests/delalloc_dirty_tail_race.c),
# and without it this lap graded holes as loss (s138b2).
#
# BOUND, derived, every term a number this lap spends:
#   prep_cluster          300 s  (measured 53-137 s; the bound its siblings use)
#   gcc of one file        60 s  (the bound tests/d0532_nowait_iomap_probe.sh
#                                uses for the same operation)
#   the race itself     RACE_S s, default 30, passed to the program
#   msync+fsync of 16 MiB  20 s  (native XFS does ~700 MB in 3-4 s on this
#                                hardware, so 16 MiB is well under a second;
#                                20 s is far past 2x and covers the wrap)
#   unmount + remount      60 s
#   the verify pass        60 s  (4032 page reads over 16 MiB from a cold mount)
#   dmesg reads            40 s
#                        ------
#                        540 s + RACE_S   (= 570 at the default)
#
# Usage: [RACE_S=30] [REQ_KB=256] tests/delalloc_dirty_tail_durability.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
MNT=/mnt/shared
RACE_S=${RACE_S:-30}
REQ_KB=${REQ_KB:-256}
BIN=/tmp/ddtr_$LABEL
SRC=/src/mxfs/tests/delalloc_dirty_tail_race.c
F=$MNT/ddtr_$LABEL.dat
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddtr_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== delalloc_dirty_tail_durability label=$LABEL node=$A race_s=$RACE_S req_kb=$REQ_KB sv=$SV $(date -u +%FT%TZ) ==="

# The probe this lap grades on must be IN the module.  A probe that is not a
# string in mxfs.ko is a guaranteed silence, and counting one is how a harness
# reads its own emptiness as a measurement of the filesystem.
if ! strings -a mxfs.ko 2>/dev/null | grep -q 'P313-DELALLOC-KEEP'; then
    echo "ABORT: P313-DELALLOC-KEEP is not a string in mxfs.ko — the scan this lap measures is not in the build"
    echo "RESULT: ABORT label=$LABEL stage=build-gate evidence=$OUT"; exit 2
fi
echo "  PASS P313-DELALLOC-KEEP is present in the built module"

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ "$prc" = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

rsx 60 "$A" "grep -a ' $MNT mxfs ' /proc/mounts | awk '{print \$1}'" > "$OUT/dev.txt"
capture_require "$OUT/dev.txt" '^/dev/' "the device under $MNT on $A"
DEV=$(grep -a '^/dev/' "$OUT/dev.txt" | head -1)
echo "DEVICE node=$A dev=$DEV"

rsx 60 "$A" "gcc -O2 -pthread -o $BIN $SRC 2>&1 && echo CC_OK" > "$OUT/cc.txt" 2>&1
capture_require "$OUT/cc.txt" 'CC_OK' "the compile of the reproducer on $A"
echo "  PASS the reproducer compiled on $A"

rsx 20 "$A" "dmesg | grep -ac 'P313-DELALLOC-KEEP'; echo end=1" > "$OUT/keep_pre.txt" 2>&1
capture_require "$OUT/keep_pre.txt" '^end=1$' "the pre-run P313 count on $A"
pre=$(grep -aoE '^[0-9]+$' "$OUT/keep_pre.txt" | head -1)

rsx $(( RACE_S + 40 )) "$A" "$BIN $F $RACE_S $REQ_KB" > "$OUT/race.txt" 2>&1
capture_require "$OUT/race.txt" '^SHORT=[0-9]+ ' "the reproducer's summary line on $A"
SUM=$(grep -aoE '^SHORT=.*ERR=[0-9]+' "$OUT/race.txt" | head -1)
echo "STAGE reproducer: $SUM"
VHI=$(echo "$SUM" | grep -ao 'VERIFY_HI=[0-9]*' | cut -d= -f2)
SHORTN=$(echo "$SUM" | grep -ao 'SHORT=[0-9]*' | cut -d= -f2)
ERRN=$(echo "$SUM" | grep -ao 'ERR=[0-9]*' | cut -d= -f2)
ck "the reproducer reported no errors of its own" "${ERRN:-x}" 0
ckge "the reproducer produced short writes (its whole premise)" "${SHORTN:-0}" 1

rsx 20 "$A" "dmesg | grep -ac 'P313-DELALLOC-KEEP'; echo end=1" > "$OUT/keep_post.txt" 2>&1
capture_require "$OUT/keep_post.txt" '^end=1$' "the post-run P313 count on $A"
post=$(grep -aoE '^[0-9]+$' "$OUT/keep_post.txt" | head -1)
kept=$(( ${post:-0} - ${pre:-0} ))
echo "STAGE P313-DELALLOC-KEEP: pre=$pre post=$post delta=$kept"

# VACUOUS, not PASS.  If the scan never had to keep a dirty folio's reservation,
# this run never produced the state the record is about, and the data check
# below would pass for a reason that has nothing to do with the fix.
if [ "$kept" -lt 1 ]; then
    echo "VACUOUS: the scan never kept a dirty folio's reservation in this run — the short writes never overlapped a dirtied tail, so the subject did not occur"
    echo "  (raise RACE_S, or REQ_KB so the punch range spans more pages)"
    echo "RESULT: VACUOUS label=$LABEL reason=subject-not-produced kept=$kept evidence=$OUT wall=$(el)s"; exit 3
fi
echo "  PASS the scan kept a dirty folio's reservation $kept time(s) — the subject occurred"

# Only a fresh mount says what reached the platter.
rsx 60 "$A" "umount $MNT && mount -t mxfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount.txt" 2>&1
capture_require "$OUT/remount.txt" 'REMOUNT_OK' "the unmount/remount on $A"
echo "  PASS the filesystem unmounted and remounted"

# The check reads the reproducer's manifest of the odd pages the toucher
# actually stored to in the closing pass (tests/ddtr_verify.py).  s138b2 graded
# FAIL without one: the toucher lags the writer when the pass restarts, the odd
# pages below where it caught up are holes the punch left, and the old oracle
# read them as lost data.  Native 6.8 XFS produced the identical verdict
# (s139a/b/d-g), which is what exposed the oracle.
rsx 60 "$A" "python3 /src/mxfs/tests/ddtr_verify.py $F $VHI 12" > "$OUT/verify.txt" 2>&1
capture_require "$OUT/verify.txt" '^CHECKED=[0-9]+ BAD=[0-9]+ BAD_WRITER=[0-9]+ BAD_TOUCHER=[0-9]+ TOUCHED=[0-9]+ UNTOUCHED=[0-9]+$' "the post-remount content check on $A"
CHECKED=$(grep -ao 'CHECKED=[0-9]*' "$OUT/verify.txt" | head -1 | cut -d= -f2)
BAD=$(grep -ao ' BAD=[0-9]*' "$OUT/verify.txt" | head -1 | cut -d= -f2)
TOUCHEDN=$(grep -ao 'TOUCHED=[0-9]*' "$OUT/verify.txt" | head -1 | cut -d= -f2)
echo "STAGE post-remount content: $(grep -a '^CHECKED=' "$OUT/verify.txt" | head -1)"
[ "$BAD" != 0 ] && grep -a '^  page=' "$OUT/verify.txt" | head -12 | sed 's/^/    /'
ckge "the check actually read the file back" "${CHECKED:-0}" 1
# A toucher that stored to only a handful of pages exercised almost nothing;
# a quarter of the odd pages is the least this lap accepts as a measurement.
ckge "the toucher's manifest covers enough odd pages to mean something" "${TOUCHEDN:-0}" $(( VHI / 4096 / 8 ))
ck "every page the filesystem accepted is on the platter after a remount" "${BAD:-x}" 0

rsx 20 "$A" "dmesg | grep -ac 'BUG:\|Oops'; echo end=1" > "$OUT/bad.txt" 2>&1
capture_require "$OUT/bad.txt" '^end=1$' "the crash scan on $A"
ck "the node logged no BUG or Oops" "$(grep -aoE '^[0-9]+$' "$OUT/bad.txt" | head -1)" 0

rs 20 "$A" "rm -f $BIN" >/dev/null 2>&1 || true
echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 kept=$kept wall=$(el)s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails kept=$kept wall=$(el)s evidence=$OUT"
fi
exit $(( fails > 0 ))
