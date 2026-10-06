#!/bin/bash
# pve_wb_refusal.sh — buffered writeback refused in the middle of an fsync's
# writeback pass, on one MXFS-on-DRBD Proxmox host, with the lease still live.
#
# A withdrawal closes the authority gate a few hundred ms before the mount
# shuts down.  An fsync already inside iomap's writeback loop then has an
# ioend refused mid-pass: MXFS ends it with -EIO, and iomap goes on to the
# next folio.  On 2026-10-06 the physical pair's pve2 logged one ioend (ino
# 8388783, off 366112768, 647168 bytes) refused eleven times in that window,
# and fio then hung in fsync on a folio lock no task held.
#
# This drives the same refusal on demand with the module's dbg_refuse_data_n
# knob.  It writes REGIONS separate 1 MiB extents of one file, each followed by
# a 1 MiB hole so that every extent is its own ioend, arms the knob, fsyncs the
# file, disarms it, then reads the file back, syncs it again and lists tasks
# in D.
#
# PASS needs all of:
#   - the fsync answers EIO, within its bound
#   - no ioend is handed back after MXFS ended it (no P294-WB-ENDED-IOEND-AGAIN)
#   - each refusal (P293-TEST-REFUSED-DATA) names a different extent
#   - the read-back, the second sync and the second fsync finish within bound
#   - no task is in D afterwards
#   - no BUG, WARNING, Oops or list corruption in the kernel log since the mark
#
# Usage: tests/pve_wb_refusal.sh <host> [regions]   (default regions 8)
# Env:   MNT (default /mnt/shared)
# Evidence: tests/evidence/pve_wb_refusal/<UTC stamp>-<host>/
#
# DESTRUCTIVE only to its own file, which it removes when nothing is stuck.  A
# build that hands an ended ioend back ends it again, which can corrupt that
# host's kernel memory: run it before the fix on a host that can be reset.

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
HOST=${1:?usage: tests/pve_wb_refusal.sh <host> [regions]}
REGIONS=${2:-8}
MNT=${MNT:-/mnt/shared}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_wb_refusal/$STAMP-$HOST"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

# Each bound: writing 8 MiB of page cache takes well under a second; an fsync
# of 8 refused extents ends them without I/O; the read-back is page cache.  A
# few seconds each, so 20-30 s is a hang, not a slow host.
REMOTE='
set -u
K=/sys/module/mxfs/parameters/dbg_refuse_data_n
[ -w $K ] || { echo "NO_KNOB: this build has no dbg_refuse_data_n"; exit 3; }
m=$(awk -v p='"$MNT"' '\''$2 == p && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1)
[ -n "$m" ] || { echo "NOT_MOUNTED: '"$MNT"'"; exit 3; }
echo "BUILD=$(cat /sys/module/mxfs/srcversion) VERSION=$(cat /sys/module/mxfs/version 2>/dev/null)"
echo "<5>mxfs-test: wb-refusal '"$STAMP"' start" > /dev/kmsg
d='"$MNT"'/wbrefusal/'"$STAMP"'
mkdir -p $d || exit 4
f=$d/f
for i in $(seq 0 $(('"$REGIONS"' - 1))); do
    dd if=/dev/urandom of=$f bs=1M count=1 seek=$((2 * i)) conv=notrunc status=none || { echo "WRITE_FAILED region $i"; exit 4; }
done
echo 1000 > $K
FSYNC='\''import os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    os.fsync(fd)
    print("FSYNC errno=0")
except OSError as e:
    print("FSYNC errno=%d" % e.errno)'\''
t0=$(date +%s%N)
timeout 30 python3 -I -c "$FSYNC" $f; echo "FSYNC_RC=$? FSYNC_MS=$(( ($(date +%s%N) - t0) / 1000000 ))"
left=$(cat $K); echo 0 > $K; echo "REFUSALS_SPENT=$((1000 - left))"
timeout 20 md5sum $f > /dev/null; echo "READ_RC=$?"
timeout 20 sync $f; echo "SYNC_RC=$?"
timeout 20 python3 -I -c "$FSYNC" $f; echo "FSYNC2_RC=$?"
# The refusals are writeback errors of the whole filesystem too (the errseq
# of the superblock), reported once to the next syncfs on this host by
# whoever calls it.  Take that report here, so the sync -f of the next test
# is not handed the error of this one; the second must then be clean.
timeout 20 sync -f $d; echo "SYNCFS_RC=$?"
timeout 20 sync -f $d; echo "SYNCFS2_RC=$?"
# Stuck, not busy: a task in D in each of five samples 2 s apart.  A worker
# waiting on its own I/O is in D for a moment at a time and is not counted.
D=""
for i in 1 2 3 4 5; do
    now=$(awk '\''$3 == "D" {print $1 "(" $2 ")"}'\'' /proc/[0-9]*/stat 2>/dev/null | sort)
    if [ "$i" = 1 ]; then D=$now; else D=$(comm -12 <(echo "$D") <(echo "$now")); fi
    [ "$i" = 5 ] || sleep 2
done
D=$(echo "$D" | tr "\n" " " | sed "s/ *$//")
echo "DSTATE=${D:-none}"
echo "<5>mxfs-test: wb-refusal '"$STAMP"' end" > /dev/kmsg
if [ -z "$D" ]; then timeout 30 rm -rf -- "$d"; echo "CLEANUP_RC=$?"; else echo "CLEANUP=skipped, tasks in D"; fi
'

say "wb-refusal on $HOST: $REGIONS extents of 1 MiB, each its own ioend"
on "$HOST" "$REMOTE" 150 > "$EVID/remote.txt"
rc=$?
sed 's/^/  /' "$EVID/remote.txt" | tee -a "$EVID/log"
on "$HOST" "dmesg --time-format iso | sed -n '/wb-refusal $STAMP start/,/wb-refusal $STAMP end/p'" 30 > "$EVID/klog.txt"
[ "$rc" = 0 ] || { say "FAIL: the remote steps ended rc=$rc"; exit 1; }

r=$(cat "$EVID/remote.txt")
val() { sed -n "s/.*$1=\([^ ]*\).*/\1/p" <<<"$r" | head -1; }
refused=$(grep -c 'P293-TEST-REFUSED-DATA' "$EVID/klog.txt")
extents=$(grep -o 'P293-TEST-REFUSED-DATA ino=[0-9]* off=[0-9]*' "$EVID/klog.txt" | sort -u | wc -l)
again=$(grep -c 'P294-WB-ENDED-IOEND-AGAIN' "$EVID/klog.txt")
again_n=$(sed -n 's/.*P294-WB-ENDED-IOEND-AGAIN-PASS .* again=\([0-9]*\).*/\1/p' "$EVID/klog.txt" | paste -sd+ | bc 2>/dev/null)
bad=$(grep -c -E 'BUG:|WARNING:|Oops|list_add corruption|list_del corruption|refcount_t:|Bad page' "$EVID/klog.txt")
say "  refusals logged $refused over $extents distinct extents; ended ioends handed back: ${again_n:-0} (P294 lines $again); kernel BUG/WARNING lines $bad"

fail=""
[ "$(sed -n 's/^FSYNC errno=\([0-9]*\).*/\1/p' <<<"$r" | head -1)" = 5 ] || fail="$fail fsync did not answer EIO ($(grep -m1 '^FSYNC' <<<"$r"));"
[ "$(val FSYNC_RC)" = 0 ] || fail="$fail fsync did not finish in 30 s (rc $(val FSYNC_RC));"
[ "$again" = 0 ] || fail="$fail an ended ioend was handed back ${again_n:-?} times;"
[ "$refused" -ge 1 ] || fail="$fail no refusal was logged, so nothing was exercised;"
[ "$refused" = "$extents" ] || fail="$fail $refused refusals named only $extents extents;"
[ "$(val READ_RC)" = 0 ] || fail="$fail the read-back did not finish (rc $(val READ_RC));"
[ "$(val SYNC_RC)" = 0 ] || fail="$fail the second sync did not finish (rc $(val SYNC_RC));"
[ "$(val FSYNC2_RC)" = 0 ] || fail="$fail the second fsync did not finish (rc $(val FSYNC2_RC));"
[ "$(val SYNCFS2_RC)" = 0 ] || fail="$fail a second syncfs still reported an error or hung (rc $(val SYNCFS2_RC));"
[ "$(val DSTATE)" = none ] || fail="$fail tasks left in D: $(val DSTATE);"
[ "$bad" = 0 ] || fail="$fail $bad BUG/WARNING lines in the kernel log;"
if [ -n "$fail" ]; then
    say "FAIL:$fail"
    exit 1
fi
say "PASS: every refused ioend was ended once; the fsync answered EIO in $(val FSYNC_MS) ms and nothing is stuck"
