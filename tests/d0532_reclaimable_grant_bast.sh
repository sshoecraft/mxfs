#!/bin/bash
# tests/d0532_reclaimable_grant_bast.sh <A> <B> [files] [label]
#
# D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532,
# item (c): a reclaimable in-core inode that still carries a cached grant.
#
# Node A caches a grant on a regular file (PR after reading it, EX after
# writing it) and then evicts the inode with drop_caches: the struct stays in
# core as IRECLAIMABLE with i_dlm_mode still set, until xfs_reclaim_inode's
# mxfs_dlm_evict runs.  Node B then modifies the file, which sends A a BAST.
# xfs_iget(XFS_IGET_INCORE) refuses a reclaimable inode, so the BAST is
# served by the no-inode release: the on-disk grant is released, the corpse's
# in-core grant fields are not touched (noino_bast_reclaimable counts it,
# P-NOINO-RECLAIMABLE names it).  A's next lookup recycles the corpse and
# mxfs_dlm_ilock_begin's fast path serves the cached mode with no cluster
# grant (recycle_grant_cached / recycle_grant_phantom count it,
# P-RECYCLE-PHANTOM names it); with no reload, A serves the stale inode core.
#
# Shapes, FILES files each, in one lap:
#   pr    B creates and writes each file (1 MiB); A reads it (PR cached);
#         A drop_caches; B appends 4 KiB and fsyncs; A stats and digests.
#   ex    A creates and writes each file (EX cached); A drop_caches; B appends
#         and fsyncs; A stats and digests.  (A's EX may already have been
#         released by the quiet-age dwork before the eviction; reported.)
#   freed A creates and writes each file, B reads it (B caches the inode),
#         A rm's it (the free is deferred: grant kept cached on the corpse),
#         B stats its cached path (a BAST on the freed corpse), A creates a
#         new file that reuses the number.  Item (c) proper.
# CTL=1 runs the pr and ex shapes without the drop_caches (inode live: the
# in-core BAST path) — the control.
#
# Read from the kernel, never from userspace:
#   noino_bast_reclaimable, recycle_grant_cached, recycle_grant_phantom,
#   p71_underflows on A (reset before each shape, read after); P-NOINO-
#   RECLAIMABLE / P-RECYCLE-PHANTOM lines in A's window; the per-file
#   size+md5 on A after B's append against B's own.
# RESULT REPRODUCED  any file where A's size or digest differs from B's, or
#                    recycle_grant_phantom > 0 (the phantom is the defect
#                    whether or not this lap's timing made it visible).
# RESULT CLEAN       every file agrees and recycle_grant_phantom == 0, with
#                    the shape reached (recycle_grant_cached > 0 or
#                    noino_bast_reclaimable > 0 in the drop_caches arms).
# RESULT INCONCLUSIVE the drop_caches arms never met a reclaimable corpse
#                    with a cached grant (both counters 0): the eviction was
#                    reclaimed before the peer's BAST or the grant was
#                    already released.
# Fails on any P71, splat or shutdown.
# budget: per shape FILES x (1 MiB write + read + append) at ms each, three
# ssh round trips per shape; measured at FILES=32 ... s (fill in); bound 240 s.
set -u
cd /src/mxfs || exit 1
A=${1:?node A}; B=${2:?node B}; FILES=${3:-32}; LABEL=${4:-rgb}
CTL=${CTL:-0}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0532rgb_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
MARK="D0532RGB-$LABEL-$$"
CNTS="noino_bast_reclaimable recycle_grant_cached recycle_grant_phantom p71_underflows"
D=$MNT/.d0532rgb_$LABEL
echo "=== d0532_reclaimable_grant_bast A=$A B=$B files=$FILES ctl=$CTL out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0532rgb: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532rgb: $MNT not mounted on $n"; exit 2; }
done
for c in $CNTS; do
  rs 15 "$A" "[ -f /sys/module/mxfs/parameters/$c ] && echo has" | grep -q has || { echo "RESULT FAIL d0532rgb: $A build has no counter $c"; exit 2; }
done
rs 20 "$A" "mkdir -p $D && echo '$MARK-START' > /dev/kmsg" >/dev/null
rs 20 "$B" "echo '$MARK-START' > /dev/kmsg" >/dev/null
T0=$(date +%s)
reset_cnt() { rs 15 "$A" "for c in $CNTS; do echo 0 > /sys/module/mxfs/parameters/\$c; done; echo '$MARK-$1-BEGIN' > /dev/kmsg" >/dev/null; }
read_cnt() { rs 15 "$A" "echo '$MARK-$1-END' > /dev/kmsg; for c in $CNTS; do printf ' %s=%s' \$c \$(cat /sys/module/mxfs/parameters/\$c); done; echo"; }
# stat+md5 of every file of a shape on one node: "name size md5"
digest() { rs 90 "$1" "cd $D && for i in \$(seq 1 $FILES); do f=$2\$i; printf '%s %s %s\n' \$f \$(stat -c %s \$f) \$(md5sum \$f | cut -d' ' -f1); done"; }
drop() { [ "$CTL" = 1 ] || rs 30 "$A" "sync; echo 2 > /proc/sys/vm/drop_caches; echo dropped" | grep -q dropped || echo "  WARN drop_caches on $A did not report"; }
mism=0; phantom_total=0; cached_total=0; noino_total=0; p71_total=0
verdict() { # <shape> <A digest file> <B digest file> <counter line>
  local sh=$1 da=$2 db=$3 cl=$4 m
  m=$(diff <(sort "$da") <(sort "$db") | grep -c '^<')
  local no=$(echo "$cl" | sed -n 's/.*noino_bast_reclaimable=\([0-9]*\).*/\1/p')
  local rc=$(echo "$cl" | sed -n 's/.*recycle_grant_cached=\([0-9]*\).*/\1/p')
  local ph=$(echo "$cl" | sed -n 's/.*recycle_grant_phantom=\([0-9]*\).*/\1/p')
  local p7=$(echo "$cl" | sed -n 's/.*p71_underflows=\([0-9]*\).*/\1/p')
  echo "  INFO shape=$sh files=$FILES mismatched=$m noino_bast_reclaimable=${no:-na} recycle_grant_cached=${rc:-na} recycle_grant_phantom=${ph:-na} p71_underflows=${p7:-na}"
  diff <(sort "$da") <(sort "$db") | grep '^[<>]' | head -6 | sed "s/^</  $A/; s/^>/  $B/"
  mism=$((mism + m)); phantom_total=$((phantom_total + ${ph:-0})); cached_total=$((cached_total + ${rc:-0})); noino_total=$((noino_total + ${no:-0})); p71_total=$((p71_total + ${p7:-0}))
}

# --- shape pr: B writes, A reads (PR), A evicts, B appends, A reads ---
reset_cnt pr
rs 90 "$B" "cd $D && for i in \$(seq 1 $FILES); do dd if=/dev/urandom of=pr\$i bs=1M count=1 status=none; done; sync; echo made" | grep -q made || { echo "RESULT FAIL d0532rgb: pr setup on $B"; exit 1; }
rs 90 "$A" "cd $D && for i in \$(seq 1 $FILES); do cat pr\$i > /dev/null; done; echo readok" | grep -q readok || { echo "RESULT FAIL d0532rgb: pr read on $A"; exit 1; }
drop
rs 90 "$B" "cd $D && for i in \$(seq 1 $FILES); do python3 -c \"import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_APPEND); os.write(fd, b'Q'*4096); os.fsync(fd); os.close(fd)\" pr\$i; done; echo appended" | grep -q appended || { echo "RESULT FAIL d0532rgb: pr append on $B"; exit 1; }
digest "$A" pr > "$OUT/pr_$A.txt"; digest "$B" pr > "$OUT/pr_$B.txt"
verdict pr "$OUT/pr_$A.txt" "$OUT/pr_$B.txt" "$(read_cnt pr)"

# --- shape ex: A writes (EX), A evicts, B appends, A reads ---
reset_cnt ex
rs 90 "$A" "cd $D && for i in \$(seq 1 $FILES); do dd if=/dev/urandom of=ex\$i bs=1M count=1 status=none; done; sync; echo made" | grep -q made || { echo "RESULT FAIL d0532rgb: ex setup on $A"; exit 1; }
drop
rs 90 "$B" "cd $D && for i in \$(seq 1 $FILES); do python3 -c \"import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_APPEND); os.write(fd, b'Q'*4096); os.fsync(fd); os.close(fd)\" ex\$i; done; echo appended" | grep -q appended || { echo "RESULT FAIL d0532rgb: ex append on $B"; exit 1; }
digest "$A" ex > "$OUT/ex_$A.txt"; digest "$B" ex > "$OUT/ex_$B.txt"
verdict ex "$OUT/ex_$A.txt" "$OUT/ex_$B.txt" "$(read_cnt ex)"

# --- shape freed: A writes, B caches, A rm (deferred free), B stats the
# cached path (BAST on the corpse), A creates a new file reusing the number ---
if [ "$CTL" != 1 ]; then
  reset_cnt freed
  rs 90 "$A" "cd $D && for i in \$(seq 1 $FILES); do dd if=/dev/urandom of=fr\$i bs=64k count=1 status=none; done; sync; for i in \$(seq 1 $FILES); do stat -c '%n %i' fr\$i; done" > "$OUT/freed_inos.txt"
  rs 90 "$B" "cd $D && for i in \$(seq 1 $FILES); do cat fr\$i > /dev/null; done; echo readok" | grep -q readok || { echo "RESULT FAIL d0532rgb: freed read on $B"; exit 1; }
  rs 90 "$A" "cd $D && rm -f fr* && sync && echo rmok" | grep -q rmok || { echo "RESULT FAIL d0532rgb: freed rm on $A"; exit 1; }
  rs 90 "$B" "cd $D && n=0; for i in \$(seq 1 $FILES); do stat -c %s fr\$i >/dev/null 2>&1 && n=\$((n+1)); done; echo STATOK=\$n" | grep -a STATOK | sed 's/^/  INFO freed: B stats of the removed paths that still succeeded /'
  rs 90 "$A" "cd $D && for i in \$(seq 1 $FILES); do echo new > nf\$i; done; sync; for i in \$(seq 1 $FILES); do stat -c '%n %i' nf\$i; done" > "$OUT/freed_newinos.txt"
  reused=$(comm -12 <(awk '{print $2}' "$OUT/freed_inos.txt" | sort) <(awk '{print $2}' "$OUT/freed_newinos.txt" | sort) | wc -l)
  cl=$(read_cnt freed)
  echo "  INFO shape=freed files=$FILES numbers_reused=$reused$cl"
  phantom_total=$((phantom_total + $(echo "$cl" | sed -n 's/.*recycle_grant_phantom=\([0-9]*\).*/\1/p') ))
  cached_total=$((cached_total + $(echo "$cl" | sed -n 's/.*recycle_grant_cached=\([0-9]*\).*/\1/p') ))
  noino_total=$((noino_total + $(echo "$cl" | sed -n 's/.*noino_bast_reclaimable=\([0-9]*\).*/\1/p') ))
  p71_total=$((p71_total + $(echo "$cl" | sed -n 's/.*p71_underflows=\([0-9]*\).*/\1/p') ))
fi

W=$(( $(date +%s) - T0 ))
rs 30 "$A" "cd $MNT && rm -rf $D" >/dev/null
sleep 1
for n in $A $B; do rs 30 "$n" "dmesg | sed -n \"/$MARK-START/,\\\$p\"" > "$OUT/dmesg_$n.txt"; done
[ -s "$OUT/dmesg_$A.txt" ] || { echo "RESULT FAIL d0532rgb: empty dmesg capture from $A"; exit 2; }
grep -a 'P-NOINO-RECLAIMABLE\|P-RECYCLE-PHANTOM' "$OUT/dmesg_$A.txt" | head -4 | cut -c1-220 | sed 's/^/  /'
splat=$(cat "$OUT/dmesg_$A.txt" "$OUT/dmesg_$B.txt" | grep -aEc 'BUG:|Oops|WARNING: CPU')
shut=$(cat "$OUT/dmesg_$A.txt" "$OUT/dmesg_$B.txt" | grep -ac 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown')
echo "  INFO wall=${W}s mismatched=$mism recycle_grant_phantom=$phantom_total recycle_grant_cached=$cached_total noino_bast_reclaimable=$noino_total p71=$p71_total splat=$splat shutdown=$shut evidence=$OUT"
[ "$p71_total" = 0 ] && [ "$splat" = 0 ] && [ "$shut" = 0 ] || { echo "RESULT FAIL d0532rgb: p71=$p71_total splat=$splat shutdown=$shut out=$OUT"; exit 1; }
if [ "$mism" -gt 0 ] || [ "$phantom_total" -gt 0 ]; then
  echo "RESULT REPRODUCED d0532rgb: mismatched=$mism recycle_grant_phantom=$phantom_total (noino_bast_reclaimable=$noino_total recycle_grant_cached=$cached_total) wall=${W}s out=$OUT"; exit 1
fi
if [ "$CTL" != 1 ] && [ "$cached_total" = 0 ] && [ "$noino_total" = 0 ]; then
  echo "RESULT INCONCLUSIVE d0532rgb: no reclaimable corpse with a cached grant met a BAST or a recycle wall=${W}s out=$OUT"; exit 3
fi
echo "RESULT CLEAN d0532rgb: every file agreed on both nodes, recycle_grant_phantom=0 (noino_bast_reclaimable=$noino_total recycle_grant_cached=$cached_total)${CTL:+ ctl=$CTL} wall=${W}s out=$OUT"
exit 0
