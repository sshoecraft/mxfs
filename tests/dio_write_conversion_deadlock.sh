#!/bin/bash
# tests/dio_write_conversion_deadlock.sh <nodeA> <nodeB> [seconds] [label]
#
# Two nodes overwrite the same file with aligned O_DIRECT writes (plain dd,
# no io_uring, no NOWAIT).  An aligned direct write takes the IOLOCK shared —
# admitted on a cached PR grant — and then, inside xfs_file_write_checks,
# updates the timestamps under ILOCK_EXCL, which asks the cluster for EX
# while its own PR hold is still counted.  With both nodes in that state the
# master denies each upgrade (P-CONVBLK-DENY held_mode=PR req_mode=EX ->
# -EDEADLK); the requester's self-demote cannot release a PR its own task
# holds (P15-REL-ABORT pr=1), and after 65 one-second laps mxfs_dlm_ilock_begin
# declares "EDEADLK retry livelock" and shuts the filesystem down.  First
# seen under tests/d0532_nowait_iomap_probe.sh PEER=... (diow phase).
#
# RESULT PASS  both nodes complete every write, no livelock line, no
#              shutdown, both mounts still live, the two nodes read the same
#              untorn image afterwards.
# RESULT FAIL  a livelock line, a shutdown, a failed write, a dead mount, or
#              differing / torn images.
# A P73-WAITSTALL line (an inode acquire waiting 30 s) fails the lap too, and
# so does a P59-IREAD-MISMATCH (an extent load whose leaves disagree with the
# dinode's count) or a P63-TORN-FLUSH (an inode flush publishing a count its
# destaged leaves do not hold).  leafwr counts bmbt leaf writes (P63-LEAFWR,
# capped at 4000 per load); unread_clean_skip and unread_local count the
# inode flush's unread-fork guard (clean blocks not destaged, and blocks
# with local work found there).  bmbt_write_unread (uncapped, fails the
# lap) counts bmbt block writes whose in-core owner's extents were unread:
# a cached image going to disk over what a peer wrote.  bmbt_evict_capped
# counts owned bmbt blocks a reload's eviction walk saw but left cached
# because its hold array was full; iflush_bmbt_capped and
# iflush_bmbt_notdone_needs count the inode flush's destage walk leaving
# owned bmbt blocks unwritten (at its hold cap, or skipped for !XBF_DONE
# while carrying local work).  crc counts bmbt reads that failed CRC or found
# a non-bmbt block on disk (fails the lap).  rel_bmbt_flushed counts EX
# releases whose extent tree the release loop had to land before the unlock;
# rel_bmbt_wedge counts releases that could not and shut down (fails the lap).
# scan_stale_skip counts freed bmbt buffers the scan declined to write;
# evict_skip counts cached bmbt blocks a reload found carrying local work
# (P67-BMBT-EVICT-SKIP, capped at 500 lines) — previous-tenure content the
# release left behind.  EXTSPAN=<blocks> widens the EXTEND span
# (default 256), for a sparse file with a multi-leaf extent tree whose
# holes the EXTCHK stray check can see; offsets are drawn from 30 random
# bits, since $RANDOM alone stops at 32767.  PREFILL=<n> first writes n
# random blocks of 'a' from nodeA alone (tests/dwcd_prefill.py), building a
# multi-leaf, multi-level tree the contended phase then works on; those
# blocks join the EXTCHK written set.  NOCAT=1 skips each writer's
# preamble read of the whole file, which on a gigabyte span trades grants
# with the other writer for the entire window.  bmbt_evict counts the reload's evictions of
# cached bmbt blocks (P59-BMBT-EVICT, capped at 1000 per load).
# Reports iomap_iread_pr per node: shared mappings whose extent load asked
# the cluster for PR (the D-0972 fix; the EXTEND arm must reach it).
# Reports write_checks_excl per node: the count of write checks retaken
# exclusive before the timestamp update (the D-0970 fix; na on a build
# without it).  Also reports iomap_nowait_refused per node (must stay 0: this arm never
# takes the nowait mapping, so a failure here is not that path).
# MIX=1: half the writes are 512-byte O_DIRECT writes at a sector offset
# that is not block-aligned (the unaligned direct-write path, which runs the
# same checks under a shared ride).  A 4 KiB block may then legitimately hold
# both nodes' bytes, so the verdict requires identical images on the two
# nodes but not uniform blocks.
# EXTEND=1: aligned 4 KiB writes at random offsets up to 1 MiB on a 64 KiB
# file, so writes extend EOF (the zero-EOF relock), land in holes and
# allocate — the mapping-side EX acquisitions, not only the timestamp.  Each
# writer reports the blocks it wrote successfully (WROTE), and the verdict
# adds EXTCHK: every written block holds 'a' or 'b', every unwritten block
# reads zero, and the file reaches the highest written block.
# At 40 s every writer's kernel stack is captured on both nodes
# (stacks_<node>.txt) and the frames that matter are summarised.
# budget: SECONDS (default 90; the livelock needs 65 s of laps to surface)
# of back-to-back 4 KiB direct writes + 20 s for setup and the verdict.
set -u
cd /src/mxfs || exit 1
A=${1:?nodeA}; B=${2:?nodeB}; S=${3:-90}; LABEL=${4:-dwcd}
MIX=${MIX:-0}
EXTEND=${EXTEND:-0}
SPAN=16; [ "$EXTEND" = 1 ] && SPAN=${EXTSPAN:-256}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dwcd_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
F=$MNT/.dwcd_$LABEL
MARK="DWCD-$LABEL-$$"
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL dwcd: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL dwcd: $MNT not mounted on $n"; exit 2; }
done
echo "=== dio_write_conversion_deadlock A=$A B=$B seconds=$S mix=$MIX extend=$EXTEND sv=$want out=$OUT ==="
rs 20 "$A" "dd if=/dev/zero of=$F bs=64k count=1 oflag=direct status=none && sync && echo ok" | grep -q ok || { echo "RESULT FAIL dwcd: setup write failed"; exit 2; }
PREFILL=${PREFILL:-0}
NOCAT=${NOCAT:-0}
if [ "$EXTEND" = 1 ] && [ "$PREFILL" -gt 0 ]; then
  rs 90 "$A" "python3 /src/mxfs/tests/dwcd_prefill.py $F $SPAN $PREFILL a" > "$OUT/prefill_$A.txt"
  echo "  prefill: $(grep -a '^PREFILL' "$OUT/prefill_$A.txt" || echo 'no PREFILL line')"
  grep -aq '^PREFILL' "$OUT/prefill_$A.txt" || { echo "RESULT FAIL dwcd: prefill failed"; exit 2; }
fi
for n in $A $B; do rs 10 "$n" "for c in iomap_nowait_refused write_checks_excl iomap_iread_pr iflush_unread_clean_skip iflush_unread_local bmbt_write_unread bmbt_evict_capped iflush_bmbt_capped iflush_bmbt_notdone_needs reg_bmbt_rel_flushed reg_bmbt_rel_wedge bmbt_scan_stale_skip bmbt_lookup_bad bmbt_rel_evicted bmbt_rel_busy bmbt_rel_localwork; do echo 0 > /sys/module/mxfs/parameters/\$c 2>/dev/null; done; echo $MARK > /dev/kmsg" >/dev/null; done
writer() {
  # $1 node, $2 pattern byte
  rs $((S + 15)) "$1" "python3 -c \"open('/tmp/dwcd_blk','wb').write(b'$2'*4096)\" || exit 1
end=\$((SECONDS + $S)); ok=0; bad=0
[ $NOCAT = 1 ] || cat $F > /dev/null
while [ \$SECONDS -lt \$end ]; do
  if [ $MIX = 1 ] && [ \$((RANDOM % 2)) = 1 ]; then
    s=\$((RANDOM % 128)); [ \$((s % 8)) = 0 ] && s=\$((s + 1))
    if dd if=/tmp/dwcd_blk of=$F bs=512 seek=\$s count=1 conv=notrunc oflag=direct status=none; then ok=\$((ok+1)); else bad=\$((bad+1)); fi
  else
    s=\$(( (RANDOM * 32768 + RANDOM) % $SPAN ))
    if dd if=/tmp/dwcd_blk of=$F bs=4k seek=\$s count=1 conv=notrunc oflag=direct status=none; then ok=\$((ok+1)); w[\$s]=1; else bad=\$((bad+1)); fi
  fi
done
echo WRITER ok=\$ok failed=\$bad
echo WROTE \${!w[@]}" > "$OUT/writer_$1.txt"
}
T0=$(date +%s)
writer "$A" a & pa=$!
writer "$B" b & pb=$!
# Instrument: 40 s in (inside the 65 s retry window if a livelock formed),
# record every writer's kernel stack and the inode's holder line, so the PR
# that blocks the self-demote is named from the live system, not inferred.
( sleep 40
  for n in $A $B; do
    rs 15 "$n" "for p in \$(pidof dd); do echo \"== pid \$p\"; cat /proc/\$p/stack; done
for s in /proc/[0-9]*/status; do d=\${s%/status}; grep -q '^State:.*D' \$s 2>/dev/null || continue; echo \"== D \${d#/proc/} \$(cat \$d/comm 2>/dev/null)\"; cat \$d/stack 2>/dev/null; done" > "$OUT/stacks_$n.txt"
  done ) & pst=$!
wait $pa; wait $pb; wait $pst
W=$(( $(date +%s) - T0 ))
fail=0
for n in $A $B; do
  wl=$(grep -a '^WRITER' "$OUT/writer_$n.txt")
  rs 30 "$n" "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_$n.txt"
  [ -s "$OUT/dmesg_$n.txt" ] || { echo "  FAIL $n: empty dmesg capture"; fail=1; }
  live=$(rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && stat -c %s $F 2>/dev/null")
  ll=$(grep -ac 'EDEADLK retry livelock' "$OUT/dmesg_$n.txt")
  deny=$(grep -ac 'P-CONVBLK-DENY' "$OUT/dmesg_$n.txt")
  shut=$(grep -ac 'Shutting down filesystem\|P-SESSION-POISON\|force-shutdown' "$OUT/dmesg_$n.txt")
  refused=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iomap_nowait_refused 2>/dev/null")
  wcx=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/write_checks_excl 2>/dev/null")
  irp=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iomap_iread_pr 2>/dev/null")
  stall=$(grep -ac 'P73-WAITSTALL' "$OUT/dmesg_$n.txt")
  mism=$(grep -ac 'P59-IREAD-MISMATCH' "$OUT/dmesg_$n.txt")
  torn=$(grep -ac 'P63-TORN-FLUSH' "$OUT/dmesg_$n.txt")
  evict=$(grep -ac 'P59-BMBT-EVICT ' "$OUT/dmesg_$n.txt")
  leafwr=$(grep -ac 'P63-LEAFWR' "$OUT/dmesg_$n.txt")
  uskip=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iflush_unread_clean_skip 2>/dev/null")
  ulocal=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iflush_unread_local 2>/dev/null")
  bwu=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_write_unread 2>/dev/null")
  bec=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_evict_capped 2>/dev/null")
  ifc=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iflush_bmbt_capped 2>/dev/null")
  ifn=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/iflush_bmbt_notdone_needs 2>/dev/null")
  crc=$(grep -ac 'Metadata CRC error\|MEDIUM-NOT-BMBT' "$OUT/dmesg_$n.txt")
  rbf=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/reg_bmbt_rel_flushed 2>/dev/null")
  rbw=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/reg_bmbt_rel_wedge 2>/dev/null")
  bss=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_scan_stale_skip 2>/dev/null")
  blb=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_lookup_bad 2>/dev/null")
  tee=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_rel_evicted 2>/dev/null")
  teb=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_rel_busy 2>/dev/null")
  tel=$(rs 10 "$n" "cat /sys/module/mxfs/parameters/bmbt_rel_localwork 2>/dev/null")
  eskip=$(grep -ac 'P67-BMBT-EVICT-SKIP' "$OUT/dmesg_$n.txt")
  echo "  $n: ${wl:-no WRITER line} livelock=$ll convblk_deny=$deny shutdown=$shut stat_size=${live:-DEAD} iomap_nowait_refused=${refused:-na} write_checks_excl=${wcx:-na} iomap_iread_pr=${irp:-na} waitstall=$stall iread_mismatch=$mism torn_flush=$torn bmbt_evict=$evict leafwr=$leafwr unread_clean_skip=${uskip:-na} unread_local=${ulocal:-na} bmbt_write_unread=${bwu:-na} bmbt_evict_capped=${bec:-na} iflush_bmbt_capped=${ifc:-na} iflush_bmbt_notdone_needs=${ifn:-na} rel_bmbt_flushed=${rbf:-na} rel_bmbt_wedge=${rbw:-na} scan_stale_skip=${bss:-na} lookup_bad=${blb:-na} rel_evicted=${tee:-na} rel_busy=${teb:-na} rel_localwork=${tel:-na} evict_skip=$eskip crc=$crc"
  grep -a 'P975-BMBT-LOOKUP-BAD\|P975-REL-LOCALWORK\|P975-REL-WEDGE\|P975-EVICT-WEDGE' "$OUT/dmesg_$n.txt" | head -3 | cut -c1-330 | sed 's/^/    /'
  grep -a 'P73-WAITSTALL' "$OUT/dmesg_$n.txt" | head -2 | cut -c1-220 | sed 's/^/    /'
  grep -a 'EDEADLK retry livelock' "$OUT/dmesg_$n.txt" | head -2 | cut -c1-200 | sed 's/^/    /'
  [ -s "$OUT/stacks_$n.txt" ] && grep -a 'xfs_vn_update_time\|xfs_file_write_checks\|mxfs_dlm_ilock_begin\|xfs_file_dio_write' "$OUT/stacks_$n.txt" | sort | uniq -c | sed 's/^/    stack /'
  echo "$wl" | grep -q ' failed=0' || fail=1
  # A writer that completed no write at all measured nothing: on a gigabyte
  # span the preamble read alone ran the whole window on one node and the
  # lap still passed on the other node's writes (20260918T040220Z, test1
  # ok=0).  A pass needs both writers to have written.
  echo "$wl" | grep -q ' ok=0 ' && { echo "  FAIL $n: writer completed no write in ${S}s (the preamble read or a stall ate the window)"; fail=1; }
  [ "$ll" = 0 ] && [ "$shut" = 0 ] && [ "$stall" = 0 ] && [ "$mism" = 0 ] && [ "$torn" = 0 ] && [ "${bwu:-0}" = 0 ] && [ "$crc" = 0 ] && [ "${rbw:-0}" = 0 ] && [ "${blb:-0}" = 0 ] && [ "${teb:-0}" = 0 ] && [ "${tel:-0}" = 0 ] && [ -n "$live" ] || fail=1
done
if [ "$fail" = 0 ]; then
  ICK=; IT=20
  [ "$EXTEND" = 1 ] && { ICK="--wrote /src/mxfs/$OUT/writer_$A.txt /src/mxfs/$OUT/writer_$B.txt"; [ -s "$OUT/prefill_$A.txt" ] && ICK="$ICK /src/mxfs/$OUT/prefill_$A.txt"; IT=120; }
  for n in $A $B; do rs $IT "$n" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 /src/mxfs/tests/d0532_img_check.py $F $ICK" > "$OUT/img_$n.txt"; done
  ia=$(grep -a '^IMG' "$OUT/img_$A.txt"); ib=$(grep -a '^IMG' "$OUT/img_$B.txt")
  echo "  $A ${ia:0:300}"; echo "  $B ${ib:0:300}"
  if [ "$MIX" = 1 ]; then
    [ -n "$ia" ] && [ "${ia#* md5=}" = "${ib#* md5=}" ] || { echo "  FAIL the two nodes read different images"; fail=1; }
  else
    echo "$ia" | grep -q ' torn=0 ' && echo "$ib" | grep -q ' torn=0 ' && [ "${ia#* md5=}" = "${ib#* md5=}" ] || { echo "  FAIL images torn or different"; fail=1; }
  fi
  if [ "$EXTEND" = 1 ]; then
    # Every block either node wrote successfully must hold one node's byte,
    # every block nobody wrote must still read zero, and the file must reach
    # the highest block written — a lost allocation, size update or data
    # write shows here even when the two nodes agree on the image.  Each
    # node checks its own read (d0532_img_check.py --wrote).
    for n in $A $B; do
      ec=$(grep -a '^EXTCHK' "$OUT/img_$n.txt")
      echo "  $n ${ec:-no EXTCHK line}"
      echo "$ec" | grep -q ' lost=0 stray=0 short=0 ' && ! echo "$ec" | grep -q 'written=0 ' || { echo "  FAIL $n extending-write image check"; fail=1; }
    done
  fi
  rs 15 "$A" "rm -f $F" >/dev/null
fi
[ "$fail" = 0 ] || { echo "RESULT FAIL dwcd: wall=${W}s out=$OUT"; exit 1; }
echo "RESULT PASS dwcd: wall=${W}s out=$OUT"
exit 0
