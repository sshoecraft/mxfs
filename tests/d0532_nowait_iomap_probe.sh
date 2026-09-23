#!/bin/bash
# tests/d0532_nowait_iomap_probe.sh <node> [ops] [label]
#
# D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532,
# the user-reachable members of the class.  xfs_ilock_nowait enters no DLM
# begin for ILOCK flags, and xfs_iunlock always runs mxfs_dlm_ilock_end, so a
# nowait ILOCK released by plain xfs_iunlock is an unpaired end: with no
# other holder it underflows (P71-UNDERFLOW); with one it silently consumes
# that holder's count, and the release pipeline then sees holders==0 under a
# live holder.  Two such sites were reachable from userspace:
#
#   xfs_ilock_for_iomap under IOMAP_NOWAIT.  MXFS never sets FMODE_NOWAIT, so
#     RWF_NOWAIT is refused at the syscall, but io_uring treats any file
#     opened O_NONBLOCK as nowait-capable and issues its first attempt with
#     IOCB_NOWAIT, which iomap turns into IOMAP_NOWAIT.  The DIO path already
#     holds the IOLOCK (a counted DLM holder), so the ILOCK's end consumed the
#     IOLOCK's count for the rest of the I/O.  tests/d0532_uring_nowait.c
#     drives it, compiled on the node.
#   mxfs_dirdump, run by a lookup of the magic name ".mxfs_dirdump1" in a
#     directory with data blocks: one nowait ILOCK_SHARED per block.
#
# Phases, each fenced by kmsg markers and bracketed by exact counters (reset
# to 0 before, read after) where the build exposes them:
#   ctl     bufw/dior/diow without O_NONBLOCK: the first attempt blocks
#           normally (control; must show P71=0)
#   bufw    buffered IORING_OP_WRITE, O_NONBLOCK -> xfs_buffered_write_iomap_begin
#           (not reachable on a 6.8 node kernel: io_uring's buffered nowait
#           needs FMODE_BUF_WASYNC there; reported, never required)
#   dior    O_DIRECT IORING_OP_READ, O_NONBLOCK  -> xfs_read_iomap_begin
#   diow    O_DIRECT overwrite, O_NONBLOCK       -> xfs_direct_write_iomap_begin
#   dsyncw  diow with O_DSYNC (the completion's sync tail, D-0971)
#   diou    O_DIRECT writes into fallocated unwritten blocks: every
#           completion converts an extent under ILOCK_EXCL (D-0971)
#   diox    O_DIRECT writes one block past EOF each: every completion
#           converts and moves the size under ILOCK_EXCL (D-0971)
#   iopoll  O_DIRECT reads on an IORING_SETUP_IOPOLL ring: a clustered mount
#           refuses polled direct I/O (D-0971)
#   dirdump stat of <dir>/.mxfs_dirdump1 on a multi-block directory
# REACHED is read from the kernel, never from userspace (io_uring retries an
# -EAGAIN first attempt from a worker, so a completed I/O proves nothing):
#   dior/diow/dsyncw/diou/diox
#              iomap_nowait_refused > 0 (the fix refused the nowait mapping
#              and io_uring reissued through the counted arm), or on a build
#              without that counter, P71 > 0 in the phase
#   diou/diox  additionally dioend_in_drain > 0: a completion began while a
#              release of the inode was in progress and the phase finished
#   iopoll     dio_hipri_refused > 0
#   dirdump    P10-DIRDUMP-BLK lines without MAPFAIL in the phase
# D-0971: every phase also fails on rel_dio_inflight > 0 (a release committed
# with this node's direct I/O in flight); rel_dio_waited, rel_dio_defer,
# dioend_* are reported.  PEER mode with rel_dio_wait=0 on the node under
# test is the control arm and is expected to fail on that count.
# P71 per phase is the p71_underflows counter where present, else the count
# of P71-UNDERFLOW lines (print-budgeted at 300 per load: a line count can
# only ever under-report).
#
# RESULT PASS          dior, diow and dirdump reached; P71=0 in every phase
#                      (control included); all I/O succeeded; no splat, no
#                      shutdown.
# RESULT FAIL          any P71, any failed I/O, a splat or a shutdown.
# RESULT INCONCLUSIVE  dior, diow or dirdump shows no kernel evidence of the
#                      path.
# P71 counts only while the cluster is multi-node: run on a joined mount.
#
# PEER=<node> (optional): grant conflicts.  For the length of the io_uring
# phases the peer loops O_DIRECT reads of the file and whole-block O_DIRECT
# writes of a 'p' pattern, so the node under test is BAST'd off its grant
# while its own I/O is in flight.  Afterwards both nodes drop caches and
# read the file: every 4 KiB block must be one uniform byte (no torn block)
# and the two nodes' images must be identical.  Adds FAIL on either.
# budget: 10 x ops (default 200) 4 KiB io_uring I/Os (milliseconds each
# against a cached grant, a grant transfer each under PEER; measured 14-17 s
# at ops=500 under PEER), 300 creates, one gcc of one small file; bounded at
# 180 s.
set -u
cd /src/mxfs || exit 1
V=${1:?node}; OPS=${2:-200}; LABEL=${3:-nowait}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0532nw_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
MARK="D0532NW-$LABEL-$$"
BIN=/tmp/d0532_uring_nowait
CNTS="p71_underflows iomap_nowait_refused rel_dio_inflight rel_dio_waited rel_dio_wait_max_us rel_dio_defer dioend_admit dioend_in_drain dioend_kthread dioend_task dio_hipri_refused"
echo "=== d0532_nowait_iomap_probe node=$V ops=$OPS out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
nsv=$(rs 15 "$V" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
[ "$nsv" = "$want" ] || { echo "RESULT FAIL d0532nw: $V srcversion '$nsv' != tree '$want'"; exit 2; }
rs 15 "$V" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532nw: $MNT not mounted on $V"; exit 2; }
cc_out=$(rs 60 "$V" "gcc -O2 -o $BIN /src/mxfs/tests/d0532_uring_nowait.c 2>&1 && echo CC_OK")
echo "$cc_out" | grep -q CC_OK || { echo "RESULT FAIL d0532nw: compile on $V failed: $(echo "$cc_out" | tail -3 | tr '\n' ' ')"; exit 2; }
F=$MNT/.d0532nw_$LABEL
D=$MNT/.d0532nw_dir_$LABEL
PEER=${PEER:-}
if [ -n "$PEER" ]; then
  rs 15 "$PEER" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532nw: $MNT not mounted on peer $PEER"; exit 2; }
fi
T0=$(date +%s)
rm -f "$OUT/peer.txt"
[ -n "$PEER" ] && { rs 175 "$PEER" "bash /src/mxfs/tests/d0532_peer_conflict.sh $F" > "$OUT/peer.txt" & PPID_LOOP=$!; }
o=$(rs 170 "$V" "set -u
P=/sys/module/mxfs/parameters
dd if=/dev/zero of=$F bs=64k count=1 oflag=direct status=none && sync || { echo SETUP_FAIL; exit 1; }
cat $F > /dev/null
mkdir -p $D && for i in \$(seq 1 300); do : > $D/entry_with_a_long_name_to_fill_dir_blocks_\$i; done; sync
ph() {
  name=\$1; shift
  for c in $CNTS; do [ -w \$P/\$c ] && echo 0 > \$P/\$c; done
  echo '$MARK-'\$name'-BEGIN' > /dev/kmsg
  \"\$@\"
  echo '$MARK-'\$name'-END' > /dev/kmsg
  printf 'CNT phase=%s' \$name
  for c in $CNTS; do printf ' %s=%s' \$c \"\$(cat \$P/\$c 2>/dev/null || echo na)\"; done
  echo
}
uring() { for m in \"\$@\"; do $BIN $F \$m $OPS; done; }
ph ctl uring ctl-bufw ctl-dior ctl-diow
ph bufw uring bufw
ph dior uring dior
ph diow uring diow
ph dsyncw uring dsyncw
ph diou uring diou
ph diox uring diox
ph iopoll uring iopoll
ph dirdump stat $D/.mxfs_dirdump1
if [ -n '$PEER' ]; then
  : > $F.stop
  for i in \$(seq 1 200); do [ -f $F.peerdone ] && break; sleep 0.1; done
  [ -f $F.peerdone ] || echo PEERDONE_MISSING
  sync; echo 3 > /proc/sys/vm/drop_caches
  python3 /src/mxfs/tests/d0532_img_check.py $F
fi
rm -rf $F $F.stop $F.peerdone $D
echo probe_done")
W=$(( $(date +%s) - T0 ))
echo "$o" > "$OUT/ops.txt"
img_fail=0
if [ -n "$PEER" ]; then
  wait "$PPID_LOOP"
  sed 's/^/  PEER /' "$OUT/peer.txt"
  echo "$o" | grep -a '^IMG' | sed "s/^/  $V /"
  vimg=$(echo "$o" | grep -a '^IMG'); pimg=$(grep -a '^IMG' "$OUT/peer.txt")
  pline=$(grep -a '^PEER ' "$OUT/peer.txt")
  echo "$o" | grep -q PEERDONE_MISSING && { echo "  FAIL peer never finished its image (handshake)"; img_fail=1; }
  echo "$vimg" | grep -q ' torn=0 ' || { echo "  FAIL image on $V: ${vimg:-missing}"; img_fail=1; }
  echo "$pimg" | grep -q ' torn=0 ' || { echo "  FAIL image on $PEER: ${pimg:-missing}"; img_fail=1; }
  [ -n "$vimg" ] && [ "${vimg#* md5=}" = "${pimg#* md5=}" ] || { echo "  FAIL the two nodes read different images"; img_fail=1; }
  echo "$pline" | grep -q ' failed=0' || { echo "  FAIL peer I/O: ${pline:-no PEER line}"; img_fail=1; }
  echo "$pline" | grep -q ' writes=0 ' && { echo "  FAIL peer made no conflicting write: $pline"; img_fail=1; }
fi
sleep 1
rs 30 "$V" "dmesg | sed -n \"/$MARK-ctl-BEGIN/,\\\$p\"" > "$OUT/dmesg_$V.txt"
[ -s "$OUT/dmesg_$V.txt" ] || { echo "RESULT FAIL d0532nw: empty dmesg capture from $V (cannot count)"; exit 2; }
echo "$o" | grep -a '^URING\|^CNT' | sed 's/^/  /'
fails=0; unreached=0; reldio_fails=0
for ph in ctl bufw dior diow dsyncw diou diox iopoll dirdump; do
  seg=$(sed -n "/$MARK-$ph-BEGIN/,/$MARK-$ph-END/p" "$OUT/dmesg_$V.txt")
  [ -n "$seg" ] || { echo "  FAIL phase=$ph: no marker pair in the capture"; fails=$((fails+1)); continue; }
  cl=$(echo "$o" | grep -a "^CNT phase=$ph ")
  cget() { echo "$cl" | sed -n "s/.* $1=\([0-9a-z]*\).*/\1/p"; }
  lines=$(printf '%s\n' "$seg" | grep -ac 'P71-UNDERFLOW')
  p71=$(cget p71_underflows); [ -n "$p71" ] && [ "$p71" != na ] || p71=$lines
  refused=$(cget iomap_nowait_refused); reldio=$(cget rel_dio_inflight)
  reldw=$(cget rel_dio_waited); reldwmax=$(cget rel_dio_wait_max_us)
  reldef=$(cget rel_dio_defer); dioadm=$(cget dioend_admit); hp=$(cget dio_hipri_refused)
  diodr=$(cget dioend_in_drain); diokt=$(cget dioend_kthread); diotk=$(cget dioend_task)
  sites=$(printf '%s\n' "$seg" | grep -ao 'P71-UNDERFLOW.*' | sed -n 's/.* mode=\([A-Z]*\) .*un=\([^ ]*\).*/\1@\2/p' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
  dblk=$(printf '%s\n' "$seg" | grep -a 'P10-DIRDUMP-BLK' | grep -avc 'MAPFAIL')
  echo "  INFO phase=$ph P71=$p71 (lines=$lines) nowait_refused=${refused:-na} rel_dio_inflight=${reldio:-na} rel_dio_waited=${reldw:-na} rel_dio_wait_max_us=${reldwmax:-na} rel_dio_defer=${reldef:-na} dioend_in_drain=${diodr:-na} dioend_kthread=${diokt:-na} dioend_task=${diotk:-na} dioend_admit=${dioadm:-na} dio_hipri_refused=${hp:-na} dirdump_blocks=$dblk ${sites:+sites=$sites}"
  [ "$p71" = 0 ] || fails=$((fails+1))
  # A release committed with this node's direct I/O still in flight
  # (D-0971) hands the peer a tenure that overlaps bios we are still
  # landing; measured 13-19 per lap before the fix, it fails the lap.
  [ -z "$reldio" ] || [ "$reldio" = na ] || [ "$reldio" = 0 ] || { echo "  FAIL phase=$ph: $reldio release(s) committed with direct I/O in flight"; reldio_fails=$((reldio_fails+1)); }
  case $ph in
    dior|diow|dsyncw)
      if [ -n "$refused" ] && [ "$refused" != na ]; then r=$refused; else r=$p71; fi
      [ "$r" -gt 0 ] || { echo "  UNREACHED phase=$ph (no kernel evidence the nowait mapping ran)"; unreached=$((unreached+1)); } ;;
    diou|diox)
      # every completion here converts an unwritten extent (diox also moves
      # the size) under ILOCK_EXCL; one that began while the inode's
      # release was in progress (dioend_in_drain) and returned — the
      # phase finished, the wait ended — is the measured progress path
      # (the kernel-thread fast path, or the registry admission for a
      # task-context completion: dioend_admit).  A phase in which no
      # completion met a release did not exercise it.
      if [ -n "$refused" ] && [ "$refused" != na ]; then r=$refused; else r=$p71; fi
      [ "$r" -gt 0 ] || { echo "  UNREACHED phase=$ph (no kernel evidence the nowait mapping ran)"; unreached=$((unreached+1)); }
      [ -n "$diodr" ] && [ "$diodr" != na ] && [ "$diodr" -gt 0 ] || { echo "  UNREACHED phase=$ph (no direct-write completion began during a release of the inode: dioend_in_drain=${diodr:-na} rel_dio_waited=${reldw:-na})"; unreached=$((unreached+1)); } ;;
    iopoll)
      [ -n "$hp" ] && [ "$hp" != na ] && [ "$hp" -gt 0 ] || { echo "  UNREACHED phase=iopoll (no polled direct I/O was refused: dio_hipri_refused=${hp:-na})"; unreached=$((unreached+1)); } ;;
    dirdump)
      [ "$dblk" -gt 0 ] || { echo "  UNREACHED phase=dirdump (no mapped P10-DIRDUMP-BLK line)"; unreached=$((unreached+1)); } ;;
  esac
done
ioerr=$(echo "$o" | grep -a '^URING' | grep -avc ' err=0 ')
splat=$(grep -aEc 'BUG:|Oops|WARNING: CPU' "$OUT/dmesg_$V.txt")
shut=$(grep -ac 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "$OUT/dmesg_$V.txt")
echo "  INFO wall=${W}s io_failures=$ioerr splat=$splat shutdown=$shut evidence=$OUT"
echo "$o" | grep -q probe_done || { echo "RESULT FAIL d0532nw: probe did not complete (wall=${W}s): $(echo "$o" | tail -3 | tr '\n' ' ')"; exit 1; }
[ "$fails" = 0 ] && [ "$reldio_fails" = 0 ] && [ "$ioerr" = 0 ] && [ "$splat" = 0 ] && [ "$shut" = 0 ] && [ "$img_fail" = 0 ] || { echo "RESULT FAIL d0532nw: phases_with_P71=$fails phases_with_rel_dio_inflight=$reldio_fails io_failures=$ioerr splat=$splat shutdown=$shut image_fail=$img_fail out=$OUT"; exit 1; }
[ "$unreached" = 0 ] || { echo "RESULT INCONCLUSIVE d0532nw: $unreached phase(s) show no kernel evidence of their path out=$OUT"; exit 3; }
echo "RESULT PASS d0532nw: dior, diow and dirdump reached, P71=0 in every phase${PEER:+, under peer conflicts from $PEER with identical untorn images}, wall=${W}s out=$OUT"
exit 0
