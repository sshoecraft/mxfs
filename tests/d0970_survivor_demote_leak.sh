#!/bin/bash
# tests/d0970_survivor_demote_leak.sh <survivor> <peer> [writes] [label]
#
# D-0970 follow-up.  On a clustered mount every direct write now takes its
# checks with the IOLOCK exclusive and then demotes to shared, and the demote
# moves the DLM holder count EX->PR (mxfs_dlm_ilock_demote).  That function
# returns early whenever the cluster is currently single-node — but a sole
# survivor (a mount that HAS had a peer) takes real grants and counts holders
# in mxfs_dlm_ilock_begin.  If the demote skips there, the EX count is never
# moved, the shared unlock ends PR against a zero PR count (silently, single-
# node), and one EX holder leaks per write: the survivor can then never
# release the inode, so a returning peer's write to it waits for ever.
#
# Shape: the peer unmounts cleanly (survivor alone, ever-multi); the survivor
# does <writes> aligned O_DIRECT overwrites of a file; the peer remounts and
# does ONE aligned O_DIRECT write of that file, bounded.
# RESULT PASS  the peer's write completes within 30 s (a grant transfer is
#              milliseconds; 30 s is far past any legitimate wait), no
#              livelock/shutdown on either node, both read the same image.
# RESULT FAIL  the peer's write times out or fails, a shutdown, or images
#              differ.
# Reports the survivor's counters across its writes: demote_survivor (IOLOCK
# demotes performed there — must equal the writes) and end_unpaired_single
# (ends that found no holder — must be 0).  Measured before the fix: the
# demote was skipped on a survivor, 200 of 200 writes each left an EX count
# (end_unpaired_single=200), though the peer's later join dropped them.
# RESULT FAIL also on end_unpaired_single != 0 when the counter exists.
# budget: peer umount+mount (~10 s each, measured by prep), writes x 4 KiB
# direct (milliseconds each), the bounded 30 s peer write; whole arm 150 s.
set -u
cd /src/mxfs || exit 1
S=${1:?survivor}; P=${2:?peer}; N=${3:-200}; LABEL=${4:-svdl}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_svdl_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
F=$MNT/.svdl_$LABEL
MARK="SVDL-$LABEL-$$"
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $S $P; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL svdl: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL svdl: $MNT not mounted on $n"; exit 2; }
done
dev=$(rs 15 "$P" "awk '\$2==\"$MNT\" && \$3==\"mxfs\" {print \$1}' /proc/mounts")
opts=$(rs 15 "$P" "awk '\$2==\"$MNT\" && \$3==\"mxfs\" {print \$4}' /proc/mounts")
[ -n "$dev" ] || { echo "RESULT FAIL svdl: cannot read the peer's mount device"; exit 2; }
echo "=== d0970_survivor_demote_leak S=$S P=$P writes=$N sv=$want dev=$dev out=$OUT ==="
for n in $S $P; do rs 10 "$n" "echo $MARK > /dev/kmsg" >/dev/null; done
rs 20 "$S" "dd if=/dev/zero of=$F bs=64k count=1 oflag=direct status=none && sync && echo ok" | grep -q ok || { echo "RESULT FAIL svdl: setup write failed"; exit 2; }
um=$(rs 60 "$P" "timeout 50 umount $MNT && echo UMOUNT_OK")
echo "  peer umount: ${um:-FAILED}"
echo "$um" | grep -q UMOUNT_OK || { echo "RESULT FAIL svdl: peer umount failed"; exit 1; }
sleep 3
rs 10 "$S" "for c in demote_survivor end_unpaired_single; do echo 0 > /sys/module/mxfs/parameters/\$c 2>/dev/null; done" >/dev/null
w=$(rs 60 "$S" "python3 -c \"open('/tmp/svdl_blk','wb').write(b's'*4096)\"; ok=0; for i in \$(seq 1 $N); do dd if=/tmp/svdl_blk of=$F bs=4k seek=\$((i % 16)) count=1 conv=notrunc oflag=direct status=none && ok=\$((ok+1)); done; echo SURVIVOR ok=\$ok of $N")
echo "  $w"
cnt=$(rs 10 "$S" "for c in demote_survivor end_unpaired_single write_checks_excl; do printf '%s=%s ' \$c \$(cat /sys/module/mxfs/parameters/\$c 2>/dev/null || echo na); done")
echo "  survivor counters: $cnt"
eus=$(echo "$cnt" | sed -n 's/.*end_unpaired_single=\([0-9]*\).*/\1/p')
# Directory phase: creates, renames and removes on the survivor (the paths
# that pin a directory's EX with mxfs_dlm_dir_hold_ex and end it after the
# flush), counted separately.
rs 10 "$S" "echo 0 > /sys/module/mxfs/parameters/end_unpaired_single 2>/dev/null" >/dev/null
dw=$(rs 60 "$S" "d=$MNT/.svdl_dir_$LABEL; mkdir -p \$d && for i in \$(seq 1 50); do : > \$d/f\$i && mv \$d/f\$i \$d/g\$i && rm -f \$d/g\$i || echo DIROP_FAIL; done; rmdir \$d; echo DIROPS_DONE; printf 'end_unpaired_single=%s' \$(cat /sys/module/mxfs/parameters/end_unpaired_single 2>/dev/null || echo na)")
echo "  survivor dir phase: $(echo "$dw" | tr '\n' ' ')"
deus=$(echo "$dw" | sed -n 's/.*end_unpaired_single=\([0-9]*\).*/\1/p')
mt=$(rs 90 "$P" "timeout 80 mount -t mxfs -o $opts $dev $MNT && echo MOUNT_OK")
echo "  peer mount: ${mt:-FAILED}"
echo "$mt" | grep -q MOUNT_OK || { echo "RESULT FAIL svdl: peer remount failed"; exit 1; }
T0=$(date +%s%N)
pw=$(rs 40 "$P" "python3 -c \"open('/tmp/svdl_blk','wb').write(b'p'*4096)\"; timeout 30 dd if=/tmp/svdl_blk of=$F bs=4k seek=3 count=1 conv=notrunc oflag=direct status=none; echo PEERWRITE rc=\$?")
ms=$(( ($(date +%s%N) - T0) / 1000000 ))
echo "  $pw wall_ms=$ms"
fail=0
[ -z "$eus" ] || [ "$eus" = 0 ] || { echo "  FAIL survivor ends found no holder: end_unpaired_single=$eus"; fail=1; }
[ -z "$deus" ] || [ "$deus" = 0 ] || { echo "  FAIL survivor directory ops left unpaired ends: end_unpaired_single=$deus"; fail=1; }
echo "$dw" | grep -q DIROPS_DONE || { echo "  FAIL survivor directory phase did not complete"; fail=1; }
echo "$dw" | grep -q DIROP_FAIL && { echo "  FAIL a survivor directory op failed"; fail=1; }
echo "$pw" | grep -q 'PEERWRITE rc=0' || { echo "  FAIL the returning peer's write did not complete"; fail=1; }
for n in $S $P; do
  rs 30 "$n" "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/dmesg_$n.txt"
  sh=$(grep -ac 'Shutting down filesystem\|EDEADLK retry livelock\|P-SESSION-POISON' "$OUT/dmesg_$n.txt")
  echo "  $n: shutdown/livelock lines=$sh"
  [ "$sh" = 0 ] || fail=1
done
if [ "$fail" = 0 ]; then
  for n in $S $P; do rs 20 "$n" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 /src/mxfs/tests/d0532_img_check.py $F" > "$OUT/img_$n.txt"; done
  ia=$(cat "$OUT/img_$S.txt"); ib=$(cat "$OUT/img_$P.txt"); echo "  $S $ia"; echo "  $P $ib"
  [ -n "$ia" ] && [ "${ia#* md5=}" = "${ib#* md5=}" ] || { echo "  FAIL images differ"; fail=1; }
  rs 15 "$S" "rm -f $F" >/dev/null
fi
[ "$fail" = 0 ] || { echo "RESULT FAIL svdl: out=$OUT"; exit 1; }
echo "RESULT PASS svdl: peer write ${ms} ms after the survivor's $N writes, out=$OUT"
exit 0
