#!/bin/bash
# crossnode_unlink_ubsweep.sh — D-CROSSNODE-OPEN-UNLINK-DATA-LOSS sess389
# item (1)+(2): a cleanly departed slot's DEFERRED open-unlink zombies must
# be re-drivable by ANY node, not only by a remount of that slot.
#
# Code claim (sess419 read): the unclaimed-bucket sweep
# (xfs_mxfs_dlm.c mxfs_unclaimed_bucket_scan, P99-UBSWEEP-*) is armed as a
# reap duty at EVERY mount settle (MXFS_REAPF_UBSCAN, +5 s) and after every
# recovery batch; it takes the on-disk recovery guard for each non-empty
# bucket whose slot nobody claims and re-drives it through the C8 survivor
# sweep (P97-SWEEP-AG walked=N) -> normal ADOPTED inactivation -> P89-REAP-DONE.
# Nodes that are ALREADY mounted have cleared that duty long ago, so with
# nothing new mounting the zombies do persist (what sess389 saw after a
# full-cluster unmount) — the claim under test is that the NEXT mount of any
# other node frees them.
#
# Shape (32/caw, all mounted): U=test1 unlinker, holders H1=test2 H2=test4,
# joiner J=test3 (unmounted before the unlink so its later mount is fresh).
#   1. J unmounts.  U creates 3 files; each H opens one and HOLDS the fd
#      (pidfile'd sleep).  U unlinks all 3 -> P87-OPEN-DEFER on U (peer
#      open bits), zombies stay on U's slot bucket.
#   2. U unmounts cleanly -> P89-REAP-UNMOUNT-PENDING on U; U's slot is
#      released (unclaimed).  Holders close (P91-OPEN-EAGER-CLEAR on H).
#   3. J mounts.  Within the reap window J must log P99-UBSWEEP-START for
#      U's old slot, P97-SWEEP-AG walked>=1, P99-UBSWEEP-DONE rc=0, and a
#      P89-REAP-DONE / free for each of the 3 inos.
#   4. Platter oracle: full parallel unmount of the fleet, then
#      tools/chk_mxfs -v on the LUN must report 0 on unlinked buckets.
#      (The caller preps afterwards.)
#
# the budget rule (derived): J umount 30 s + setup 15 s + U umount 30 s + J mount
# ~15 s + reap window <= 5 s first + one 30 s retry => 60 s + 31 parallel
# umounts <= 120 s (d526 measured) + chk 60 s => ~330 s.  Caller bound 400 s.
#
# Usage: tests/crossnode_unlink_ubsweep.sh <label> [U] [H1] [H2] [J] [nodes]
set -u
LABEL=${1:?label}; U=${2:-test1}; H1=${3:-test2}; H2=${4:-test4}; J=${5:-test3}; NODES=${6:-32}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$U"; DEV=$MXFS_DEV_RESOLVED
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ubsweep
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/window_count_into (tests/lib/rig.sh): every count a verdict
# is taken from is acquired into its own file and validated in the parent
# shell first; a failed ssh is an ABORT, never a count of zero.  Adopted by
# reading (a 4-node harness: no fault/healthy lap on the 2-node rig).
. "$(dirname "$0")/lib/rig.sh"
# cnt: POLLING ONLY (the sweep-done wait); never feeds a verdict
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }
t0=$(date +%s)

echo "=== crossnode_unlink_ubsweep label=$LABEL U=$U H=$H1,$H2 J=$J nodes=$NODES out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $U $H1 $H2 $J; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
done
MARK="UBS-$LABEL-$$"
for n in $U $H1 $H2 $J; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done

# 1. J leaves first (its later mount must be a FRESH settle)
value_now_into rv1 "$J" 60 "$OUT/rv_rv1_1.txt" '^rc=' "rv1 on $J" "timeout 45 umount $MNT; echo rc=\$?"; rv1=$(printf '%s\n' "$rv1" | sed -n 's/^rc=//p')
ck "J=$J unmounted before the unlink" "$rv1" "0"
D="$MNT/.ubs_$LABEL"
rs 30 "$U" "mkdir -p $D && for i in 1 2 3; do dd if=/dev/urandom of=$D/f\$i bs=4096 count=1 2>/dev/null; done; sync; for i in 1 2 3; do stat -c %i $D/f\$i; done" > "$OUT/inos.txt"
ino1=$(sed -n 1p "$OUT/inos.txt" | tr -dc '0-9'); ino2=$(sed -n 2p "$OUT/inos.txt" | tr -dc '0-9'); ino3=$(sed -n 3p "$OUT/inos.txt" | tr -dc '0-9')
[ -n "$ino1" ] && [ -n "$ino2" ] && [ -n "$ino3" ] || { echo "ABORT: U setup failed: $(cat "$OUT/inos.txt")"; exit 2; }
echo "  INFO inos=$ino1,$ino2,$ino3"
# sess420 fix: the recorded pid MUST be the process holding fd 3.  The first
# cut recorded the sh and left `sleep` as a child holding the fd, so the
# later `kill` never closed the file: no last close, no P91, open bit left
# set on the platter, zombies un-reapable, holder umounts busy (rc=32) — all
# nine s419 FAILs.  `exec sleep` keeps the pid and the inherited fd.
# hold_into <var> <node> <file>: the holder's pid across the boundary (a
# node that did not answer is an ABORT, never an empty pid)
hold_into() { value_now_into "$1" "$2" 20 "$OUT/hold_$2.txt" '^[0-9]+$' "the holder pid on $2" "nohup setsid sh -c 'echo \$\$ > /tmp/ubs_hold.pid; exec 3<$D/$3; exec sleep 300' >/dev/null 2>&1 & sleep 1; cat /tmp/ubs_hold.pid"; }
hold_into p1 "$H1" f1; hold_into p2 "$H2" f2
ck "holders armed ($H1 pid=$p1 f1, $H2 pid=$p2 f2)" "$([ -n "$p1" ] && [ -n "$p2" ] && echo ok || echo none)" "ok"
sleep 2
value_now_into rv2 "$U" 30 "$OUT/rv_rv2_2.txt" '^rc=' "rv2 on $U" "rm -f $D/f1 $D/f2 $D/f3 && sync && echo rc=0 || echo rc=1"; rv2=$(printf '%s\n' "$rv2" | sed -n 's/^rc=//p')
ck "U unlinked the 3 files" "$rv2" "0"
sleep 3
window_count_into wc1 "$U" 20 "$MARK" 'P87-OPEN-DEFER' "U deferred the open-held frees (P87-OPEN-DEFER >= 1)"
ck "U deferred the open-held frees (P87-OPEN-DEFER >= 1)" "$([ "$wc1" -ge 1 ] && echo yes || echo no)" "yes"
window_count_into wc2 "$U" 20 "$MARK" 'P87-OPEN-DEFER-ERR' "U no open-bitmap read errors (P87-OPEN-DEFER-ERR)"
ck "U no open-bitmap read errors (P87-OPEN-DEFER-ERR)" "$wc2" "0"

# 2. U departs cleanly with the zombies pending; holders then close
uslot=$(rs 15 "$U" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | grep -o '[0-9]*\$'" | tr -dc '0-9')
value_now_into rv3 "$U" 90 "$OUT/rv_rv3_3.txt" '^rc=' "rv3 on $U" "timeout 60 umount $MNT; echo rc=\$?"; rv3=$(printf '%s\n' "$rv3" | sed -n 's/^rc=//p')
ck "U unmounted cleanly" "$rv3" "0"
window_count_into wc3 "$U" 20 "$MARK" 'P89-REAP-UNMOUNT-PENDING' "U left its zombies durable (P89-REAP-UNMOUNT-PENDING >= 1)"
ck "U left its zombies durable (P89-REAP-UNMOUNT-PENDING >= 1)" "$([ "$wc3" -ge 1 ] && echo yes || echo no)" "yes"
rs 15 "$H1" "kill $p1 2>/dev/null; true" >/dev/null; rs 15 "$H2" "kill $p2 2>/dev/null; true" >/dev/null
sleep 3
window_count_into wc4 "$H1" 20 "$MARK" 'P91-OPEN-EAGER-CLEAR' "H1 last close published (P91-OPEN-EAGER-CLEAR)"
ck "$H1 last close published (P91-OPEN-EAGER-CLEAR)" "$([ "$wc4" -ge 1 ] && echo yes || echo no)" "yes"
window_count_into wc5 "$H2" 20 "$MARK" 'P91-OPEN-EAGER-CLEAR' "H2 last close published (P91-OPEN-EAGER-CLEAR)"
ck "$H2 last close published (P91-OPEN-EAGER-CLEAR)" "$([ "$wc5" -ge 1 ] && echo yes || echo no)" "yes"

# 3. a DIFFERENT node mounts: its settle duty must sweep U's unclaimed bucket
rs 12 "$J" "echo '$MARK' > /dev/kmsg" >/dev/null
value_now_into rv4 "$J" 120 "$OUT/rv_rv4_4.txt" '^rc=' "rv4 on $J" "timeout 90 mount -t mxfs $DEV $MNT; echo rc=\$?"; rv4=$(printf '%s\n' "$rv4" | sed -n 's/^rc=//p')
ck "J mounted" "$rv4" "0"
i=0; done_n=0
while [ $i -lt 75 ]; do
    done_n=$(( $(cnt "$J" 'P99-UBSWEEP-DONE') + $(cnt "$J" 'P98-ORPHAN-SCAN-DONE') ))
    [ "${done_n:-0}" -ge 1 ] && break
    sleep 5; i=$((i+5))
done
echo "  INFO J ubsweep done after ~${i}s (slot of U was ${uslot:-unknown}; J slot=$(rs 12 "$J" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | grep -o '[0-9]*$'"))"
# sess436: J may CLAIM U's freed slot itself (s436f: U slot 0, J claimed slot 0)
# — then U's bucket is J's OWN bucket and the residue is re-driven by the
# own-rescan (P96-OWN-RESCAN / P98-ORPHAN-SCAN-DONE) instead of the
# unclaimed-bucket sweep (P99).  Either path must reap the zombies.
window_count_into wc6 "$J" 20 "$MARK" 'P99-UBSWEEP-START' "J re-drove U s bucket (P99-UBSWEEP-START or P96-OWN-RESCAN)"
window_count_into wc7 "$J" 20 "$MARK" 'P96-OWN-RESCAN' "J re-drove U s bucket (P99-UBSWEEP-START or P96-OWN-RESCAN)"
ck "J re-drove U's bucket (P99-UBSWEEP-START or P96-OWN-RESCAN)" "$([ $(( $wc6 + $wc7 )) -ge 1 ] && echo yes || echo no)" "yes"
window_count_into wc8 "$J" 20 "$MARK" 'P99-UBSWEEP-DONE slot=[0-9]* rc=0' "J s re-drive completed (P99-UBSWEEP-DONE rc=0 or P98-ORPHAN-SCAN-DONE)"
window_count_into wc9 "$J" 20 "$MARK" 'P98-ORPHAN-SCAN-DONE' "J s re-drive completed (P99-UBSWEEP-DONE rc=0 or P98-ORPHAN-SCAN-DONE)"
ck "J's re-drive completed (P99-UBSWEEP-DONE rc=0 or P98-ORPHAN-SCAN-DONE)" "$([ $(( $wc8 + $wc9 )) -ge 1 ] && echo yes || echo no)" "yes"
window_into "$OUT/rv_rv5_5.txt" "$J" 20 "$MARK"; rv5=$(cat "$OUT/rv_rv5_5.txt" | grep -a 'P97-SWEEP-AG' | grep -avc 'walked=0')
ck "J walked zombies (P97-SWEEP-AG walked>=1)" "$([ "$rv5" -ge 1 ] && echo yes || echo no)" "yes"
sleep 10
for ino in $ino1 $ino2; do
    window_count_into wc10 "$J" 20 "$MARK" "P89-REAP-DONE ino=$ino" "ino  ino reaped on J (P89-REAP-DONE)"
    ck "ino $ino reaped on J (P89-REAP-DONE)" "$([ "$wc10" -ge 1 ] && echo yes || echo no)" "yes"
done
# sess436: the third file has NO holder, so U frees it at unlink time (P82-REM
# on U) — it never becomes a zombie for J to reap.
window_count_into wc11 "$U" 20 "$MARK" "P82-REM ino=$ino3 " "ino  ino3 (no holder) freed on U at unlink (P82-REM)"
ck "ino $ino3 (no holder) freed on U at unlink (P82-REM)" "$([ "$wc11" -ge 1 ] && echo yes || echo no)" "yes"
for n in $U $H1 $H2 $J; do measure "$n" 20 "$OUT/dmesg_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"; ck "zero splats on $n" "$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$n.txt")" "0"; done

# 4. platter oracle: everyone off, chk counts unlinked-bucket residents
for i in $(seq 1 "$NODES"); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | filt | tail -1 > "$OUT/um_test$i.txt" ) &
done
wait
um_bad=$(grep -L 'rc=0' "$OUT"/um_test*.txt 2>/dev/null | wc -l)
ck "fleet unmounted cleanly for the oracle" "$um_bad" "0"
# sess420 fix: chk runs ON CLYDE, where the LUN is the SCST backing image, not
# the nodes' multipath device (s419: "cannot open /dev/mapper/mpatha").
HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
timeout 120 tools/chk_mxfs -v "$HOST_IMG" > "$OUT/chk.txt" 2>&1; chkrc=$?
# the oracle's own structural line is the shape: without it (image absent,
# tool missing, timeout) nothing was measured and a zero ERROR count is not
# a verdict
[ "$chkrc" != 124 ] || { echo "ABORT: chk_mxfs ran out its 120 s bound; nothing was measured"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; exit 2; }
capture_require "$OUT/chk.txt" 'unlinked buckets|bucketed zombies' "chk_mxfs -v on the backing image"
bucketed=$(grep -ao '[0-9]* on unlinked buckets\|[0-9]* bucketed zombies' "$OUT/chk.txt" | head -1 | tr -dc '0-9')
echo "  INFO chk rc=$chkrc: $(grep -a 'unlinked buckets\|bucketed zombies' "$OUT/chk.txt" | head -1)"
ck "platter: ZERO inodes left on unlinked buckets" "${bucketed:-unparsed}" "0"
ck "chk_mxfs reports no ERROR" "$(grep -ac 'ERROR' "$OUT/chk.txt")" "0"
echo "=== crossnode_unlink_ubsweep $LABEL: fails=$fails total=$(( $(date +%s) - t0 ))s out=$OUT ==="
echo "NOTE: fleet is unmounted — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
