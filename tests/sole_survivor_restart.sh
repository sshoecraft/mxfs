#!/bin/bash
# sole_survivor_restart.sh — the whole cluster loses power; only ONE node comes
# back.  Does the survivor mount, and is the data both nodes had fsynced still
# there and correct?
#
# WHY THIS SHAPE HAS NO HARNESS YET, AND WHY IT MATTERS MOST.  Every
# whole-cluster restart harness on this rig brings BOTH nodes back together,
# and that is the easy case: each victim is a previous boot of a host that is
# live again, so BOOT_SUCCESSION_ABSENT (fence kind 21) proves exclusion
# immediately and no harder question is ever asked.  Measured directly — the
# s587a lap's journals show kind 21 on both nodes and both mounts completing.
# A single returning node cannot use that proof for its ABSENT peer: that
# host is not back, so nothing about it can be inferred from its own boot.
#
# Two open records converge on exactly this lap:
#
#   D-...-0927 owes "a shape in which a node genuinely becomes the bootstrap
#   owner, so mxfs_dlm_takeover_orphans runs" — and records that on a
#   both-nodes-return restart the sweep is unreachable BY CONSTRUCTION, since
#   dlm_bootstrap_node returns this node only when the mount is the bootstrap
#   OWNER (the total-outage adoption path) and a boot-succession-resolved
#   restart elects no owner at all.  One node returning IS a total outage from
#   that node's point of view, so this is the candidate shape.  If the sweep
#   still does not run here, that is the finding the record asks for: the
#   sweep is dead code on a two-node configuration.
#
#   D-...-437 says a whole-cluster crash leaves each rebooted host's previous
#   PR key on its I_T nexus and no node can mount again without an operator.
#   On the QNAP target a registration is purged with its iSCSI session, so the
#   survivor finds its peer's key ABSENT and must classify that without help.
#
# NOTHING IS INJECTED.  No knob is armed and no view is forced.  The nodes are
# destroyed with their mounts in flight, which is what a power cut does, and
# one of them is simply not started again.  Every heartbeat record, PR key,
# ledger page and journal slice the survivor meets was written by a real mount.
#
# THE DATA CHECK IS THE POINT, NOT THE MOUNT.  A mount that completes over a
# slice it silently discarded is worse than a mount that refuses.  Both nodes
# write and fsync a numbered file set before the crash; the survivor must read
# back EVERY file BOTH nodes acknowledged, with the right content.  Files the
# peer wrote are the ones that can only arrive through foreign replay of its
# dead slice, so they are scored separately from the survivor's own.
#
# the budget rule (derived, not rounded).  prep 45 s measured (bound 300); write+fsync
# of 2x60 small files ~5 s (bound 60); destroy 10 s; one VM boots ~60 s (bound
# 150); the survivor's mount pays the 62 s ghost dead-window before it may
# declare its peer dead, then fence certify and replay — measured 86 s on the
# both-return shape, so expect 90-130 s here and bound it at 300 (a mount that
# needs longer has failed, and the pre-fix shape of the records above does not
# return at all); verify 10 s; the peer's later rejoin boots 60 + mounts ~30
# (bound 150).  Expect ~380 s; wrapper 900 s.
#
# Usage: tests/sole_survivor_restart.sh <label>
# Env:   MXFS_NODE_LIST, MXFS_DEV, MXFS_MODARGS, NF (files per node, default
#        60), JOIN_BOUND (default 300), REJOIN (default 1 — bring the peer
#        back at the end; set 0 to leave the survivor alone).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
NF=${NF:-60}
JOIN_BOUND=${JOIN_BOUND:-300}
REJOIN=${REJOIN:-1}
D=$MNT/.sole_survivor
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_solesurv_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
ckle() { if [ "${2:-999999}" -le "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 <= $3)"; else echo "  FAIL $1 got=${2:-?} want<=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/cnt/capture_require/require_epoch/ensure_src_or_abort/
# mxfs_dev_resolve (tests/lib/rig.sh): every capture a verdict is taken from
# is proven to hold its tool's shape first; a failed acquisition is an
# ABORT, never a count of zero.  MXFS_DEV: resolved on A (its live mount if
# any, else the MXFS_TRANSPORT rig default); no rig's device is assumed.
. "$(dirname "$0")/lib/rig.sh"
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
boot_wait() {   # <node> <max_polls>
    local w=0
    until [ "$(timeout 15 $SSH "$1" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge "$2" ]; do
        w=$((w+1)); sleep 5
    done
    echo "$w"
}
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== sole_survivor_restart label=$LABEL survivor=$A absent=$B sv=$SV nf=$NF join_bound=${JOIN_BOUND}s rejoin=$REJOIN $(date -u +%FT%TZ) ==="
s0=$(date +%s)

for n in $A $B; do boot_wait "$n" 24 > /dev/null; done
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s0 ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
value_now_into rv1 "$A" 30 "$OUT/rv_rv1_1.txt" '^[0-9A-F]+$' "rv1 on $A" 'cat /sys/module/mxfs/srcversion 2>/dev/null'
ck "the rig runs this build" "$rv1" "$SV"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL wrong build evidence=$OUT"; exit 2; }

# Both nodes write and FSYNC their own file set.  Content is derived from the
# name so it can be checked without a sidecar, and the fsync is what makes the
# later read-back an integrity assertion rather than a cache hit.
rs 120 "$A" "mkdir -p $D && sync" > /dev/null
for n in $A $B; do
    # dd conv=fsync is the acknowledgement: it returns only after the data is
    # on the LUN, so a file counted here was durably promised before the crash.
    rs 120 "$n" "H=\$(hostname); ok=0; for i in \$(seq 1 $NF); do f=$D/\${H}_\$i; printf '%s:%s:%s\\n' \"\$H\" \"\$i\" 'mxfs-sole-survivor' | dd of=\$f conv=fsync status=none 2>/dev/null && ok=\$((ok+1)); done; sync; echo ACKED=\$ok" > "$OUT/${n}_write.txt" &
done
wait
AW=$(field "$OUT/${A}_write.txt" ACKED); BW=$(field "$OUT/${B}_write.txt" ACKED)
echo "STAGE write acked A=$AW B=$BW wall=$(( $(date +%s) - s0 ))s"
ck "survivor acked its whole file set"   "$AW" "$NF"
ck "absent peer acked its whole file set" "$BW" "$NF"
# The directory must be durable on the LUN before the crash, or the read-back
# below is asserting against files no node ever promised.
rs 60 "$A" "sync" > /dev/null

# The power cut.  Both nodes die with mounts in flight; only A is started.
for n in $A $B; do timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1; done
echo "STAGE crash both destroyed wall=$(( $(date +%s) - s0 ))s"
timeout 30 virsh -c qemu:///system start "$A" > /dev/null 2>&1
w=$(boot_wait "$A" 30)
echo "STAGE survivor booted (polls=$w) wall=$(( $(date +%s) - s0 ))s"
ck "the absent peer is NOT running" \
   "$(timeout 30 virsh -c qemu:///system domstate "$B" 2>/dev/null | tr -d ' \n')" "shutoff"

MD5=$(md5sum mxfs.ko | cut -c1-32)
ensure_src_or_abort "$A"
measure "$A" 60 "$OUT/A_md5.txt" '^[0-9a-f]{32}$' "the module copy on $A" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
ck "$A runs the tree build (md5)" "$(head -1 "$OUT/A_md5.txt")" "$MD5"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "STAGE device=$MXFS_DEV"

MARK=$(rsx 30 "$A" 'date +%s' | tail -1)
require_epoch "$MARK" "$A's clock mark before the survivor mount"
measure "$A" $((JOIN_BOUND + 60)) "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the survivor mount on $A" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
echo "STAGE survivor join rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms total=$(( $(date +%s) - s0 ))s"

# Read back BEFORE anything else touches the filesystem.
measure "$A" 180 "$OUT/A_read.txt" '^LISTED=[0-9]+$' "the read-back on $A" "own=0; peer=0; bad=0; miss=0; for i in \$(seq 1 $NF); do for h in $A $B; do f=$D/\${h}_\$i; if [ -r \$f ]; then if [ \"\$(cat \$f 2>/dev/null)\" = \"\${h}:\${i}:mxfs-sole-survivor\" ]; then [ \$h = $A ] && own=\$((own+1)) || peer=\$((peer+1)); else bad=\$((bad+1)); fi; else miss=\$((miss+1)); fi; done; done; echo OWN=\$own; echo PEER=\$peer; echo BAD=\$bad; echo MISS=\$miss; echo LISTED=\$(ls $D 2>/dev/null | grep -c .)"
echo "STAGE readback own=$(field "$OUT/A_read.txt" OWN) peer=$(field "$OUT/A_read.txt" PEER) bad=$(field "$OUT/A_read.txt" BAD) miss=$(field "$OUT/A_read.txt" MISS) listed=$(field "$OUT/A_read.txt" LISTED)"

measure "$A" 120 "$OUT/A_journal.txt" 'kernel: ' "the kernel journal on $A across the survivor mount" "journalctl -k --since=@$MARK --no-pager -o short-iso 2>/dev/null | tail -4000"

echo "--- survivor mount"
ck   "the survivor's mount completed"       "$(grep -ac '^MOUNTED' "$OUT/A_join.txt")" "1"
ck   "the survivor's mount returned rc=0"   "$(field "$OUT/A_join.txt" MOUNT_RC)" "0"
ckle "the survivor's mount was inside the bound (ms)" "$(field "$OUT/A_join.txt" WALL_MS)" "$((JOIN_BOUND * 1000))"
ck   "zero shutdown / BUG / Oops on the survivor" \
     "$(grep -ac 'BUG:\|Oops\|Internal error\|Shutting down filesystem\|kernel BUG' "$OUT/A_journal.txt")" "0"

echo "--- data integrity (the point of the lap)"
ck "every file the survivor fsynced reads back correctly" "$(field "$OUT/A_read.txt" OWN)"  "$NF"
ck "every file the ABSENT peer fsynced reads back correctly (foreign replay of its dead slice)" \
   "$(field "$OUT/A_read.txt" PEER)" "$NF"
ck "no file read back with wrong content"  "$(field "$OUT/A_read.txt" BAD)"  "0"
ck "no acknowledged file is missing"       "$(field "$OUT/A_read.txt" MISS)" "0"

echo "--- what the survivor did about its absent peer (D-0927 item 2 / D-437)"
echo "    fence kinds:        $(grep -ao 'kind=[A-Z_]*([0-9]*)' "$OUT/A_journal.txt" | sort | uniq -c | tr '\n' ' ')"
echo "    P-TAUTH-ORPHAN-SWEEP=$(cnt "$OUT/A_journal.txt" 'P-TAUTH-ORPHAN-SWEEP') P-TAUTH-ORPHAN-AUTH=$(cnt "$OUT/A_journal.txt" 'P-TAUTH-ORPHAN-AUTH') P-DEPART-WORK-ORPHAN-SWEEP=$(cnt "$OUT/A_journal.txt" 'P-DEPART-WORK-ORPHAN-SWEEP')"
echo "    bootstrap:          $(grep -ao 'bootstrap[^ ]*' "$OUT/A_journal.txt" | sort | uniq -c | head -6 | tr '\n' ' ')"
echo "    parked/stranded:    P-TAUTH-REMASTER-PARKED=$(cnt "$OUT/A_journal.txt" 'P-TAUTH-REMASTER-PARKED') P-TAUTH-PAGE-PARKED=$(cnt "$OUT/A_journal.txt" 'P-TAUTH-PAGE-PARKED') lock-request-failed=$(cnt "$OUT/A_journal.txt" 'lock request failed after')"
echo "    replay:             foreign-complete=$(cnt "$OUT/A_journal.txt" 'foreign replay of slot .* complete') recovery-complete=$(cnt "$OUT/A_journal.txt" 'P163-RECOVERY-COMPLETE') NOT-replayed=$(cnt "$OUT/A_journal.txt" 'NOT replayed')"
ck "the survivor exhausted no lock-request budget" "$(cnt "$OUT/A_journal.txt" 'lock request failed after')" "0"
ckge "the absent peer's dead slice was recovered" "$(cnt "$OUT/A_journal.txt" 'P163-RECOVERY-COMPLETE')" "1"

if [ "$REJOIN" = 1 ]; then
    timeout 30 virsh -c qemu:///system start "$B" > /dev/null 2>&1
    w=$(boot_wait "$B" 30)
    ensure_src_or_abort "$B"
    measure "$B" 60 "$OUT/B_md5.txt" '^[0-9a-f]{32}$' "the module copy on $B" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    BMARK=$(rsx 30 "$B" 'date +%s' | tail -1)
    require_epoch "$BMARK" "$B's clock mark before its rejoin"
    measure "$B" $((JOIN_BOUND + 60)) "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the rejoin of $B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
    measure "$B" 180 "$OUT/B_read.txt" '^BAD=[0-9]+$' "the read-back on $B" "ok=0; bad=0; for i in \$(seq 1 $NF); do for h in $A $B; do f=$D/\${h}_\$i; if [ \"\$(cat \$f 2>/dev/null)\" = \"\${h}:\${i}:mxfs-sole-survivor\" ]; then ok=\$((ok+1)); else bad=\$((bad+1)); fi; done; done; echo OK=\$ok; echo BAD=\$bad"
    measure "$B" 120 "$OUT/B_journal.txt" 'kernel: ' "the kernel journal on $B across its rejoin" "journalctl -k --since=@$BMARK --no-pager -o short-iso 2>/dev/null | tail -4000"
    echo "--- the peer rejoins (polls=$w)"
    echo "STAGE rejoin rc=$(field "$OUT/B_join.txt" MOUNT_RC) wall=$(field "$OUT/B_join.txt" WALL_MS)ms"
    ck "the returning peer's mount completed" "$(grep -ac '^MOUNTED' "$OUT/B_join.txt")" "1"
    ck "the returning peer sees every file"   "$(field "$OUT/B_read.txt" OK)" "$((NF * 2))"
    ck "the returning peer sees no wrong content" "$(field "$OUT/B_read.txt" BAD)" "0"
    ck "zero shutdown / BUG / Oops on the returning peer" \
       "$(grep -ac 'BUG:\|Oops\|Internal error\|Shutting down filesystem\|kernel BUG' "$OUT/B_journal.txt")" "0"
fi

echo "RESULT: $([ $fails = 0 ] && echo PASS || echo FAIL) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
