#!/bin/bash
# d0287_2node_death_rejoin.sh — the DEATH arm of
# D-TCP-MEMBERSHIP-CHANGE-PURGES-HELD-GRANTS-NO-RECONSTRUCTION-0287 at TWO
# nodes (the 1.0 ship shape: 2 nodes, TCP, one NAS LUN).
#
# Claim under test: on the TCP transport a membership change makes every node
# purge its DLM lock table and nothing re-asserts a survivor's HELD grants to
# the new master.  tests/d0287_remaster_measure.sh measured the clean-
# departure arm at 32 nodes (sess426, PASS).  This is the death arm, shaped
# for two nodes, where the requester IS the victim:
#
#   1. H writes F (32 KiB random), records md5_H, arms the D-512 T2 release
#      pausepoint on F (stage 1 = BEFORE the dirty-page flush, PAUSE_MS long),
#      re-dirties F.  H holds F's grant with unflushed pages.
#   2. W starts `md5sum F` (BAST -> H enters the pause).  W's read blocks.
#   3. Once H logs P-D512-RELPAUSE: virsh destroy W (real node death while
#      W's request is queued behind H's paused release).
#   4. H: death -> fence -> replay -> P163-RECOVERY-COMPLETE -> membership
#      change -> TABLE PURGE (the mechanism under test).
#   5. W is restarted, rejoins (prep_node.sh join; a second membership
#      change + purge) and reads F again — well before the pause ends.
#   6. Verdict: W's read completes ONLY after H's P-D512-RELPAUSE-END, with
#      md5_W == md5_H.  The defect is measured if W is served while H is
#      still paused (a master granted over H's live, unflushed tenure) or W
#      reads stale bytes.
#
# the budget rule (derived): setup ~10 s + pause entry <= 15 s + TCP death ~62 s +
# fence/replay/publish ~15 s + W reboot 40-90 s + rejoin ~30 s => W's second
# request lands ~170-220 s after setup.  PAUSE_MS=300000 keeps H paused past
# that with margin; correct behaviour returns W's read at ~300 s from setup.
# Caller bound 420 s.  A read that has not returned 60 s after the pause end
# is a FAIL (the D-0345-style stall), never a reason to wait longer.
#
# Usage: tests/d0287_2node_death_rejoin.sh <label> [H=test1] [W=test2]
# Env:   MXFS_DEV (default: the QNAP LUN by-path), MXFS_MNT, PAUSE_MS.
# Leaves both nodes mounted.  Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
H=${2:-test1}; W=${3:-test2}
PAUSE_MS=${PAUSE_MS:-300000}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0287_2node_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every
# capture a verdict is counted from crosses the boundary in the parent shell
# first; a failed acquisition is an ABORT, never a count of zero.  MXFS_DEV
# defaults to H's live mxfs mount (no rig's device path is assumed).
. "$(dirname "$0")/lib/rig.sh"
hd() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }   # polling only; never counted
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }

echo "=== d0287_2node_death_rejoin label=$LABEL H=$H W=$W pause_ms=$PAUSE_MS out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
for n in "$H" "$W"; do
    info=$(timeout 15 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' mxfs ' /proc/mounts)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"ft=1"* ]] || { echo "ABORT: $n not on TCP ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]] || { echo "ABORT: $n not mounted ($info)"; exit 2; }
done
mxfs_dev_resolve "$H"
DEV=$MXFS_DEV_RESOLVED
echo "  INFO device=$DEV (from $H's live mount)"
MARK="D0287B-$LABEL-$$"
for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done

# 1. H writes F, arms the pause, re-dirties.
F="$MNT/.d0287b_$LABEL.dat"
timeout 25 $SSH "$H" "
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd1_rc=\$? >&2; exit 1; }
    md5sum '$F' | cut -d' ' -f1
    ino=\$(stat -c %i '$F'); echo \$ino
    echo \$ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo $PAUSE_MS > $P/dbg_rel_pause_ms
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd2_rc=\$? >&2; exit 1; }
    md5sum '$F' | cut -d' ' -f1
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
md5_h=$(sed -n 3p "$OUT/h_setup.txt" | tr -dc 'a-f0-9')
ino=$(sed -n 2p "$OUT/h_setup.txt" | tr -dc '0-9')
[ -n "$md5_h" ] && [ -n "$ino" ] || {
    echo "ABORT: H setup failed: stdout=[$(tr '\n' ' ' < "$OUT/h_setup.txt")] stderr=[$(filt < "$OUT/h_setup.err" | tail -5 | tr '\n' ' ')]"
    exit 2; }
echo "  INFO ino=$ino md5_H=$md5_h at +$(el)s"

# 2. W's first read: blocks behind H's paused release; dies with W.
( timeout 120 $SSH "$W" "md5sum '$F' 2>&1 | cut -d' ' -f1" 2>/dev/null | filt | head -1 > "$OUT/w_first_md5.txt" ) &
WPID=$!
i=0; paused=0
while [ $i -lt 15 ]; do
    if hd "$H" | grep -aq "P-D512-RELPAUSE ino=$ino stage=1"; then paused=1; break; fi
    sleep 1; i=$((i+1))
done
ck "H entered the release-drain pause (BAST from W landed)" "$paused" "1"
if [ "$paused" != 1 ]; then
    kill $WPID 2>/dev/null
    timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1
    exit 1
fi
tpause=$(date +%s)

# 3. Kill W while its request is queued.
$VIRSH destroy "$W" >/dev/null 2>&1; echo "  INFO virsh destroy $W rc=$? at +$(el)s $(date -u +%T)"
tkill=$(date +%s)
kill $WPID 2>/dev/null; wait $WPID 2>/dev/null

# 4. H recovers W's death (bounded 150 s from the kill).
rec=0; i=0
while [ $i -lt 150 ]; do
    if hd "$H" | grep -aq 'P163-RECOVERY-COMPLETE'; then rec=1; break; fi
    sleep 3; i=$((i+3))
done
trec=$(( $(date +%s) - tkill ))
ck "H published P163-RECOVERY-COMPLETE for $W's death within 150s (took ${trec}s)" "$rec" "1"
measure "$H" 20 "$OUT/dmesg_${H}_recovered.txt" '^DMESG_END$' "the kernel log on $H after the recovery" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
memb=$(grep -ac 'MXFS-MEMBERSHIP\|purged .* stale locks\|update_active_nodes' "$OUT/dmesg_${H}_recovered.txt")
echo "  INFO $H membership-change lines after the kill: $memb"
ck "H still inside the pause after the recovery (no P-D512-RELPAUSE-END yet)" "$(grep -ac "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_${H}_recovered.txt")" "0"

# 5. W restarts and rejoins.
$VIRSH start "$W" >/dev/null 2>&1; echo "  INFO virsh start $W rc=$? at +$(el)s"
up=0
for i in $(seq 1 24); do
    timeout 8 $SSH "$W" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP && { up=1; break; }
    sleep 5
done
ck "$W back on ssh within 120s of the start" "$up" "1"
[ "$up" = 1 ] || { timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms" >/dev/null 2>&1; exit 2; }
# the preparation's own result record is required (prep_require): a
# NODE_PREP_FAIL, with its reason kept in the capture, is an ABORT, never a
# verdict about the pause
rsx 90 "$W" "mountpoint -q /src || mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh tcp 2>&1" > "$OUT/w_rejoin.txt"
prep_require "$OUT/w_rejoin.txt" "the rejoin preparation on $W"
ck "$W rejoined (NODE_PREP_OK)" "$(grep -ac '^NODE_PREP_OK' "$OUT/w_rejoin.txt")" "1"
trejoin=$(( $(date +%s) - tpause ))
echo "  INFO $W rejoined at +$(el)s (${trejoin}s into the ${PAUSE_MS}ms pause): $(grep -a 'NODE_PREP' "$OUT/w_rejoin.txt" | head -1 | cut -c1-160)"
if ! grep -aq '^NODE_PREP_OK' "$OUT/w_rejoin.txt"; then
    timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms" >/dev/null 2>&1
    exit 2
fi
timeout 12 $SSH "$W" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# 6. W's second read: must wait for H's pause to end.
remain=$(( PAUSE_MS / 1000 - trejoin + 60 ))
[ "$remain" -lt 90 ] && remain=90
s0=$(date +%s)
rsx "$remain" "$W" "md5sum '$F' 2>&1; echo md5_rc=\$?" > "$OUT/w_second_read.txt"
rrc=$?
# a read that ran out the bound (124) is the stall verdict below, not an ABORT
[ "$rrc" = 124 ] || capture_require "$OUT/w_second_read.txt" '^md5_rc=[0-9]+$' "W's second read of F"
tread=$(( $(date +%s) - s0 ))
# H's own clock the instant the read returned: the pause-end ordering is
# decided on H's dmesg stamps, never across two hosts' wall clocks.
h_up_at_return=$(timeout 10 $SSH "$H" "cut -d' ' -f1 /proc/uptime" 2>/dev/null | filt | tr -dc '0-9.')
# s517g: 'tr -dc a-f0-9' reduced an md5sum ERROR line to 'd5' and counted it
# as a returned digest.  Only a 32-hex token is a read.
md5_w=$(grep -aoE '^[0-9a-f]{32}' "$OUT/w_second_read.txt" | head -1)
sleep 5
measure "$H" 20 "$OUT/dmesg_$H.txt" '^DMESG_END$' "the kernel log on $H from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$W" 20 "$OUT/dmesg_$W.txt" '^DMESG_END$' "the kernel log on $W from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
ended=$(grep -ac "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_$H.txt")
end_ts=$(grep -a "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_$H.txt" | head -1 | sed -n 's/^\[ *\([0-9.]*\)\].*/\1/p')
# s517g: the capture raced the pause end (END stamped 4 s after the read
# returned and 0 lines were seen).  Order by H's timestamps instead.
end_before_read=$(awk -v e="${end_ts:-0}" -v u="${h_up_at_return:-0}" 'BEGIN{print (e>0 && u>0 && e<=u+1.0)?1:0}')
lkwait=$(grep -ac 'P-LKWAIT-LIVE' "$OUT/dmesg_$W.txt")
echo "  INFO W second read: wall=${tread}s (bound ${remain}s) rc=$rrc md5_W=${md5_w:-none} raw=[$(head -c 120 "$OUT/w_second_read.txt" | tr '\n' ' ')]; H pause-end seen=$ended end_ts=${end_ts:-none} h_up_at_return=${h_up_at_return:-none}; W P-LKWAIT-LIVE=$lkwait; pause was $(( $(date +%s) - tpause ))s old"
ck "W's read returned a digest (no stall past the pause, no error)" "$([ -n "$md5_w" ] && echo 1 || echo 0)" "1"
ck "W was NOT served while H's drain was still paused (H's pause-end stamp precedes W's read return on H's clock)" "$end_before_read" "1"
ck "W md5 == H md5 (no stale data served over H's unflushed tenure)" "$([ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
ck "W's read waited for the pause (>= $(( PAUSE_MS / 1000 - trejoin - 5 ))s)" "$([ "$tread" -ge $(( PAUSE_MS / 1000 - trejoin - 5 )) ] && echo 1 || echo 0)" "1"
for n in "$H" "$W"; do
    s=$(grep -aEc 'BUG:|Oops|Shutting down filesystem' "$OUT/dmesg_$n.txt"); ck "zero splats/shutdowns on $n" "$s" "0"
done
timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1
echo "=== d0287_2node_death_rejoin $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
