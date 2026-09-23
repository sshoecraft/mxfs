#!/bin/sh
# d0287_remaster_measure.sh — instrumented step-2 MEASUREMENT for
# D-TCP-MEMBERSHIP-CHANGE-PURGES-HELD-GRANTS-NO-RECONSTRUCTION-0287.
#
# Claim under test (code-read, sess418): on the TCP transport a membership
# change makes every node purge its ENTIRE DLM lock table (dlm.c
# mxfs_dlm_update_active_nodes) and nothing re-asserts a survivor's HELD
# grants to the new masters (v5_membership_cb_tcp is a no-op).  So a holder
# H that is mid-tenure when a third node dies is, to the new master, holding
# nothing: the next request for H's resource is granted at once — and a
# shared-mode (read) request is not even settle-gated.
#
# Shape (32/tcp; H, W, A distinct; A is the victim):
#   1. H writes F (32 KiB random) and records md5_H; H holds F's grant.
#   2. Arm the D-512 T2 pausepoint on H: ino(F), stage 1 (BEFORE the site-1
#      dirty-page flush), 30 000 ms — H's release drain will hold with
#      UNFLUSHED dirty pages when W's BAST arrives.
#   3. W starts `md5sum F` in the background (blocks: BAST -> H pauses).
#   4. After H logs P-D512-RELPAUSE, virsh-destroy A (real node death).
#      Survivors: monitor -> fence -> replay -> recovery_complete -> lease
#      unregister -> refresh -> update_active_nodes -> TABLE PURGE.
#   5. Watch W's read.  The DEFECT is measured if W's read completes while
#      H is still inside the pause (no P-D512-RELPAUSE-END on H yet): the new
#      master granted W over H's live, unflushed tenure.  Its md5 then shows
#      whether the platter served STALE data (mismatch vs md5_H).
#      Correct behaviour: W completes only after P-D512-RELPAUSE-END with
#      md5 == md5_H.
#   6. virsh-start A again; the caller must prep_cluster afterwards.
#
# the budget rule (derived, revised sess418 run 1): the disklock monitor expires a
# heartbeat only after ~31 checks (~62 s, measured 04:31Z lap: "heartbeat
# expired after 31 checks") and recovery completes ~5 s later, so the pause
# must outlast ~70 s: setup ~8 s + pause 100 s + harvest ~10 s => ~120 s.
# Caller bound 200 s.
#
# Usage: tests/d0287_remaster_measure.sh <label> [H] [W] [A]
set -u
LABEL=${1:?label}
H=${2:-test3}; W=${3:-test1}; A=${4:-test8}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0287
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): the kernel-log captures
# a verdict is counted from cross the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
hd() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }   # polling only; never counted

echo "=== d0287_remaster_measure label=$LABEL H=$H W=$W victim=$A out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$H" "$W" "$A"; do
    nsv=$(timeout 15 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | filt | tr -dc 'A-F0-9')
    [ "$nsv" = "$TREESV" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$TREESV'"; exit 2; }
    ft=$(timeout 15 $SSH "$n" "cat $P/force_transport" 2>/dev/null | filt | tr -dc '0-9')
    [ "$ft" = 1 ] || { echo "ABORT: $n force_transport='$ft' — not TCP"; exit 2; }
done
MARK="D0287-$LABEL-$$"
for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done

F="$MNT/.d0287_$LABEL.dat"
timeout 25 $SSH "$H" "
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd1_rc=\$? >&2; exit 1; }
    md5sum '$F' | cut -d' ' -f1
    ino=\$(stat -c %i '$F'); echo \$ino
    echo \$ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo 100000 > $P/dbg_rel_pause_ms
    # re-dirty so the drain has unflushed pages when the BAST lands
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd2_rc=\$? >&2; exit 1; }
    md5sum '$F' | cut -d' ' -f1
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
md5_h=$(sed -n 3p "$OUT/h_setup.txt" | tr -dc 'a-f0-9')
ino=$(sed -n 2p "$OUT/h_setup.txt" | tr -dc '0-9')
# sess425: the s424/s425 aborts printed an EMPTY detail — H's stderr (the
# dd error, e.g. the D-0345 root-inode lock failure) was discarded.  Keep it.
[ -n "$md5_h" ] && [ -n "$ino" ] || {
    echo "ABORT: H setup failed: stdout=[$(tr '\n' ' ' < "$OUT/h_setup.txt")] stderr=[$(filt < "$OUT/h_setup.err" | tail -5 | tr '\n' ' ')]"
    exit 2; }
echo "  INFO ino=$ino md5_H=$md5_h"

# W's blocked read
( s0=$(date +%s.%N)
  timeout 170 $SSH "$W" "m=\$(md5sum '$F' 2>&1); rc=\$?; echo \"\$m\" | cut -d' ' -f1; exit \$rc" 2>/dev/null | filt | head -1 | tr -dc 'a-f0-9' > "$OUT/w_md5.txt"
  echo "$(date +%s.%N) $s0" > "$OUT/w_done.txt" ) &
WPID=$!

# wait for H to enter the pause
i=0; paused=0
while [ $i -lt 15 ]; do
    if hd "$H" | grep -aq "P-D512-RELPAUSE ino=$ino stage=1"; then paused=1; break; fi
    sleep 1; i=$((i+1))
done
ck "H entered the release-drain pause (BAST from W landed)" "$paused" "1"
if [ "$paused" != 1 ]; then kill $WPID 2>/dev/null; exit 1; fi
tkill=$(date +%s.%N)
# sess418 run 2: a DEATH trigger never produced the membership change on TCP
# within any window, because the victim's slice replay is refused (D-0288)
# so recovery never completes and mastership never migrates.  A CLEAN
# departure (umount) reaches the identical global purge immediately: goodbye
# -> purge_node -> lease unregister -> refresh -> update_active_nodes.
# MODE=destroy keeps the death trigger for when D-0288 is fixed.
if [ "${MODE:-umount}" = destroy ]; then
    $VIRSH destroy "$A" >/dev/null 2>&1; echo "  INFO virsh destroy $A rc=$? at $(date -u +%T)"
else
    urc=$(timeout 60 $SSH "$A" "timeout 45 umount $MNT; echo rc=\$?" 2>/dev/null | filt | sed -n 's/^rc=//p')
    echo "  INFO clean umount $A rc=${urc:-nossh} at $(date -u +%T)"
fi

# observe: does W's read complete while H is still paused?
served_during_pause=0; i=0
while [ $i -lt 160 ]; do
    if [ -s "$OUT/w_done.txt" ]; then
        if hd "$H" | grep -aq "P-D512-RELPAUSE-END ino=$ino"; then served_during_pause=0; else served_during_pause=1; fi
        break
    fi
    sleep 1; i=$((i+1))
done
wait $WPID 2>/dev/null
md5_w=$(cat "$OUT/w_md5.txt" 2>/dev/null)
if [ -s "$OUT/w_done.txt" ]; then
    read -r t1 t0 < "$OUT/w_done.txt"
    wall=$(awk -v a="$t1" -v b="$t0" 'BEGIN{printf "%.1f", a-b}')
    after_kill=$(awk -v a="$t1" -v b="$tkill" 'BEGIN{printf "%.1f", a-b}')
else
    wall=timeout; after_kill=timeout
fi
echo "  INFO W read: wall=${wall}s (+${after_kill}s after kill) md5_W=${md5_w:-none}"
measure "$H" 20 "$OUT/dmesg_$H.txt" '^DMESG_END$' "the kernel log on $H from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$W" 20 "$OUT/dmesg_$W.txt" '^DMESG_END$' "the kernel log on $W from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
memb=$(grep -ac 'MXFS-MEMBERSHIP\|purged .* stale locks' "$OUT/dmesg_$W.txt")
death=$(grep -ac 'initiating recovery\|lease expired/died\|P-TCPDEATH-DEFERRED\|declaring dead' "$OUT/dmesg_$W.txt")
echo "  INFO $W: membership-change lines=$memb death-path lines=$death"

# THE VERDICT LINES (instrumented): the defect is MEASURED if either fires.
ck "W was NOT served while H's drain was still paused" "$served_during_pause" "0"
ck "W md5 == H md5 (no stale data served)" "$([ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
ck "the membership change actually happened on $W during the window" "$([ "$memb" -ge 1 ] && echo 1 || echo 0)" "1"
for n in "$H" "$W"; do
    s=$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$n.txt"); ck "zero splats on $n" "$s" "0"
done
timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1
if [ "${MODE:-umount}" = destroy ]; then
    $VIRSH start "$A" >/dev/null 2>&1; echo "  INFO virsh start $A rc=$?"
fi
echo "=== d0287_remaster_measure $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
echo "NOTE: $A left the cluster (${MODE:-umount}) — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
