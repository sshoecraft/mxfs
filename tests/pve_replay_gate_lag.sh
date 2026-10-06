#!/bin/bash
# pve_replay_gate_lag.sh — the foreign replay's changecount gate must follow
# the platter when the survivor's own cached copy of an inode is behind it.
#
# A survivor replaying its dead peer's journal slice compares each logged inode
# image's change count with the slot it holds for that inode.  For an inode the
# survivor has in core, that slot is its own cached copy, which is behind the
# platter whenever the peer published after the survivor last held the inode.
# A gate that trusts the slot then APPLIES an image the platter has moved past:
# committed metadata reverted, on the recovery's authority.  Since 0.90.54 the
# gate takes the newer of the slot's and the platter's counts
# (replay_gate_platter=1); 0 is the old gate, kept as this test's control.
#
# The stale slot is rare in nature, so it is made on every image: on the
# survivor, dbg_replay_gate_buf_lag makes the gate read each slot's count that
# many changes low.  With the platter consulted, every such image must be
# judged by the platter (P77-STALE-BASE-VERDICT buf_verdict=APPLY verdict=SKIP
# where they disagree); with the slot alone, those images are applied.
#
#  1. Both hosts churn one shared directory with CHURN loops each: loop k on
#     either host appends numbered lines to the shared file shared.<k>.log,
#     creates and renames files of its own there, removes old ones, and every
#     25 lines syncs the filesystem and records the last line it knows durable
#     on its root filesystem.  Both hosts change the same inodes, so the peer's
#     slice holds images the survivor has newer copies of.
#  2. After WORK_S participant 1 is reset (sysrq b).  Participant 0 recovers
#     it under the injected lag, its own churn still running.
#  3. Participant 0 must recover participant 1 and keep writing, and every line
#     either host recorded durable must be in the shared file, read on both.
#  4. Once participant 1 has mounted again, both mounts stop and `chk_mxfs -n`
#     runs while nothing has the filesystem mounted
#     (scripts/pve_pair_update.sh SKIP_INSTALL=1 CHECK=1), then both start.
#
# Usage: tests/pve_replay_gate_lag.sh fix|control
#   fix      replay_gate_platter=1 (the shipped gate): must pass
#   control  replay_gate_platter=0: the old gate, to show the test can fail;
#            it may revert metadata, so run it only on a pair whose
#            filesystem may be rebuilt afterwards
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#              participant 0 is the lower address
#   LAG        changes the gate reads each slot low by (default 1000000: every
#              in-core slot reads as older than any image)
#   WORK_S     seconds of churn before the reset (default 40)
#   CHURN      churn loops per host (default 4; the first run, with one, put a
#              single foreign inode image in front of the gate)
#
# Evidence: tests/evidence/pve_replay_gate_lag/<UTC stamp>-<addr>-<arm>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
ARM=${1:-}
case "$ARM" in
    fix) PLATTER=1 ;;
    control) PLATTER=0 ;;
    *) echo "usage: $0 fix|control"; exit 2 ;;
esac
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_replay_gate_lag: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
LAG=${LAG:-1000000}
WORK_S=${WORK_S:-40}
CHURN=${CHURN:-4}
# The same bounds as tests/pve_pair_failover.sh: the survivor's recovery of a
# reset peer, the peer's boot, and its mount after answering.
RECOVER_BUDGET=60
BOOT_BUDGET=300
REJOIN_BUDGET=180
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_replay_gate_lag/$STAMP-${PAIR[0]}-$ARM"
mkdir -p "$EVID" || exit 1
PARAMS=/sys/module/mxfs/parameters

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
LEFT=""
die() { say "FAIL: $*"; [ -z "$LEFT" ] || say "LEFT: $LEFT"; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
STATE_CMD='echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null) boot=$(cat /proc/sys/kernel/random/boot_id)"'
state() { on "$1" "$STATE_CMD" 20 | grep '^unit='; }
pair_ok() { case "$1" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*) return 0 ;; esac; return 1; }
field() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<"$1" | head -1; }

s0=$(state "$P0"); s1=$(state "$P1")
pair_ok "$s0" || die "$P0 is not up as half of the pair: ${s0:-no answer}"
pair_ok "$s1" || die "$P1 is not up as half of the pair: ${s1:-no answer}"
[ "$(field "$s0" build)" = "$(field "$s1" build)" ] || die "the hosts run different MXFS builds"
on "$P0" "test -w $PARAMS/dbg_replay_gate_buf_lag && test -w $PARAMS/replay_gate_platter && echo HAS_KNOBS" 15 | grep -q HAS_KNOBS \
    || die "$P0's module has no replay gate knobs (dbg_replay_gate_buf_lag, replay_gate_platter)"
N0=$(on "$P0" hostname 10); N1=$(on "$P1" hostname 10)
B1=$(field "$s1" boot)
D="$MNT/gatelag/$STAMP"
say "replay gate lag ($ARM): participant 0 $P0 ($N0) survives, participant 1 $P1 ($N1) is reset; build $(field "$s0" build); replay_gate_platter=$PLATTER lag=$LAG; evidence $EVID"

# One churn loop, k.  It stops at its first error and says which command
# failed; its durable count is /root/gatelag.durable.<k>.
LOAD='d=$1; k=$2; h=$(hostname); i=0
rm -f /root/gatelag.durable.$k /root/gatelag.err.$k
while [ ! -e /dev/shm/gatelag.stop ]; do
    i=$((i + 1))
    echo "$h $i" >> $d/shared.$k.log || { echo "append $k $i" > /root/gatelag.err.$k; exit 1; }
    echo "$h $i" > $d/$h.$k.$i && mv $d/$h.$k.$i $d/$h.$k.$i.r || { echo "create $k $i" > /root/gatelag.err.$k; exit 1; }
    [ $i -gt 20 ] && { rm -f $d/$h.$k.$((i - 20)).r || { echo "remove $k $i" > /root/gatelag.err.$k; exit 1; }; }
    if [ $((i % 25)) = 0 ]; then
        sync -f $d/shared.$k.log || { echo "sync $k $i" > /root/gatelag.err.$k; exit 1; }
        echo $i > /root/gatelag.durable.$k.tmp && sync /root/gatelag.durable.$k.tmp && mv /root/gatelag.durable.$k.tmp /root/gatelag.durable.$k && sync /root
    fi
done'
on "$P0" "mkdir -p $D && echo MADE" 30 | grep -q MADE || die "could not make $D"
for h in "$P0" "$P1"; do
    on "$h" "rm -f /dev/shm/gatelag.stop; cat > /dev/shm/gatelag-load.sh <<'EOS'
$LOAD
EOS
for k in \$(seq 1 $CHURN); do nohup setsid bash /dev/shm/gatelag-load.sh $D \$k >/dev/null 2>&1 </dev/null & done; echo STARTED" 20 | grep -q STARTED || die "could not start the churn on $h"
done
LEFT="the churn may still run on $P0: touch /dev/shm/gatelag.stop there"
say "  both hosts churn $D; resetting $P1 in ${WORK_S}s"
sleep "$WORK_S"

on "$P0" "echo $PLATTER > $PARAMS/replay_gate_platter && echo $LAG > $PARAMS/dbg_replay_gate_buf_lag && echo 'file xfs_inode_item_recover.c +p' > /proc/dynamic_debug/control && echo ARMED" 15 | grep -q ARMED \
    || die "could not set the replay gate knobs on $P0"
LEFT="$LEFT; $P0's replay gate knobs: echo 1 > $PARAMS/replay_gate_platter; echo 0 > $PARAMS/dbg_replay_gate_buf_lag; echo 'file xfs_inode_item_recover.c -p' > /proc/dynamic_debug/control"
t0=$(date +%s)
on "$P1" "echo 1 > /proc/sys/kernel/sysrq; nohup setsid sh -c 'sleep 1; echo b > /proc/sysrq-trigger' >/dev/null 2>&1 < /dev/null & echo RESET_ARMED" 15 | grep -q RESET_ARMED \
    || die "could not arm the reset on $P1"
say "  $P1 reset"
rec=""
while [ $(( $(date +%s) - t0 )) -lt "$RECOVER_BUDGET" ]; do
    rec=$(on "$P0" "journalctl -k --no-pager -o cat --since @$t0 | grep -aoE 'P163-RECOVERY-COMPLETE|P-RBLK-[A-Z-]+' | sort | uniq -c | tr '\n' ' '" 30)
    grep -q -E 'P163-RECOVERY-COMPLETE|P-RBLK' <<<"$rec" && break
    sleep 3
done
say "  $P0 after the reset ($(( $(date +%s) - t0 )) s): ${rec:-no recovery lines}"
sleep 10
on "$P0" "touch /dev/shm/gatelag.stop; sleep 3; for k in \$(seq 1 $CHURN); do cat /root/gatelag.err.\$k 2>/dev/null; echo DURABLE.\$k=\$(cat /root/gatelag.durable.\$k 2>/dev/null); done" 30 > "$EVID/churn.$P0"
on "$P0" "echo 1 > $PARAMS/replay_gate_platter; echo 0 > $PARAMS/dbg_replay_gate_buf_lag; echo 'file xfs_inode_item_recover.c -p' > /proc/dynamic_debug/control" 15 >/dev/null
LEFT=""
on "$P0" "journalctl -k --no-pager -o short-iso --since @$t0 | grep -aE 'P77-|P163-|P236-FENCE-CERTIFIED|P-RBLK|XFS|corrupt|Corruption|shutdown' | cut -c1-400" 60 > "$EVID/klog.$P0"
inj=$(grep -c 'P77-GATE-LAG-INJECT' "$EVID/klog.$P0")
apply=$(grep -c 'P77-FRINODE foreign.*verdict=APPLY' "$EVID/klog.$P0")
skip=$(grep -c 'P77-FRINODE foreign.*verdict=SKIP' "$EVID/klog.$P0")
stale_skip=$(grep -c 'P77-STALE-BASE-VERDICT.*buf_verdict=APPLY verdict=SKIP' "$EVID/klog.$P0")
stale_apply=$(grep -c 'P77-STALE-BASE-VERDICT.*buf_verdict=APPLY verdict=APPLY' "$EVID/klog.$P0")
say "  $P0's gate: injected $inj, foreign images applied $apply / skipped $skip; slot and platter disagreed $((stale_skip + stale_apply)) times: followed the platter (skip) $stale_skip, followed the slot (apply) $stale_apply"
say "  $P0's churn: $(tr '\n' ' ' <<<"$(cat "$EVID/churn.$P0")")"

FAIL=0
grep -q P163-RECOVERY-COMPLETE <<<"$rec" || { say "FAIL: $P0 did not complete the recovery of $P1 within ${RECOVER_BUDGET}s"; FAIL=1; }
grep -q P-RBLK <<<"$rec" && { say "FAIL: $P0 refused operations as RECOVERY_BLOCKED"; FAIL=1; }
[ "$inj" -gt 0 ] || { say "FAIL: INVALID RUN: the lag was never injected (no foreign inode image reached the gate)"; FAIL=1; }
grep -q -E '^(append|create|remove|sync) ' "$EVID/churn.$P0" && { say "FAIL: $P0's churn failed: $(head -1 "$EVID/churn.$P0")"; FAIL=1; }
[ "$stale_apply" = 0 ] || { say "FAIL: the gate applied $stale_apply images the platter had moved past"; FAIL=1; }

# Participant 1 back, then every durable line of both hosts on both.
t1=$(date +%s)
while [ $(( $(date +%s) - t1 )) -lt "$BOOT_BUDGET" ]; do
    b=$(on "$P1" 'cat /proc/sys/kernel/random/boot_id' 10 | grep -E '^[0-9a-f-]{36}$')
    [ -n "$b" ] && [ "$b" != "$B1" ] && break
    sleep 5
done
[ -n "$b" ] && [ "$b" != "$B1" ] || die "$P1 did not come back within ${BOOT_BUDGET}s of its reset"
t1=$(date +%s)
until pair_ok "$(state "$P1")"; do
    [ $(( $(date +%s) - t1 )) -lt "$REJOIN_BUDGET" ] || die "$P1 did not mount again within ${REJOIN_BUDGET}s of answering"
    sleep 5
done
say "  $P1 mounted again $(( $(date +%s) - t1 )) s after answering"
on "$P1" "for k in \$(seq 1 $CHURN); do echo DURABLE.\$k=\$(cat /root/gatelag.durable.\$k 2>/dev/null); done" 15 > "$EVID/churn.$P1"
for k in $(seq 1 "$CHURN"); do
    d0=$(sed -n "s/^DURABLE.$k=//p" "$EVID/churn.$P0"); d1=$(sed -n "s/^DURABLE.$k=//p" "$EVID/churn.$P1")
    say "  shared.$k.log durable lines: $N0 ${d0:-0}, $N1 ${d1:-0}"
    [ -n "$d1" ] && [ "$d1" -gt 0 ] || { say "FAIL: INVALID RUN: $P1's loop $k recorded no durable line before its reset"; FAIL=1; }
    for h in "$P0" "$P1"; do
        out=$(on "$h" "awk -v a=$N0 -v na=${d0:-0} -v b=$N1 -v nb=${d1:-0} '\$1 == a && \$2 <= na {sa[\$2] = 1} \$1 == b && \$2 <= nb {sb[\$2] = 1} END {ma = 0; mb = 0; for (j = 1; j <= na; j++) if (!(j in sa)) ma++; for (j = 1; j <= nb; j++) if (!(j in sb)) mb++; print \"MISSING \" ma \" \" mb}' $D/shared.$k.log" 60)
        say "    $h reads shared.$k.log: $(grep '^MISSING' <<<"$out" || echo "$out")"
        grep -q '^MISSING 0 0$' <<<"$out" || { say "FAIL: $h is missing durable lines of shared.$k.log"; FAIL=1; }
    done
done
on "$P1" "rm -f /dev/shm/gatelag-load.sh /dev/shm/gatelag.stop /root/gatelag.durable.* /root/gatelag.err.*; echo 1" 10 >/dev/null
on "$P0" "rm -f /dev/shm/gatelag-load.sh /dev/shm/gatelag.stop /root/gatelag.durable.* /root/gatelag.err.*; rm -rf $D; echo 1" 60 >/dev/null

say "  stopping both mounts for a cold check"
bash -c "PVE_PAIR='$P0 $P1' SKIP_INSTALL=1 CHECK=1 exec '$REPO/scripts/pve_pair_update.sh'" > "$EVID/cold-check.log" 2>&1
crc=$?
grep -E 'chk_mxfs|FAIL|pair updated' "$EVID/cold-check.log" | tail -6 | sed 's/^/    /' | tee -a "$EVID/log"
[ "$crc" = 0 ] || { say "FAIL: the cold check or the restart failed (rc=$crc): $EVID/cold-check.log"; FAIL=1; }

if [ "$FAIL" = 0 ]; then
    say "PASS: evidence $EVID"
    exit 0
fi
say "FAIL: evidence $EVID"
exit 1
