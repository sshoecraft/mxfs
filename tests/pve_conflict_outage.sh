#!/bin/bash
# pve_conflict_outage.sh — replay the 2026-10-07 chain on the nested DRBD pair
# with the bootstrap's verdicts printed: a dual-write conflict under the
# shared-directory churn (the passenger write switched back on), participant
# 1's restart and participant 0's wedge when it reconnects, then a total
# outage, then the restart's whole-cluster bootstrap.
#
# For D-DRBD-OUTAGE-BOOTSTRAP-REFUSES-THE-LAST-SURVIVORS-OWN-LOG.  The lone
# survivor's own log bootstraps clean without the conflict
# (tests/pve_outage_lone_survivor.sh, three runs); the hypothesis here is that
# the images refused on 2026-10-07 were the conflict's inodes, logged around
# the exclusion under grants the survivor had already released.
#
# cluster_passenger_skip=3 restores the 0.90.92 behaviour that made the dual
# write (conflicts in 4 of 8 churn runs then, 1 of 3 on 0.90.93 with the knob
# at 3); the laps run until DRBD logs a conflict or LAPS run out.
#
# Runs on the NESTED pair only (pve9-2 = participant 0 192.168.120.137,
# pve9-1 = participant 1 192.168.120.192): it destroys both VMs.  Participant
# 0's boot unit is held disabled from the start and participant 1's once it
# is back from its restart, so the post-outage mounts start by hand with the
# verdict probes already on; both units are enabled again at the end.
#
# Usage: tests/pve_conflict_outage.sh
# Env:
#   LAPS          churn laps to try for a conflict (default 6)
#   PIN=1         hold participant 0's log tail from each lap's start
#                 (dbg_ail_pin_ino on a fresh file; released after a lap with
#                 no conflict), as the wedged survivor's tail was held on
#                 2026-10-07, so the outage's replay window carries the
#                 conflict's checkpoints; the wedge is then not waited for
#   WEDGE_BUDGET  seconds after the conflict for participant 1 to be back and
#                 participant 0's heartbeat to stall (default 400: participant
#                 1 restarted 10 s after the fence and reconnected ~30 s after
#                 its boot on 2026-10-07; the stall line repeats every 30 s)
#   MOUNT_BUDGET  seconds from the units' start to both mounted or a refusal
#                 (default 300)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
P0=192.168.120.137; P0VM=pve9-2
P1=192.168.120.192; P1VM=pve9-1
RES=mxfs; MNT=/mnt/shared
LAPS=${LAPS:-6}
WEDGE_BUDGET=${WEDGE_BUDGET:-400}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
EVID="$REPO/tests/evidence/pve_conflict_outage/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
count() {  # <host> <cmd printing a count>: the count, or nothing
    local c
    c=$(on "$1" "$2" 20 | tail -1)
    [[ "$c" =~ ^[0-9]+$ ]] && echo "$c"
}
units() { on "$1" "systemctl $2 mxfs-drbd@$RES 2>&1 | grep -v '^Created\\|^Removed'; systemctl is-enabled mxfs-drbd@$RES" 20 | sed "s/^/$1 unit: /" | tee -a "$EVID/log"; }
probes() {
    local f
    for f in P227-TOKEN P273-SHADOW-EVAL P-RMAN-EVAL; do
        on "$1" "echo 'module mxfs format \"$f\" +p' > /proc/dynamic_debug/control" 15
    done
    on "$1" "grep -c '=p .*P227-TOKEN' /proc/dynamic_debug/control" 15 | sed "s/^/$1 P227-TOKEN sites on: /" | tee -a "$EVID/log"
}
cleanup() { units "$P0" enable >/dev/null; units "$P1" enable >/dev/null; }
trap cleanup EXIT

say "evidence $EVID"
units "$P0" disable
on "$P0" "echo '<5>mxfs-test: conflict outage run start' > /dev/kmsg" 15
T0=$(date +%s)

# 1. churn with the passenger write back on until DRBD logs a conflict
conflicts=0
pin_set() {  # PIN=1: hold participant 0's log tail on a fresh file's inode (0 releases)
    local ino=$1
    if [ "$ino" = new ]; then
        ino=$(on "$P0" "mkdir -p $MNT/conflict-pin && f=$MNT/conflict-pin/p.\$(date +%s) && echo pin > \$f && stat -c %i \$f" 30 | tail -1)
        [[ "$ino" =~ ^[0-9]+$ ]] || { say "ABORT: no pin inode ($ino)"; exit 1; }
        on "$P0" "echo $ino > /sys/module/mxfs/parameters/dbg_ail_pin_ino; echo again >> \$(ls -t $MNT/conflict-pin/p.* | head -1)" 30
    else
        on "$P0" "echo 0 > /sys/module/mxfs/parameters/dbg_ail_pin_ino" 30
    fi
    say "dbg_ail_pin_ino on participant 0: $(on "$P0" "cat /sys/module/mxfs/parameters/dbg_ail_pin_ino" 15)"
}
for lap in $(seq 1 "$LAPS"); do
    [ "${PIN:-0}" = 1 ] && pin_set new
    env CHURN=8 JOIN_BUDGET=120 timeout 600 "$REPO/tests/pve_write_authority_laps.sh" 1 3 2>&1 | cut -c1-400 | tee -a "$EVID/log"
    conflicts=$(count "$P0" "journalctl -k -b --no-pager | sed -n '/mxfs-test: conflict outage run start/,\$p' | grep -a -c 'Concurrent writes detected'")
    say "after lap $lap: participant 0 logged ${conflicts:-?} conflict line(s)"
    [ "${conflicts:-0}" -gt 0 ] && break
    [ "${PIN:-0}" = 1 ] && pin_set 0
done
if [ "${conflicts:-0}" -eq 0 ]; then
    say "NO CONFLICT in $LAPS laps: nothing to test"
    exit 2
fi

# 2. participant 1 restarts (it loses the tie-break); wait for it and for
# participant 0's heartbeat to stall once it reconnects
t1=$(date +%s)
state=none
# PIN=1 holds the tail as the wedge did, so the wedge is not waited for: the
# survivor gets 30 s alone after its recovery of the peer, then the outage
[ "${PIN:-0}" = 1 ] && { state=pinned; sleep 30; }
while [ "$state" = none ] && [ $(( $(date +%s) - t1 )) -lt "$WEDGE_BUDGET" ]; do
    st=$(count "$P0" "journalctl -k -b --no-pager | sed -n '/mxfs-test: conflict outage run start/,\$p' | grep -a -c 'P278-HB-STALL'")
    if [ "${st:-0}" -gt 0 ]; then state=wedged; break; fi
    if [ "$(count "$P0" "grep -c ' $MNT mxfs ' /proc/mounts")" = 0 ]; then state=p0-unmounted; break; fi
    sleep 10
done
say "participant 0 after the conflict: $state ($(( $(date +%s) - t1 ))s)"
on "$P0" "cat /proc/drbd; journalctl -k -b --no-pager -o short-monotonic | sed -n '/mxfs-test: conflict outage run start/,\$p' | grep -aE 'Concurrent writes|BarrierAck|ProtocolError|fence-peer|P163-RECOVERY-COMPLETE|P-RELMARK-REINSTALL|P278-HB-STALL|blocked for more' | head -40" 60 > "$EVID/p0-before-outage.txt"
on "$P1" "uptime; grep ' cs:' /proc/drbd" 20 | tee -a "$EVID/log"
units "$P1" disable

# 3. the outage, then the restart with the probes on before any mount
say "destroying both VMs"
$VIRSH destroy "$P0VM" 2>&1 | tee -a "$EVID/log"
$VIRSH destroy "$P1VM" 2>&1 | tee -a "$EVID/log"
$VIRSH start "$P0VM" 2>&1 | tee -a "$EVID/log"
$VIRSH start "$P1VM" 2>&1 | tee -a "$EVID/log"
t2=$(date +%s)
until on "$P0" true 10 >/dev/null && on "$P1" true 10 >/dev/null; do
    [ $(( $(date +%s) - t2 )) -ge 240 ] && { say "FAIL: hosts not answering in 240s"; exit 1; }
    sleep 5
done
say "both hosts answering after $(( $(date +%s) - t2 ))s"
probes "$P0"
probes "$P1"
units "$P0" enable
units "$P1" enable
on "$P0" "systemctl start --no-block mxfs-drbd@$RES" 30
on "$P1" "systemctl start --no-block mxfs-drbd@$RES" 30
t3=$(date +%s)
verdict=timeout
while [ $(( $(date +%s) - t3 )) -lt "$MOUNT_BUDGET" ]; do
    m0=$(count "$P0" "grep -c ' $MNT mxfs ' /proc/mounts")
    m1=$(count "$P1" "grep -c ' $MNT mxfs ' /proc/mounts")
    if [ "${m0:-0}" = 1 ] && [ "${m1:-0}" = 1 ]; then verdict=both-mounted; break; fi
    r=$(count "$P0" "journalctl -k -b --no-pager | grep -a -c -E 'P-BOOT-REFUSED|P-BOOT-ADMISSION-REFUSED'")
    if [ "${r:-0}" -gt 0 ]; then verdict=refused; break; fi
    sleep 10
done
say "restart verdict: $verdict after $(( $(date +%s) - t3 ))s"
sleep 5
for h in "$P0" "$P1"; do
    on "$h" "journalctl -b --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd'" 90 > "$EVID/boot0-$h.log"
    on "$h" "journalctl -b -1 --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd|mxfs-test|blocked for more|Call Trace|^\\[.*\\]  [a-z_]+\\+0x'" 120 > "$EVID/boot-1-$h.log"
done
say "P0 boot0: P227-TOKEN $(grep -c 'P227-TOKEN ' "$EVID/boot0-$P0.log") TOKENSUM $(grep -c 'P227-TOKENSUM' "$EVID/boot0-$P0.log") ATOMIC-SKIP $(grep -c 'ATOMIC-SKIP' "$EVID/boot0-$P0.log") P273 $(grep -c 'P273-SHADOW-EVAL' "$EVID/boot0-$P0.log")"
grep -ahE 'P-BOOT-(CLAIM|ADOPT |ADOPTED-REFUSED|REFUSING|REFUSED|COMPLETE)|ATOMIC-SKIP|P273-SHADOW-EVAL|mounted /dev/drbd0' "$EVID/boot0-$P0.log" "$EVID/boot0-$P1.log" | cut -c1-300 | tee -a "$EVID/log"
[ "$verdict" = both-mounted ] && { say "PASS (no refusal after the conflict chain)"; exit 0; }
say "FAIL ($verdict)"
exit 1
