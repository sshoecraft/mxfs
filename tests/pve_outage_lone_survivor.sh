#!/bin/bash
# pve_outage_lone_survivor.sh — a DRBD pair loses one host, the other carries
# on alone, then the lone survivor loses power too (a total outage), and both
# must come back with no operator action.
#
# For D-DRBD-OUTAGE-BOOTSTRAP-REFUSES-THE-LAST-SURVIVORS-OWN-LOG: after such an
# outage the first mount's whole-cluster bootstrap adopts the survivor's log
# slice and replays it under authority evaluation; on 2026-10-07 it refused
# the survivor's two newest checkpoints and the pair never remounted.  The
# hypothesis under test: checkpoints written after the survivor excluded its
# peer and took over its grants carry tokens the bootstrap refuses.  This run
# has no conflict and no wedge in it — only the exclusion, the survivor's own
# writes, and the outage.
#
# The replay's per-item verdicts (P227-TOKEN per buffer image, P227-TOKENSUM
# per transaction, P273-SHADOW-EVAL per log) are dynamic-debug probes.  The
# module loads from the initramfs, so /etc/modprobe.d options never reach it,
# and the boot's unit mounts ~10 s in; DIAG=1 therefore holds the unit off for
# the restart, turns the probes on, and starts the unit by hand.
#
# Runs on the NESTED pair only (it destroys both VMs): pve9-2 = participant 0
# (192.168.120.137), pve9-1 = participant 1 (192.168.120.192).
#
# Usage: tests/pve_outage_lone_survivor.sh
# Env:
#   FORMAT=1        stop both units and reformat /dev/drbd0 first (mkfs.mxfs
#                   -f -n 16, the pair's layout)
#   DIAG=1          print the replay's verdicts (see above); the restart is
#                   then started by hand, so it no longer proves an unattended one
#   PIN=1           hold participant 0's log tail from before the exclusion to
#                   the outage (dbg_ail_pin_ino), and churn one shared
#                   directory from both hosts first (see the block below)
#   SURVIVE_S       seconds the survivor churns alone before the outage (20)
#   JOIN_BUDGET     seconds for both hosts mounted, Primary/Primary (300: the
#                   heartbeat scan ~64 s, DRBD connect and the boot program's
#                   ordering, twice over)
#   RECOVER_BUDGET  seconds from the peer's destruction to the survivor's
#                   P163-RECOVERY-COMPLETE (120: the fence handler and the
#                   recovery took ~6 s on 2026-10-07, the TCP death grace 40 s,
#                   twice that plus margin)
#   RESTART_BUDGET  seconds from starting both VMs to both mounted (400: boot
#                   ~40 s, the boot program's DRBD wait, the bootstrap's scan
#                   ~64 s, replay, then participant 1's join, about twice the
#                   ~190 s it took on the physical pair after its power cut)
# Exit 0 only if both hosts remount after the outage with no refusal.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
P0=192.168.120.137; P0VM=pve9-2
P1=192.168.120.192; P1VM=pve9-1
RES=mxfs; MNT=/mnt/shared
SURVIVE_S=${SURVIVE_S:-20}
JOIN_BUDGET=${JOIN_BUDGET:-300}
RECOVER_BUDGET=${RECOVER_BUDGET:-120}
RESTART_BUDGET=${RESTART_BUDGET:-400}
EVID="$REPO/tests/evidence/pve_outage_lone_survivor/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
mounted() {  # <host>: mounted and Primary on a Connected or StandAlone link
    [ "$(on "$1" "grep -c ' $MNT mxfs ' /proc/mounts" 15)" = 1 ]
}
whole() {
    local h s
    for h in "$P0" "$P1"; do
        s=$(on "$h" "grep ' cs:' /proc/drbd; grep -c ' $MNT mxfs ' /proc/mounts" 15)
        case "$s" in *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*) ;; *) return 1 ;; esac
        [ "$(tail -1 <<<"$s")" = 1 ] || return 1
    done
}
wait_for() {  # <budget> <what> <cmd...>: poll every 5 s
    local budget=$1 what=$2 t0
    shift 2
    t0=$(date +%s)
    until "$@"; do
        if [ $(( $(date +%s) - t0 )) -ge "$budget" ]; then
            say "FAIL: $what not reached within ${budget}s"
            return 1
        fi
        sleep 5
    done
    say "$what after $(( $(date +%s) - t0 ))s"
}
probes() {  # <host> on|off: the replay's verdict probes, at run time
    local f flag=+p
    [ "$2" = on ] || flag=-p
    for f in P227-TOKEN P273-SHADOW-EVAL P-RMAN-EVAL; do
        on "$1" "echo 'module mxfs format \"$f\" $flag' > /proc/dynamic_debug/control" 15
    done
    on "$1" "grep -c '=p .*P227-TOKEN' /proc/dynamic_debug/control" 15 | sed "s/^/$1 P227-TOKEN sites on: /"
}
units() {  # <host> enable|disable: whether the host's boot starts the MXFS unit
    on "$1" "systemctl $2 mxfs-drbd@$RES 2>&1 | grep -v '^Created\\|^Removed'; systemctl is-enabled mxfs-drbd@$RES" 20 | sed "s/^/$1 unit: /"
}
cleanup() {
    if [ "${DIAG:-0}" = 1 ]; then units "$P0" enable >/dev/null; units "$P1" enable >/dev/null; fi
}

say "evidence $EVID"
if [ "${FORMAT:-0}" = 1 ]; then
    say "reformatting /dev/drbd0 from $P0VM"
    on "$P1" "systemctl stop mxfs-drbd@$RES; drbdadm secondary $RES; grep ' cs:' /proc/drbd" 120 | tee -a "$EVID/log"
    on "$P0" "systemctl stop mxfs-drbd@$RES; systemctl reset-failed mxfs-drbd@$RES" 120 | tee -a "$EVID/log"
    # a unit that stops cleanly takes its DRBD resource down with it; bring it
    # back on both and wait for the link before promoting for the format
    on "$P1" "drbdadm up $RES 2>&1 | grep -v 'already'" 60 | tee -a "$EVID/log"
    on "$P0" "drbdadm up $RES 2>&1 | grep -v 'already'" 60 | tee -a "$EVID/log"
    linked() { on "$P0" "grep ' cs:' /proc/drbd" 15 | grep -q 'cs:Connected ro:Secondary/Secondary ds:UpToDate/UpToDate'; }
    wait_for 120 "DRBD Connected Secondary/Secondary UpToDate" linked || exit 1
    on "$P0" "drbdadm primary $RES && mkfs.mxfs -f -n 16 /dev/drbd0 > /dev/shm/mkfs.out 2>&1; echo MKFS_RC=\$?; tail -3 /dev/shm/mkfs.out; drbdadm secondary $RES" 300 | tee -a "$EVID/log"
    grep -q 'MKFS_RC=0' "$EVID/log" || { say "ABORT: mkfs failed"; exit 1; }
    on "$P1" "systemctl reset-failed mxfs-drbd@$RES; systemctl start --no-block mxfs-drbd@$RES" 30
    on "$P0" "systemctl start --no-block mxfs-drbd@$RES" 30
fi
wait_for "$JOIN_BUDGET" "pair whole (mounted, Primary/Primary, UpToDate)" whole || exit 1
for h in "$P0" "$P1"; do on "$h" "cat /sys/module/mxfs/srcversion; cat /sys/module/mxfs/version" 15 | tr '\n' ' ' | sed "s/^/$h build: /" | tee -a "$EVID/log"; echo | tee -a "$EVID/log"; done

# both hosts write, so the survivor holds grants of its own and the peer's
on "$P0" "mkdir -p $MNT/outage/a && for i in \$(seq 1 200); do echo a\$i > $MNT/outage/a/f\$i; done; sync; echo P0_PREWRITE_RC=\$?" 120 | tee -a "$EVID/log"
on "$P1" "mkdir -p $MNT/outage/b && for i in \$(seq 1 200); do echo b\$i > $MNT/outage/b/f\$i; done; sync; echo P1_PREWRITE_RC=\$?" 120 | tee -a "$EVID/log"
# DIAG=1: the restart's mount must run with the verdict probes on, and the
# module loads from the initramfs before anything can turn them on, so the
# boot does not start the unit; the probes go on first and the unit is started
# by hand (the verdict then no longer proves an unattended restart)
trap cleanup EXIT
if [ "${DIAG:-0}" = 1 ]; then
    units "$P0" disable | tee -a "$EVID/log"
    units "$P1" disable | tee -a "$EVID/log"
fi

# PIN=1: pin participant 0's log tail before the exclusion (dbg_ail_pin_ino on
# a file it then logs), so every checkpoint from before the peer's death to the
# outage stays in its replay window, as it did when the 2026-10-07 survivor's
# writeback hung; then both hosts churn one shared directory so its grants
# change hands across that window
if [ "${PIN:-0}" = 1 ]; then
    pino=$(on "$P0" "mkdir -p $MNT/outage/shared && echo pin > $MNT/outage/a/pin && stat -c %i $MNT/outage/a/pin" 30 | tail -1)
    [[ "$pino" =~ ^[0-9]+$ ]] || { say "ABORT: no pin inode ($pino)"; exit 1; }
    on "$P0" "echo $pino > /sys/module/mxfs/parameters/dbg_ail_pin_ino && echo again >> $MNT/outage/a/pin && sync && cat /sys/module/mxfs/parameters/dbg_ail_pin_ino" 60 | sed 's/^/pinned ino /' | tee -a "$EVID/log"
    for h in "$P0" "$P1"; do
        ( on "$h" "cd $MNT/outage/shared || exit 1; t=\$(hostname); n=0; end=\$((\$(date +%s) + 10)); while [ \$(date +%s) -lt \$end ]; do n=\$((n+1)); echo \$t\$n >> log.\$(( n % 4 )); echo \$n > \$t.\$n; [ \$n -gt 10 ] && unlink \$t.\$((n-10)); [ \$(( n % 50 )) -eq 0 ] && sync; done; echo SHARED_OPS \$t \$n" 60 | tee -a "$EVID/log" ) &
    done
    wait
fi
say "destroying $P1VM (participant 1)"
on "$P0" "echo '<5>mxfs-test: lone survivor run peer destroyed' > /dev/kmsg" 15
$VIRSH destroy "$P1VM" 2>&1 | tee -a "$EVID/log"
recovered() {
    local c
    c=$(on "$P0" "journalctl -k -b --no-pager | sed -n '/mxfs-test: lone survivor run peer destroyed/,\$p' | grep -a -c P163-RECOVERY-COMPLETE" 20 | tail -1)
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ]
}
wait_for "$RECOVER_BUDGET" "survivor $P0VM P163-RECOVERY-COMPLETE" recovered || exit 1
mounted "$P0" || { say "FAIL: the survivor lost its mount"; exit 1; }

# the survivor alone: creates, renames, appends and unlinks in one directory
# and in the peer's, with a sync every 100 operations so committed checkpoints
# written after the takeover stand in the log ahead of their writeback at the
# moment of the outage (without it the work sits in the CIL and is simply lost,
# and the log's tail is at its head: nothing for the bootstrap to judge)
say "survivor churns alone for ${SURVIVE_S}s"
on "$P0" "cd $MNT/outage || exit 1; n=0; end=\$((\$(date +%s) + $SURVIVE_S)); while [ \$(date +%s) -lt \$end ]; do n=\$((n+1)); echo s\$n > a/s\$n; mv a/s\$n a/t\$n; echo s\$n >> b/f\$(( n % 200 + 1 )); [ \$n -gt 20 ] && unlink a/t\$((n-20)); [ \$(( n % 100 )) -eq 0 ] && sync; done; echo SURVIVOR_OPS=\$n" $(( SURVIVE_S + 30 )) | tee -a "$EVID/log"
on "$P0" "echo '<5>mxfs-test: lone survivor run outage' > /dev/kmsg" 15
say "destroying $P0VM (the lone survivor, mount live)"
$VIRSH destroy "$P0VM" 2>&1 | tee -a "$EVID/log"

say "starting both VMs"
$VIRSH start "$P0VM" 2>&1 | tee -a "$EVID/log"
$VIRSH start "$P1VM" 2>&1 | tee -a "$EVID/log"
T0=$(date +%s)
if [ "${DIAG:-0}" = 1 ]; then
    up() { on "$P0" "true" 10 >/dev/null && on "$P1" "true" 10 >/dev/null; }
    wait_for 180 "both hosts answering" up || exit 1
    probes "$P0" on | tee -a "$EVID/log"
    probes "$P1" on | tee -a "$EVID/log"
    units "$P0" enable | tee -a "$EVID/log"
    units "$P1" enable | tee -a "$EVID/log"
    on "$P0" "systemctl start --no-block mxfs-drbd@$RES" 30
    on "$P1" "systemctl start --no-block mxfs-drbd@$RES" 30
fi
# a host still booting answers with ssh's error text, not a count: only a
# number above zero is a refusal
refused() {
    local c
    c=$(on "$P0" "journalctl -k -b --no-pager | grep -a -c -E 'P-BOOT-REFUSED|P-BOOT-ADMISSION-REFUSED'" 20 | tail -1)
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ]
}
verdict=timeout
while [ $(( $(date +%s) - T0 )) -lt "$RESTART_BUDGET" ]; do
    if whole; then verdict=both-mounted; break; fi
    if refused; then verdict=refused; break; fi
    sleep 10
done
say "restart verdict: $verdict after $(( $(date +%s) - T0 ))s"
for h in "$P0" "$P1"; do
    on "$h" "journalctl -b --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd'" 90 > "$EVID/boot0-$h.log"
    on "$h" "journalctl -b -1 --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd|mxfs-test'" 90 > "$EVID/boot-1-$h.log"
done
say "P0 boot0: P227-TOKEN $(grep -c 'P227-TOKEN ' "$EVID/boot0-$P0.log") TOKENSUM $(grep -c 'P227-TOKENSUM' "$EVID/boot0-$P0.log") ATOMIC-SKIP $(grep -c 'ATOMIC-SKIP' "$EVID/boot0-$P0.log")"
grep -ahE 'P-BOOT-(CLAIM|ADOPT |ADOPTED-REFUSED|REFUSING|REFUSED|COMPLETE)|RECOVERY_COMPLETE|ATOMIC-SKIP|mounted /dev/drbd0' "$EVID/boot0-$P0.log" "$EVID/boot0-$P1.log" | cut -c1-240 | tee -a "$EVID/log"
[ "$verdict" = both-mounted ] && { say "PASS"; exit 0; }
say "FAIL ($verdict)"
exit 1
