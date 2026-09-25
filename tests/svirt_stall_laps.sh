#!/bin/bash
#
# svirt_stall_laps.sh — repeat the order in which a create on the RHEL survivor
# stalled 60 s after a peer death, until it stalls again or the laps run out.
#
# One lap, on the rhel9 verification pair (alma9-1 survivor, alma9-2 victim):
#   1. tests/packaged_round.sh rhel9 VERSION   install the packaged build; ends
#                                              with a reboot of both nodes
#   2. PREP=rhel9 tests/tcp_peer_freeze_death.sh
#                                              freeze the victim, death, fence,
#                                              replay, resume the victim
#   3. tests/selinux_svirt_mxfs.sh <survivor>  qemu-img create on the survivor;
#                                              records blocked stacks 8 s before
#                                              its 60 s budget if it overruns
#   4. unmount MXFS on both nodes
#
# Stops at the first lap whose step 3 fails, so the evidence of that lap
# (stacks.log, the freeze-death dmesg) is the last thing written.  A failing
# step 1 or 2 also stops the loop: step 3 is only meaningful after both passed.
#
# Budgets are the steps' own (each harness enforces its budget and fails on an
# overrun); measured on 0.89.90: round 164 s, freeze-death 364 s, svirt 5 s.
#
# Usage: tests/svirt_stall_laps.sh VERSION LAPS
#   VERSION is a build in dist/<VERSION>/ (A/B against an older release by
#   passing its version).  Log: tests/evidence/svirt_stall_laps_<VERSION>_<stamp>.log
#   Exit 0 when every lap passed, 1 at the first failing lap.
#
set -u

VERSION="${1:?usage: svirt_stall_laps.sh VERSION LAPS}"
LAPS="${2:?usage: svirt_stall_laps.sh VERSION LAPS}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
[ -d "dist/$VERSION" ] || { echo "no dist/$VERSION"; exit 1; }
SSH="$HERE/tools/mxfs_sshpass.sh"
A=$(tools/mxfs_lab.sh addr alma9-1)
B=$(tools/mxfs_lab.sh addr alma9-2)
L="$HERE/tests/evidence/svirt_stall_laps_${VERSION}_$(date +%Y%m%dT%H%M%S).log"
say() { echo "[$(date +%T)] $*" | tee -a "$L"; }

unmount_both() {
    for n in $A $B; do
        timeout 75 "$SSH" $n 'for m in $(grep " mxfs " /proc/mounts | cut -d" " -f2); do timeout 60 umount $m; done' >/dev/null 2>&1 &
    done
    wait
}

say "version=$VERSION laps=$LAPS survivor=alma9-1 ($A) victim=alma9-2 ($B) log=$L"
for i in $(seq 1 "$LAPS"); do
    say "##### lap $i/$LAPS"
    tests/packaged_round.sh rhel9 "$VERSION" >> "$L" 2>&1
    rc=$?; say "lap $i round_rc=$rc"
    [ $rc = 0 ] || { say "STOP: packaged round failed on lap $i"; exit 1; }
    PREP=rhel9 tests/tcp_peer_freeze_death.sh >> "$L" 2>&1
    rc=$?; say "lap $i freeze_rc=$rc"
    [ $rc = 0 ] || { say "STOP: tcp_peer_freeze_death failed on lap $i"; exit 1; }
    s=$(date +%s)
    tests/selinux_svirt_mxfs.sh "$A" >> "$L" 2>&1
    rc=$?
    D=$(ls -td tests/evidence/selinux_svirt/* | head -1)
    F=$(ls -td tests/evidence/tcp_peer_freeze_death/* | head -1)
    say "lap $i svirt_rc=$rc wall=$(( $(date +%s) - s ))s $(grep -E '^t_(start|create)=' "$D/svirt.log" 2>/dev/null | tr '\n' ' ') svirt=$D freeze=$F"
    if [ $rc != 0 ]; then
        say "STALL on lap $i: stacks.log $(stat -c %s "$D/stacks.log" 2>/dev/null || echo absent) bytes"
        # the survivor's kernel log while its mount is still up, before any unmount
        timeout 60 "$SSH" $A "dmesg | tail -300" 2>/dev/null > "$D/dmesg_survivor_at_stall.log"
        timeout 60 "$SSH" $B "dmesg | tail -300" 2>/dev/null > "$D/dmesg_victim_at_stall.log"
        unmount_both
        exit 1
    fi
    unmount_both
done
say "all $LAPS laps passed"
exit 0
