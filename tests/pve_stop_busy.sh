#!/bin/bash
# pve_stop_busy.sh — a clean stop of mxfs-drbd@<res> on an MXFS-on-DRBD
# Proxmox pair while a process briefly holds the mountpoint.
#
# The unit's stop (mxfs-drbd-fence-self stop) used to make one umount attempt:
# on the physical pair (0.90.111) one stop in 32 was refused busy 2.1 s in,
# the unit failed with DRBD Primary under the still-mounted filesystem, and
# nothing named the holder.  The stop now retries a busy umount once a second
# for up to 30 s and names the holders.  This holds the mountpoint on the
# stopping host (a shell whose working directory is in it) for HOLD_S seconds,
# stops the unit, and requires: a "refused busy" line naming the holder, a
# "succeeded on attempt" line, the mount gone, the unit inactive within
# HOLD_S + 15 s, then the pair whole again after a start.
#
# Usage: tests/pve_stop_busy.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default the physical pair); the SECOND host stops
#   HOLD_S     seconds the holder keeps the mountpoint (default 5)
#   MOUNT_BUDGET  seconds for the start to bring the pair whole (default 300)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_stop_busy: PVE_PAIR must name two hosts"; exit 2; }
H=${PAIR[1]}
HOLD_S=${HOLD_S:-5}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
MNT=/mnt/shared
bad=0

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*"; }
whole() {
    on "$1" "grep -q ' $MNT mxfs ' /proc/mounts && [ \"\$(drbdadm role mxfs)\" = Primary/Primary ] && [ \"\$(drbdadm cstate mxfs)\" = Connected ] && [ \"\$(drbdadm dstate mxfs)\" = UpToDate/UpToDate ] && echo WHOLE" 20 | grep -q WHOLE
}

for h in "${PAIR[@]}"; do
    whole "$h" || { say "FAIL: $h is not whole; not starting"; exit 1; }
done
t_start=$(on "$H" "date +%s" 20)
on "$H" "nohup setsid bash -c 'cd $MNT && sleep $HOLD_S' > /dev/null 2>&1 < /dev/null & echo HOLDER_STARTED" 20 | grep -q HOLDER_STARTED || { say "FAIL: holder did not start"; exit 1; }
sleep 1
t0=$(date +%s)
on "$H" "systemctl stop mxfs-drbd@mxfs" $((HOLD_S + 200)) >/dev/null
wall=$(( $(date +%s) - t0 ))
unit=$(on "$H" "systemctl is-active mxfs-drbd@mxfs" 20)
mounted=$(on "$H" "grep -c ' $MNT mxfs ' /proc/mounts" 20)
log=$(on "$H" "journalctl -t mxfs-drbd-fence-self --since @$t_start --no-pager -o cat" 30)
refused=$(grep -a 'refused busy' <<<"$log" | head -1)
succeeded=$(grep -a 'succeeded on attempt' <<<"$log" | head -1)
say "$H stop: wall=${wall}s unit=$unit mounted=$mounted"
say "  refused: ${refused:-none}"
say "  succeeded: ${succeeded:-none}"
grep -qE '(bash|sleep)\(' <<<"$refused" || { say "FAIL: the busy refusal did not name the holding shell"; bad=1; }
[ -n "$succeeded" ] || { say "FAIL: no later umount attempt succeeded"; bad=1; }
[ "$unit" = inactive ] && [ "$mounted" = 0 ] || { say "FAIL: the stop did not leave the unit inactive and the mount gone"; bad=1; }
[ "$wall" -le $((HOLD_S + 15)) ] || { say "FAIL: the stop took ${wall}s, more than HOLD_S + 15"; bad=1; }
on "$H" "systemctl reset-failed mxfs-drbd@mxfs 2>/dev/null; systemctl start --no-block mxfs-drbd@mxfs" 30 >/dev/null
t1=$(date +%s)
until whole "$H"; do
    [ $(( $(date +%s) - t1 )) -lt "$MOUNT_BUDGET" ] || { say "FAIL: $H not whole again within ${MOUNT_BUDGET}s"; bad=1; break; }
    sleep 5
done
say "$H whole again after $(( $(date +%s) - t1 ))s"
[ "$bad" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
exit "$bad"
