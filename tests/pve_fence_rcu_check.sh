#!/bin/bash
# pve_fence_rcu_check.sh — does participant 0's exclusion of its peer still
# trip the DRBD 8.4 driver's sleep inside an RCU read section?
#
# When the fence handler answered 7 with the I/O still frozen, the driver
# rotated the current UUID inside rcu_read_lock() and the kernel logged
# "Voluntary context switch within RCU read-side critical section!" (a
# WARN_ONCE: the first exclusion of each boot).  The handler now resumes the
# I/O itself first (tools/mxfs_drbd_fence_self.py resume_frozen_io).
#
# The warning fires once per boot, so participant 0 is restarted first (cleanly:
# its unit unmounts and steps down, and it rejoins), then tests/pve_pair_failover.sh
# p1-crash resets participant 1 under load and participant 0 excludes it.  Then
# participant 0's kernel log since that boot is read: no RCU warning, the
# handler's answer, DRBD's freeze ended, the peer recorded Outdated.
#
# Usage: tests/pve_fence_rcu_check.sh
# Env:   PVE_PAIR (default the nested pair "192.168.120.137 192.168.120.192");
#        participant 0 is the lower address.
# Evidence: tests/evidence/pve_fence_rcu_check/<UTC stamp>-<participant 0>/,
# and the p1-crash run's own under tests/evidence/pve_pair_failover/.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
export PVE_PAIR=${PVE_PAIR:-192.168.120.137 192.168.120.192}
read -r -a PAIR <<<"$PVE_PAIR"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_fence_rcu_check: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
# From the reboot to participant 0 answering ssh (BOOT_BUDGET of the suite),
# then to it mounted as half of the pair again (REJOIN_BUDGET of the suite).
BOOT_BUDGET=${BOOT_BUDGET:-300}
REJOIN_BUDGET=180
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}
else
    P0=${PAIR[1]}
fi
EVID="$REPO/tests/evidence/pve_fence_rcu_check/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
die() { say "FAIL: $*"; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
STATE_CMD='echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) boot=$(cat /proc/sys/kernel/random/boot_id)"'

# 1. participant 0 restarted, so the warning is armed again
b0=$(on "$P0" "cat /proc/sys/kernel/random/boot_id" 20)
[ -n "$b0" ] || die "$P0 does not answer"
on "$P0" "nohup setsid sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 < /dev/null & echo REBOOTING" 15 | grep -q REBOOTING || die "could not reboot $P0"
say "rebooting $P0 (participant 0)"
t0=$(date +%s)
while :; do
    s=$(on "$P0" "$STATE_CMD" 20 | grep '^unit=')
    case "$s" in *"boot=$b0"*|"") ;; *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate "*) break ;; esac
    [ $(( $(date +%s) - t0 )) -lt $(( BOOT_BUDGET + REJOIN_BUDGET )) ] || die "$P0 not back as half of the pair within $(( BOOT_BUDGET + REJOIN_BUDGET ))s: ${s:-no answer}"
    sleep 5
done
say "$P0 back and mounted $(( $(date +%s) - t0 )) s after the reboot began"
n=$(on "$P0" "journalctl -k -b --no-pager -o cat | grep -c 'Voluntary context switch within RCU'" 30)
[ "${n:-x}" = 0 ] || die "$P0 logged the RCU warning before any exclusion this boot ($n)"

# 2. participant 1 reset under load; participant 0 excludes it
"$REPO/tests/pve_pair_failover.sh" p1-crash 2>&1 | tee -a "$EVID/log"
rc=${PIPESTATUS[0]}
say "p1-crash rc=$rc"

# 3. participant 0's kernel log this boot
on "$P0" "journalctl -k -b --no-pager -o short-monotonic | grep -aE 'drbd|Voluntary context switch|rcu_note_context_switch|mxfs-drbd-fence-self' | cut -c1-300" 60 > "$EVID/klog.$P0"
warn=$(grep -c 'Voluntary context switch within RCU' "$EVID/klog.$P0")
helper=$(grep -aoE 'fence-peer helper returned [0-9]+' "$EVID/klog.$P0" | sort | uniq -c | tr '\n' ' ')
resumed=$(grep -ac 'susp( 1 -> 0 )\|susp_fen( 1 -> 0 )\|susp-fen( 1 -> 0 )' "$EVID/klog.$P0")
outdated=$(grep -ac 'pdsk( DUnknown -> Outdated )' "$EVID/klog.$P0")
failed=$(grep -ac 'resume-io .* exited\|resume-io .* has not returned\|resume-io .* could not start' "$EVID/klog.$P0")
say "$P0 this boot: rcu_warning=$warn helper{$helper} freeze_ended=$resumed peer_outdated=$outdated resume_failures=$failed"
[ "$rc" = 0 ] || die "p1-crash failed (rc=$rc)"
[ -n "$helper" ] || die "$P0 ran no fence-peer handler: nothing was tested"
[ "$failed" = 0 ] || die "the handler's resume-io failed on $P0"
[ "$warn" = 0 ] || die "$P0 logged the RCU warning at the exclusion"
say "PASS"
