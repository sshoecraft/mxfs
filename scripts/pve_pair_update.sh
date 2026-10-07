#!/bin/bash
# pve_pair_update.sh — bring a two-host Proxmox pair running MXFS on DRBD to
# the build that was just pushed, the way a user does it, and swap the running
# module for it.
#
# On each host, at the same time: `cd /root/mxfs && git fetch && git pull &&
# make install OVERWRITE=1` (the clone a user makes), logged on the host to
# /root/mxfs-update.log.  Then both mounts stop (the unit unmounts and steps
# down), optionally the filesystem is checked from participant 0 while
# nothing has it mounted, the old module is unloaded and the new one loaded on
# both, and both units start; done when both are mounted again,
# Primary/Primary, Connected, UpToDate, on the one new build.
#
# Usage: scripts/pve_pair_update.sh
# Env:
#   PVE_PAIR       "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#                  participant 0 is the lower address
#   RES / MNT      DRBD resource and mount point (default mxfs, /mnt/shared)
#   CHECK=1        run `chk_mxfs -n` (check only) on participant 0 between the
#                  stop and the start; a finding stops the update there
#   SKIP_INSTALL=1 no pull and build: swap to the module already installed
#                  (with CHECK=1, a filesystem check of a running pair)
#   INSTALL_BUDGET seconds for the pull and build on a host (default 900: a
#                  full DKMS-style build on the slower physical host is ~6 min)
#   MOUNT_BUDGET   seconds from the units' start to both mounted (default 300:
#                  the mount's heartbeat scan ~64 s, DRBD connect and the boot
#                  program's ordering, twice over)
#   CHECK_BUDGET   seconds for chk_mxfs (default 600)
#   CHECK_OUT      where the check's whole report is kept (default
#                  tests/evidence/pve_pair_update/chk-<UTC stamp>-<participant 0>.txt);
#                  only its last lines are printed, and a finding needs all of it
#
# Refuses to start while anything holds the mount on either host, a running
# guest whose disk is on it above all: stopping the unit unmounts it.  Guests
# whose disks are on other storage (local, local-lvm) keep running; nothing
# here touches them.  Prints each step with its wall time; exits non-zero at
# the first step that fails, saying what it left.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_update: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
INSTALL_BUDGET=${INSTALL_BUDGET:-900}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
CHECK_BUDGET=${CHECK_BUDGET:-600}
T0=$(date +%s)

say() { echo "[$(date +%H:%M:%S) +$(( $(date +%s) - T0 ))s] $*"; }
die() { say "FAIL: $*"; exit 1; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
STATE_CMD='echo "unit=$(systemctl is-active mxfs-drbd@'"$RES"') mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null) ver=$(cat /sys/module/mxfs/version 2>/dev/null) tree=$(cat /root/mxfs/VERSION 2>/dev/null)"'
state() { on "$1" "$STATE_CMD" 20 | grep '^unit='; }

for h in "$P0" "$P1"; do
    # every process with a file open on the mount, by pid and name
    held=$(on "$h" "awk '\$2 == \"$MNT\" && \$3 == \"mxfs\"' /proc/mounts | grep -q . || exit 0; fuser -m $MNT 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+' | tr -dc '0-9\n' | while read -r p; do echo \"\$p:\$(cat /proc/\$p/comm 2>/dev/null)\"; done | tr '\n' ' '" 30)
    [ -z "${held// /}" ] || die "$h: processes hold $MNT ($held); stop them (qm stop for a guest whose disk is there) before the update"
    say "$h before: $(state "$h")"
done

# 1. pull and build on both hosts at once (SKIP_INSTALL=1: the build already
# installed is the one to run — a check and a module swap only)
for h in "$P0" "$P1"; do
    [ "${SKIP_INSTALL:-0}" = 1 ] && break
    on "$h" "test -d /root/mxfs/.git || { echo NO_CLONE; exit 1; }; rm -f /root/mxfs-update.log; nohup setsid bash -c 'cd /root/mxfs && { git fetch && git pull && make install OVERWRITE=1; } > /root/mxfs-update.log 2>&1; echo UPDATE_RC=\$? >> /root/mxfs-update.log' >/dev/null 2>&1 </dev/null & echo LAUNCHED" 30 | grep -q LAUNCHED || die "$h: could not start the update"
done
for h in "$P0" "$P1"; do
    [ "${SKIP_INSTALL:-0}" = 1 ] && break
    rc=""
    while [ $(( $(date +%s) - T0 )) -lt "$INSTALL_BUDGET" ]; do
        rc=$(on "$h" "sed -n 's/^UPDATE_RC=//p' /root/mxfs-update.log" 20)
        [ -n "$rc" ] && break
        sleep 10
    done
    [ -n "$rc" ] || die "$h: the update did not finish within ${INSTALL_BUDGET}s (budget exceeded); its log: /root/mxfs-update.log"
    on "$h" "grep -aE '^(Updating|Fast-forward|Already up to date)|error|Error' /root/mxfs-update.log | head -5; tail -2 /root/mxfs-update.log" 20 | sed "s/^/  $h: /"
    [ "$rc" = 0 ] || die "$h: the update exited $rc; its log: /root/mxfs-update.log"
    say "$h installed: $(on "$h" "echo tree=\$(cat /root/mxfs/VERSION) installed=\$(modinfo -F version mxfs) \$(modinfo -F srcversion mxfs)" 20)"
done
NEW=$(on "$P0" "modinfo -F srcversion mxfs" 20)
[ "$NEW" = "$(on "$P1" "modinfo -F srcversion mxfs" 20)" ] || die "the two hosts built different modules"

# 2. both mounts down
for h in "$P1" "$P0"; do
    on "$h" "systemctl stop mxfs-drbd@$RES; echo STOP_RC=\$?" 240 | grep -q 'STOP_RC=0' \
        || die "$h: the unit did not stop: $(on "$h" "journalctl -u mxfs-drbd@$RES --since -5min --no-pager | tail -8" 20)"
    say "$h stopped: $(state "$h")"
done

# 3. optionally, check the filesystem nothing has mounted.  The stopped units
# took DRBD down on both, the second one's disk Outdated by its own graceful
# exit; DRBD only promotes a node with its peer connected (anything else is
# the fence handler's call, which refuses), so both come up and connect, the
# Outdated one resyncs, participant 0 is promoted alone for the check, and
# both go back down for the units to start them.
if [ "${CHECK:-0}" = 1 ]; then
    for h in "$P0" "$P1"; do
        on "$h" "drbdadm up $RES 2>&1; echo UP_RC=\$?" 60 | grep -q 'UP_RC=0' || die "$h: drbdadm up failed (both units are stopped)"
    done
    T2=$(date +%s)
    while :; do
        s=$(on "$P0" "echo cs=\$(drbdadm cstate $RES) ds=\$(drbdadm dstate $RES)" 20)
        [ "$s" = "cs=Connected ds=UpToDate/UpToDate" ] && break
        [ $(( $(date +%s) - T2 )) -lt 120 ] || die "$P0: DRBD not Connected UpToDate/UpToDate within 120s for the check: $s (both units are stopped, DRBD up)"
        sleep 3
    done
    dev=$(on "$P0" "drbdadm sh-dev $RES" 20)
    on "$P0" "drbdadm primary $RES && echo PRIMARY_OK" 60 | grep -q PRIMARY_OK || die "$P0: could not be made Primary for the check (both units are stopped, DRBD up)"
    out=$(on "$P0" "chk_mxfs -n $dev; echo CHK_RC=\$?" "$CHECK_BUDGET")
    CHECK_OUT=${CHECK_OUT:-$REPO/tests/evidence/pve_pair_update/chk-$(date -u +%Y%m%dT%H%M%SZ)-$P0.txt}
    mkdir -p "$(dirname -- "$CHECK_OUT")" && echo "$out" > "$CHECK_OUT"
    echo "$out" | tail -15 | sed "s/^/  chk_mxfs: /"
    say "the check's whole report: $CHECK_OUT"
    crc=$(sed -n 's/^CHK_RC=//p' <<<"$out")
    on "$P0" "drbdadm secondary $RES" 60 >/dev/null
    for h in "$P1" "$P0"; do
        on "$h" "drbdadm down $RES" 60 >/dev/null
    done
    [ "$crc" = 0 ] || die "chk_mxfs found problems (rc=${crc:-none}); both units are stopped, nothing was repaired"
    say "chk_mxfs -n $dev on $P0: clean"
fi

# 4. the new module on both, then both units
for h in "$P0" "$P1"; do
    out=$(on "$h" "rmmod mxfs 2>&1; modprobe mxfs && echo LOADED \$(cat /sys/module/mxfs/version) \$(cat /sys/module/mxfs/srcversion); systemctl restart mxfs-drbd-guard" 60)
    grep -q "LOADED .* $NEW" <<<"$out" || die "$h: the new module did not load: $out"
    say "$h $(grep LOADED <<<"$out")"
done
for h in "$P0" "$P1"; do
    on "$h" "systemctl start --no-block mxfs-drbd@$RES" 30 >/dev/null
done
T1=$(date +%s)
for h in "$P0" "$P1"; do
    while :; do
        s=$(state "$h")
        case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate build=$NEW"*) break ;; esac
        [ $(( $(date +%s) - T1 )) -lt "$MOUNT_BUDGET" ] || die "$h not mounted on the new build within ${MOUNT_BUDGET}s: ${s:-no answer}"
        sleep 5
    done
    say "$h mounted: $s"
done
say "pair updated to $NEW in $(( $(date +%s) - T0 ))s"
