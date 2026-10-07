#!/bin/bash
# pve_chk_unreplayed.sh — chk_mxfs on a filesystem whose journals no mount has
# replayed, on a two-host Proxmox pair running MXFS on DRBD.
#
# On the physical pair both mounts withdrew and the hosts were stopped with no
# mount since; chk_mxfs -n then reported the superblock's lazy inode counter as
# an error and advised a repair, while the journals still held the allocations
# that explain it.  chk_mxfs must instead say the journals are not replayed,
# give no verdict (-n exits 8, the counter comparisons as notes), refuse to
# write (-y exits 8), and in preen mode (-a, fsck.mxfs at boot) check and write
# nothing and exit 0, because the mount replays them.  One mount must then
# replay both journals, after which a clean stop leaves a clean check.
#
#  1. Both hosts create NFILES files in a directory of their own on the mount
#     and sync it: both journals hold allocations the platter's metadata and
#     superblock counters may not have yet.
#  2. Both guards are stopped (they would rejoin a withdrawn mount, which
#     replays it), and both heartbeats are paused past the 30 s authority
#     lease: both mounts withdraw, leaving their slices unreplayed.
#  3. Both units stop (unmount, step down, DRBD down).  DRBD comes up on both,
#     participant 0 is made Primary alone, and on it:
#       chk_mxfs -n  must exit 8, name both slots NOT REPLAYED, and report no
#                    superblock counter as an ERROR;
#       chk_mxfs -y  must exit 8, refuse, and change nothing (-n's summary
#                    after it equals the one before);
#       chk_mxfs -a  must exit 0 and say nothing was checked or repaired.
#  4. DRBD goes down again, both guards start, both units start, and both
#     hosts mount: the first mount replays both journals.  Every file both
#     hosts created must be there.
#  5. scripts/pve_pair_update.sh SKIP_INSTALL=1 CHECK=1: both units stop
#     cleanly, chk_mxfs -n must exit 0 (filesystem clean), both mount again.
#
# Usage: tests/pve_chk_unreplayed.sh
# Env:   PVE_PAIR "<addr> <addr>" (default "192.168.1.80 192.168.1.81";
#        participant 0 is the lower address), RES / MNT (default mxfs,
#        /mnt/shared), NFILES (default 300)
# Evidence: tests/evidence/pve_chk_unreplayed/<UTC stamp>-<participant 0>/.
#
# Refuses to start while any guest runs on either host: the units stop.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_chk_unreplayed: PVE_PAIR must name two hosts"; exit 2; }
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
NFILES=${NFILES:-300}
# The pause outlasts the 30 s authority lease by 15 s; the withdrawal shows
# within a few seconds of the lease running out.
PAUSE_MS=45000
WITHDRAW_BUDGET=60
# A unit stop: an unmount and DRBD down, measured at 3-12 s; twice the worst.
STOP_BUDGET=30
# DRBD up to Connected UpToDate/UpToDate on two disks that were in sync: the
# connect and a bitmap exchange, seconds; the update script allows 120 s.
CONNECT_BUDGET=120
# chk_mxfs on these filesystems: 8 s measured on the physical pair; it reads
# every btree and inode cluster, so its time follows the filesystem's size.
CHK_BUDGET=300
# Both units started on two unreplayed journals mount as after a pair outage:
# 143-148 s on the rig, 162 s on the physical pair; the failover test allows
# 300 s.
OUTAGE_BUDGET=300
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
T0=$(date +%s)

say() { echo "[$(date +%H:%M:%S) +$(( $(date +%s) - T0 ))s] $*" | tee -a "$EVID/log"; }
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
EVID="$REPO/tests/evidence/pve_chk_unreplayed/$STAMP-$P0"
mkdir -p "$EVID" || exit 1
STATE='echo "mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"' 2>/dev/null) cs=$(drbdadm cstate '"$RES"' 2>/dev/null) ds=$(drbdadm dstate '"$RES"' 2>/dev/null) build=$(cat /sys/module/mxfs/srcversion 2>/dev/null)"'
FAIL=0
bad() { say "FAIL: $*"; FAIL=1; }

say "chk_mxfs on unreplayed journals: participant 0 $P0, participant 1 $P1; evidence $EVID"
for h in "$P0" "$P1"; do
    run=$(on "$h" "qm list 2>/dev/null | awk 'NR > 1 && \$3 == \"running\" {print \$1}' | tr '\n' ' '" 30)
    [ -z "${run// /}" ] || die "$h is running guests ($run); stop them first"
    s=$(on "$h" "$STATE" 20)
    case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*) ;;
        *) die "$h is not mounted Primary/Primary, Connected, UpToDate: $s" ;; esac
    say "  $h: $s"
done

# 1. allocations in both journals, each host in a directory named for it
NAMES=""
for h in "$P0" "$P1"; do
    n=$(on "$h" "hostname" 20)
    [ -n "$n" ] || die "$h did not say its name"
    NAMES="$NAMES $n"
    out=$(on "$h" "d=$MNT/chk-unreplayed/$n; mkdir -p \$d && for i in \$(seq 1 $NFILES); do echo \$i > \$d/f.\$i || exit 1; done && sync -f \$d && echo MADE=\$(ls \$d | wc -l)" 120)
    grep -q "MADE=$NFILES" <<<"$out" || die "$h could not create its $NFILES files: $out"
done
say "1. both hosts ($NAMES ) created $NFILES files each and synced them"

# 2. no rejoin, then both mounts withdraw
for h in "$P0" "$P1"; do
    on "$h" "systemctl stop mxfs-drbd-guard && echo STOPPED" 30 | grep -q STOPPED || die "could not stop $h's guard"
done
for h in "$P0" "$P1"; do
    on "$h" "echo $PAUSE_MS > /sys/module/mxfs/parameters/dl_inject_hb_pause_ms && echo ARMED" 15 | grep -q ARMED \
        || die "could not pause $h's heartbeat (its guard is stopped: systemctl start mxfs-drbd-guard)"
done
t1=$(date +%s)
for h in "$P0" "$P1"; do
    until on "$h" "cat /sys/fs/mxfs/*/shutdown 2>/dev/null" 15 | grep -q '^1$'; do
        [ $(( $(date +%s) - t1 )) -lt $(( PAUSE_MS / 1000 + WITHDRAW_BUDGET )) ] \
            || die "$h's mount did not withdraw within $(( PAUSE_MS / 1000 + WITHDRAW_BUDGET ))s of the pause (guards stopped)"
        sleep 3
    done
    say "2. $h's mount withdrew $(( $(date +%s) - t1 )) s after the pause"
done

# 3. both units down, DRBD up, participant 0 Primary alone, the three checks
for h in "$P1" "$P0"; do
    on "$h" "systemctl stop mxfs-drbd@$RES; echo STOP_RC=\$?" "$STOP_BUDGET" | grep -q 'STOP_RC=0' \
        || die "$h: the unit did not stop within ${STOP_BUDGET}s (guards stopped)"
done
for h in "$P0" "$P1"; do
    on "$h" "drbdadm up $RES 2>&1; echo UP_RC=\$?" 60 | grep -q 'UP_RC=0' || die "$h: drbdadm up failed"
done
t2=$(date +%s)
until [ "$(on "$P0" "echo cs=\$(drbdadm cstate $RES) ds=\$(drbdadm dstate $RES)" 20)" = "cs=Connected ds=UpToDate/UpToDate" ]; do
    [ $(( $(date +%s) - t2 )) -lt "$CONNECT_BUDGET" ] || die "$P0: DRBD not Connected UpToDate/UpToDate within ${CONNECT_BUDGET}s"
    sleep 3
done
on "$P0" "drbdadm primary $RES && echo PRIMARY_OK" 60 | grep -q PRIMARY_OK || die "$P0 could not be made Primary for the check"
dev=$(on "$P0" "drbdadm sh-dev $RES" 20)
say "3. both units stopped; $P0 Primary alone on $dev for the checks"
chk() {  # <mode> <file>
    on "$P0" "chk_mxfs $1 $dev; echo CHK_RC=\$?" "$CHK_BUDGET" > "$EVID/$2"
    sed -n 's/^CHK_RC=//p' "$EVID/$2"
}
summary() { grep -a -E 'Journals|Superblock (icount|ifree|fdblocks)|inobt sum|BNO btree sum' "$EVID/$1"; }
rc=$(chk -n chk-n.txt)
say "   chk_mxfs -n: rc=${rc:-none}; $(grep -a -m1 'Journals' "$EVID/chk-n.txt")"
[ "$rc" = 8 ] || bad "chk_mxfs -n exited ${rc:-nothing}, not 8"
grep -a 'Journals' "$EVID/chk-n.txt" | grep -a -q 'NOT REPLAYED  (2 slice' || bad "chk_mxfs -n did not name both unreplayed slots"
grep -a -E 'ERROR: .*superblock (icount|ifree|fdblocks)' "$EVID/chk-n.txt" && bad "chk_mxfs -n reported a superblock counter as an error"
grep -a 'NOTE (journals not replayed)' "$EVID/chk-n.txt" | sed 's/^/   /' | tee -a "$EVID/log"
rc=$(chk -y chk-y.txt)
say "   chk_mxfs -y: rc=${rc:-none}; $(grep -a -m1 'repair refused' "$EVID/chk-y.txt" | cut -c1-80)"
[ "$rc" = 8 ] && grep -a -q 'repair refused' "$EVID/chk-y.txt" || bad "chk_mxfs -y did not refuse (rc=${rc:-none})"
grep -a -q 'REPAIRED' "$EVID/chk-y.txt" && bad "chk_mxfs -y wrote a repair"
rc=$(chk -n chk-n-after-y.txt)
[ "$(summary chk-n.txt)" = "$(summary chk-n-after-y.txt)" ] || bad "the filesystem's summary changed across chk_mxfs -y"
rc=$(chk -a chk-a.txt)
say "   chk_mxfs -a: rc=${rc:-none}; $(grep -a -m1 'nothing checked' "$EVID/chk-a.txt" | cut -c1-80)"
[ "$rc" = 0 ] && grep -a -q 'nothing checked or repaired' "$EVID/chk-a.txt" || bad "chk_mxfs -a did not stand aside (rc=${rc:-none})"

# 4. back in service: the mount replays both journals
on "$P0" "drbdadm secondary $RES" 60 >/dev/null
for h in "$P1" "$P0"; do on "$h" "drbdadm down $RES" 60 >/dev/null; done
for h in "$P0" "$P1"; do
    on "$h" "systemctl start mxfs-drbd-guard && echo STARTED" 30 | grep -q STARTED || bad "could not start $h's guard"
    on "$h" "systemctl start --no-block mxfs-drbd@$RES" 30 >/dev/null
done
t3=$(date +%s)
for h in "$P0" "$P1"; do
    while :; do
        s=$(on "$h" "$STATE" 20)
        case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*) break ;; esac
        [ $(( $(date +%s) - t3 )) -lt "$OUTAGE_BUDGET" ] || die "$h not mounted again within ${OUTAGE_BUDGET}s: ${s:-no answer}"
        sleep 5
    done
    say "4. $h mounted again $(( $(date +%s) - t3 )) s after the units started"
done
for h in "$P0" "$P1"; do
    for n in $NAMES; do
        out=$(on "$h" "d=$MNT/chk-unreplayed/$n; k=0; for i in \$(seq 1 $NFILES); do [ \"\$(cat \$d/f.\$i 2>/dev/null)\" = \$i ] && k=\$((k + 1)); done; echo INTACT=\$k" 120)
        grep -q "INTACT=$NFILES" <<<"$out" || bad "$h sees $out of $n's $NFILES files"
    done
done
say "   every file both hosts created is intact on both"

# 5. a clean stop leaves a clean check
PVE_PAIR="$P0 $P1" SKIP_INSTALL=1 CHECK=1 "$REPO/scripts/pve_pair_update.sh" > "$EVID/clean-check.log" 2>&1
rc=$?
grep -a -E 'chk_mxfs -n|CHK_RC|FAIL|pair updated' "$EVID/clean-check.log" | sed 's/^/   /' | tee -a "$EVID/log"
[ "$rc" = 0 ] || bad "after the replay, the clean stop and check did not pass (see clean-check.log)"
for h in "$P0" "$P1"; do
    on "$h" "rm -rf $MNT/chk-unreplayed" 60 >/dev/null
done

if [ "$FAIL" = 0 ]; then
    say "PASS: chk_mxfs gave no verdict and wrote nothing on unreplayed journals; one mount replayed them; the clean check passed"
    exit 0
fi
say "FAIL: see above; evidence $EVID"
exit 1
