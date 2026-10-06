#!/bin/bash
# pve_cas_witness_stall.sh — a DRBD compare-and-swap that waits on the peer's
# ticket must not stall on the DRBD witness while the peer is Primary on a
# Connected link.
#
# On DRBD every MXFS coordination update, the heartbeat among them, is a
# compare-and-swap emulated with a bakery lock over two registers.  A swap
# that has waited on the peer's ticket for a second asks the witness (a
# userspace program the module starts) whether the peer is excluded or
# Secondary, holding its own published ticket meanwhile.  On the physical pair
# under VM installs (0.90.76) one such run took at least 21 s on a host short
# of memory: both hosts' heartbeat swaps failed and that host's authority
# lease expired, though the peer was Primary on a Connected link throughout,
# where neither answer can be yes.
#
# This makes the witness slow on purpose and makes a swap wait: on participant
# 1 the module's witness helper is pointed at a wrapper that sleeps SLOW_S
# before running the real one (a host that cannot start a process promptly);
# participant 0's next swap holds its ticket HOLD_MS inside its critical
# section (dbg_drbd_cas_hold_ms), so participant 1's heartbeat swap, every
# 2 s, waits on it for more than a second.  Then OBSERVE_S passes and both
# kernel logs since the start are read.
#
# Pass: participant 0 logged the hold; neither host ran the witness for it
# (no P-DRBD-CAS-PEER-NOT-EXCLUDED), neither host's swaps timed out
# (P-DRBD-CAS-WAIT-TIMEOUT), neither heartbeat stalled (P278-HB-STALL) and both
# kept their authority (no P290-AUTH-CLOSED / P131-SELF-FENCE); both still
# mounted.  Measured on 0.90.76 (the control): participant 1 waited out the slow
# witness holding its ticket, participant 0's swaps timed out waiting on it,
# and both hosts' leases expired.
#
# Usage: tests/pve_cas_witness_stall.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81");
#              participant 0 is the lower address
#   HOLD_MS    participant 0's ticket hold (default 5000: two of participant
#              1's heartbeat periods, under the swap's 10 s wait bound)
#   SLOW_S     the wrapper's sleep before the real witness (default 35: past
#              the 30 s authority lease)
#   OBSERVE_S  how long to watch after the hold is armed (default 60: the
#              wrapper's sleep plus the lease's last refusal, with margin)
#
# A participant 1 that withdraws is rejoined by its guard; the test waits for
# that (REJOIN_BUDGET) so the pair is left mounted either way.
#
# Evidence: tests/evidence/pve_cas_witness_stall/<UTC stamp>-<addr>/ — both
# kernel logs since the start and summary.txt.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_cas_witness_stall: PVE_PAIR must name two hosts"; exit 2; }
HOLD_MS=${HOLD_MS:-5000}
SLOW_S=${SLOW_S:-35}
OBSERVE_S=${OBSERVE_S:-60}
# A withdrawn participant 1 rejoined by its guard: the lease's end, the
# guard's 5 s poll, the unmount and the unit's mount as after a restart
# (~100 s on the nested pair), twice that.
REJOIN_BUDGET=300
RES=${RES:-mxfs}
MNT=${MNT:-/mnt/shared}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/pve_cas_witness_stall/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
# Not /run: Proxmox mounts it noexec, and the upcall's exec then fails at once
# (P-DRBDW-NOEXEC rc=-13), which tests nothing.
WRAP=/dev/shm/mxfs-slow-witness
PARAMS=/sys/module/mxfs/parameters

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
STATE_CMD='echo "mnt=$(awk '\''$2 == "'"$MNT"'" && $3 == "mxfs" {print $2}'\'' /proc/mounts | head -1) role=$(drbdadm role '"$RES"') cs=$(drbdadm cstate '"$RES"') ds=$(drbdadm dstate '"$RES"') build=$(cat /sys/module/mxfs/srcversion) ver=$(cat /sys/module/mxfs/version) shut=$(cat /sys/fs/mxfs/drbd0/shutdown 2>/dev/null)"'

for h in "$P0" "$P1"; do
    s=$(on "$h" "$STATE_CMD" 20)
    say "$h before: $s"
    case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*" shut=0") ;;
        *) say "ABORT: $h is not mounted, Primary/Primary, Connected, UpToDate"; exit 2 ;; esac
done

real=$(on "$P1" "cat $PARAMS/drbd_witness_helper" 15 | tr -d '[:space:]')
[ -n "$real" ] && [ "$real" != "$WRAP" ] || { say "ABORT: $P1's witness helper reads '$real'"; exit 2; }
t0=$(on "$P1" "date +%s" 10)
# The wrapper replaces nothing on disk: it lives in /run and only the module
# parameter points at it, restored below whatever happens.
on "$P1" "printf '#!/bin/sh\nsleep $SLOW_S\nexec $real \"\$@\"\n' > $WRAP && chmod 755 $WRAP && echo $WRAP > $PARAMS/drbd_witness_helper && echo WRAPPED" 15 | grep -q WRAPPED \
    || { say "ABORT: could not install the slow witness on $P1"; exit 2; }
restore() {
    on "$P1" "echo $real > $PARAMS/drbd_witness_helper; rm -f /dev/shm/mxfs-slow-witness; cat $PARAMS/drbd_witness_helper" 15 | sed "s/^/  $P1 witness helper restored: /" | tee -a "$SUM"
}
trap restore EXIT
say "$P1's witness helper now sleeps ${SLOW_S}s first; $P0's next swap holds its ticket ${HOLD_MS} ms"
on "$P0" "echo $HOLD_MS > $PARAMS/dbg_drbd_cas_hold_ms && echo ARMED" 15 | grep -q ARMED \
    || { say "ABORT: could not arm the hold on $P0"; exit 2; }
sleep "$OBSERVE_S"
restore
trap - EXIT

for h in "$P0" "$P1"; do
    on "$h" "journalctl -k --no-pager -o short-precise --since @$t0" 60 > "$EVID/klog.$h"
done
count() { grep -a -c -E "$2" "$EVID/klog.$1"; }
held=$(count "$P0" 'P-DBG-DRBD-CAS-HOLD')
noexec=$(count "$P1" 'P-DRBDW-NOEXEC')
FAIL=0
[ "$held" -ge 1 ] || { say "FAIL: $P0 never held its ticket: the test did not make a swap wait"; FAIL=1; }
[ "$noexec" = 0 ] || { say "FAIL: INVALID RUN: the slow witness could not be executed on $P1 (P-DRBDW-NOEXEC), so nothing was slowed"; FAIL=1; }
say "$P0: hold lines $held"
# Both hosts: a swap stuck in the slow witness on one holds its ticket, and
# the other's swaps wait on that (measured: on 0.90.76 both withdrew).
withdrew=0
for h in "$P0" "$P1"; do
    asked=$(count "$h" 'P-DRBD-CAS-PEER-(NOT-)?EXCLUDED|P-DRBD-CAS-PEER-SET-ASIDE')
    tmo=$(count "$h" 'P-DRBD-CAS-WAIT-TIMEOUT')
    stall=$(count "$h" 'P278-HB-STALL')
    closed=$(count "$h" 'P290-AUTH-CLOSED|P131-SELF-FENCE')
    say "$h: witness verdicts $asked, swap timeouts $tmo, heartbeat stalls $stall, authority closed $closed"
    grep -a -E 'P-DBG-DRBD-CAS-HOLD|P-DRBD-CAS-|P-DRBDW-|P278-HB-STALL|P290-AUTH-CLOSED|P131-SELF-FENCE' "$EVID/klog.$h" \
        | cut -c1-240 | head -8 | sed "s/^/  $h: /" | tee -a "$SUM"
    [ "$asked" = 0 ] || { say "FAIL: $h ran the witness while its peer was Primary on a Connected link"; FAIL=1; }
    [ "$tmo" = 0 ] || { say "FAIL: $h's swaps timed out waiting on the peer's ticket"; FAIL=1; }
    [ "$stall" = 0 ] || { say "FAIL: $h's heartbeat stalled"; FAIL=1; }
    [ "$closed" = 0 ] || { say "FAIL: $h lost its authority and withdrew"; FAIL=1; withdrew=1; }
done

if [ "$withdrew" != 0 ]; then
    say "waiting up to ${REJOIN_BUDGET}s for the guards to rejoin the withdrawn mounts"
    tw=$(date +%s)
    while [ $(( $(date +%s) - tw )) -lt "$REJOIN_BUDGET" ]; do
        up=0
        for h in "$P0" "$P1"; do
            s=$(on "$h" "$STATE_CMD" 20)
            case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*" shut=0") up=$(( up + 1 )) ;; esac
        done
        [ "$up" = 2 ] && break
        sleep 5
    done
fi
for h in "$P0" "$P1"; do
    s=$(on "$h" "$STATE_CMD" 20)
    say "$h after: $s"
    case "$s" in *"mnt=$MNT role=Primary/Primary cs=Connected ds=UpToDate/UpToDate"*" shut=0") ;;
        *) say "FAIL: $h is not mounted, Primary/Primary, Connected, UpToDate"; FAIL=1 ;; esac
done
if [ "$FAIL" = 0 ]; then
    say "PASS: evidence $EVID"
    exit 0
fi
say "FAIL: evidence $EVID"
exit 1
