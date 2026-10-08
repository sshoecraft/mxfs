#!/bin/bash
# pve_wedged_umount_reboot.sh — reboot one host of a nested Proxmox DRBD pair
# while its MXFS unmount is stuck in the kernel, and measure what the host's
# shutdown and the pair's recovery do about it.
#
# The unmount is held with the module's debug knob dbg_teardown_lease_hold_ms
# (the unmount sleeps in its teardown, unkillable, as a wedged DLM leaves it),
# then `systemctl reboot` is requested on the victim and nothing else is done
# to it.  Graded:
#   1. the victim's mxfs-drbd@ stop gives up on the umount within STOP_BUDGET
#      and says so, instead of sitting out systemd's stop timeouts;
#   2. the victim comes back with a new boot by itself within BOOT_BUDGET of
#      the request;
#   3. the victim's boot program stays Secondary until the survivor has
#      recovered its previous incarnation (it logs "has recovered this node's
#      previous incarnation", never "still owes a recovery after"), and no
#      mount on the new boot fails;
#   4. the victim is mounted again, Primary/Primary UpToDate on both, within
#      MOUNT_BUDGET of its new boot.
# Never on the physical pair: the victim is rebooted.  If the victim has no
# new boot at BOOT_BUDGET + 600 s it is reset with virsh (a lab VM), and the
# run fails.
#
# Usage: tests/pve_wedged_umount_reboot.sh
# Env:
#   VICTIM / SURVIVOR   addresses (default 192.168.120.192 / 192.168.120.137,
#                       nested pair A)
#   DOM                 the victim's libvirt domain (default pve9-1)
#   STOP_BUDGET         seconds for the unit's stop (default 180: its 170 s
#                       bound on the umount plus the unit's own teardown)
#   BOOT_BUDGET         seconds from the request to a new boot (default 600:
#                       measured 435 s on 0.90.97, stop 170 s + sync 30 s +
#                       systemd-shutdown's own waits + the nested VM's boot)
#   MOUNT_BUDGET        seconds from the new boot to mounted (default 300: the
#                       boot program's 180 s wait for the peer's recovery,
#                       DRBD connect, mount)
#   EVID                default tests/evidence/wedged_umount_reboot/<UTC stamp>-<DOM>
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
V=${VICTIM:-192.168.120.192}
S=${SURVIVOR:-192.168.120.137}
DOM=${DOM:-pve9-1}
STOP_BUDGET=${STOP_BUDGET:-180}
BOOT_BUDGET=${BOOT_BUDGET:-600}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
EVID=${EVID:-$REPO/tests/evidence/wedged_umount_reboot/$(date -u +%Y%m%dT%H%M%SZ)-$DOM}
mkdir -p "$EVID" || exit 1
LOG=$EVID/poll.log
T0=$(date +%s)
say() { echo "[$(date +%T) +$(( $(date +%s) - T0 ))s] $*" | tee -a "$LOG"; }
rs() {  # <host> <timeout> <cmd>
    timeout "$2" "$SSHP" "$1" "$3" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|disconnect immediately|^If you|^$'
}
FAIL=0
fail() { say "FAIL: $*"; FAIL=1; }

VCMD='echo "vb=$(cat /proc/sys/kernel/random/boot_id) role=$(timeout 5 drbdadm role mxfs 2>/dev/null) mnt=$(grep -c " /mnt/shared mxfs " /proc/mounts) $(grep -o "cs:[A-Za-z]* ro:[A-Za-z/]* ds:[A-Za-z/]*" /proc/drbd)"'
SCMD='echo "$(grep -o "cs:[A-Za-z]* ro:[A-Za-z/]* ds:[A-Za-z/]*" /proc/drbd) mnt=$(grep -c " /mnt/shared mxfs " /proc/mounts) osh=$(cat /sys/fs/mxfs/drbd0/other_slots_held 2>/dev/null) rp=$(cat /sys/fs/mxfs/drbd0/recovery_pending 2>/dev/null)"'

before=$(rs "$V" 20 "$VCMD" | grep '^vb=')
sbefore=$(rs "$S" 20 "$SCMD" | grep 'cs:')
say "victim $V ($DOM) before: ${before:-no answer}"
say "survivor $S before: ${sbefore:-no answer}"
case "$before" in *"role=Primary/Primary mnt=1 cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*) ;;
    *) say "FAIL: the victim is not mounted Primary/Primary UpToDate; nothing done"; exit 1 ;; esac
# a whole pair: the survivor counts exactly one slot besides its own, the
# victim's; it falls to 0 only once the victim's old incarnation is recovered
case "$sbefore" in *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate mnt=1 osh=1"*) ;;
    *) say "FAIL: the survivor is not mounted Primary/Primary UpToDate holding exactly the victim's slot; nothing done"; exit 1 ;; esac
OLD_VB=$(sed 's/^vb=\([^ ]*\).*/\1/' <<<"$before")
say "build: victim $(rs "$V" 20 'cat /sys/module/mxfs/srcversion') survivor $(rs "$S" 20 'cat /sys/module/mxfs/srcversion')"

# hold the next unmount, then request the reboot
say "victim: $(rs "$V" 20 'echo 1500000 > /sys/module/mxfs/parameters/dbg_teardown_lease_hold_ms; echo dbg_teardown_lease_hold_ms=$(cat /sys/module/mxfs/parameters/dbg_teardown_lease_hold_ms)')"
T0=$(date +%s)
say "reboot requested: $(rs "$V" 20 'systemd-run --no-block systemctl reboot; echo rc=$?')"

# phase 1: wait for the new boot
NEWVB=""; TNEW=""; reset_done=0
while :; do
    el=$(( $(date +%s) - T0 ))
    vout=$(rs "$V" 8 "$VCMD" | grep '^vb=' | tail -1)
    sout=$(rs "$S" 8 "$SCMD" | grep 'cs:' | tail -1)
    say "ph1 V[${vout:-unreachable}] S[${sout:-no answer}]"
    vb=$(sed -n 's/^vb=\([^ ]*\).*/\1/p' <<<"$vout")
    if [ ${#vb} -eq 36 ] && [ "$vb" != "$OLD_VB" ]; then NEWVB=$vb; TNEW=$el; break; fi
    if [ "$el" -ge $(( BOOT_BUDGET + 600 )) ] && [ $reset_done = 0 ]; then
        say "no new boot at +${el}s: virsh reset $DOM"
        virsh -c qemu:///system reset "$DOM" 2>&1 | tee -a "$LOG"; reset_done=1
    fi
    [ "$el" -ge $(( BOOT_BUDGET + 900 )) ] && break
    sleep 10
done
if [ -z "$NEWVB" ]; then
    fail "the victim never came back with a new boot"
    exit 1
fi
say "new boot $NEWVB at +${TNEW}s"
[ $reset_done = 1 ] && fail "the new boot came only after a virsh reset"
[ "$TNEW" -le "$BOOT_BUDGET" ] || fail "new boot at +${TNEW}s, budget ${BOOT_BUDGET}s"

# phase 2: watch the victim's promotion against the survivor's census
TN=$(date +%s); MOUNTED=""
while :; do
    vout=$(rs "$V" 8 "$VCMD" | grep '^vb=' | tail -1)
    sout=$(rs "$S" 8 "$SCMD" | grep 'cs:' | tail -1)
    since=$(( $(date +%s) - TN ))
    say "ph2 +${since}s V[${vout:-unreachable}] S[${sout:-no answer}]"
    case "$vout" in *"mnt=1 cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*)
        case "$sout" in *"ro:Primary/Primary ds:UpToDate/UpToDate mnt=1"*) MOUNTED=$since; break ;; esac ;; esac
    [ "$since" -ge "$MOUNT_BUDGET" ] && break
    sleep 5
done

# the victim's previous boot, from its own journal
rs "$V" 60 'journalctl -b -1 --no-pager -o short-precise' > "$EVID/victim-prev-boot-journal.txt"
rs "$V" 60 'journalctl -b 0 --no-pager -o short-precise' > "$EVID/victim-this-boot-journal.txt"
stop_from=$(grep -a 'Stopping mxfs-drbd@' "$EVID/victim-prev-boot-journal.txt" | tail -1 | awk '{print $3}')
stop_to=$(grep -aE 'Stopped mxfs-drbd@|mxfs-drbd@.*: Failed' "$EVID/victim-prev-boot-journal.txt" | tail -1 | awk '{print $3}')
stuck=$(grep -ac 'it is stuck in the kernel' "$EVID/victim-prev-boot-journal.txt")
if [ -n "$stop_from" ] && [ -n "$stop_to" ]; then
    stop_s=$(python3 -I -c 'import sys; f=lambda t: sum(float(x)*m for x, m in zip(t.split(":"), (3600, 60, 1))); print(round(f(sys.argv[2]) - f(sys.argv[1])))' "$stop_from" "$stop_to")
    say "victim's unit stop: $stop_from -> $stop_to = ${stop_s}s; 'stuck in the kernel' lines: $stuck"
    [ "$stop_s" -le "$STOP_BUDGET" ] || fail "the unit's stop took ${stop_s}s, budget ${STOP_BUDGET}s"
else
    fail "the victim's previous boot does not show the unit's stop (from='$stop_from' to='$stop_to')"
fi
[ "$stuck" -ge 1 ] || fail "the unit's stop never said the umount was stuck in the kernel"
busy=$(grep -ac 'already mounted or mount point busy' "$EVID/victim-this-boot-journal.txt")
say "victim's new boot: 'already mounted or mount point busy' lines: $busy"
[ "$busy" = 0 ] || fail "a mount on the new boot failed"
# The boot program's own decision (tools/mxfs_drbd_fence_self.py
# wait_peer_recovered).  A poll cannot judge it: the survivor's count goes
# 0 -> 1 again as soon as the victim's new mount claims its slot.
waited=$(grep -aE "has recovered this node's previous incarnation \([0-9]+ s\); promoting" "$EVID/victim-this-boot-journal.txt" | grep -a fence-self: | head -1)
anyway=$(grep -ac 'still owes a recovery after' "$EVID/victim-this-boot-journal.txt")
say "victim's boot program: ${waited:-no wait line}"
[ -n "$waited" ] || fail "the victim's boot program never waited for its peer to recover its previous incarnation"
[ "$anyway" = 0 ] || fail "the victim's boot program promoted while its peer still owed the recovery"
if [ -n "$MOUNTED" ]; then
    say "victim mounted, both Primary/Primary UpToDate, ${MOUNTED}s after its new boot was seen"
else
    fail "the victim was not mounted within ${MOUNT_BUDGET}s of its new boot"
fi
[ $FAIL = 0 ] && say "PASS: evidence $EVID" || say "FAILED: evidence $EVID"
exit $FAIL
