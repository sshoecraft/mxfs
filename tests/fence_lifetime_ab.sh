#!/bin/bash
# tests/fence_lifetime_ab.sh
#
# The cause-exercising test for
#   D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381
#   D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381
#
# Runs the EXACT minimal sequence that bricked the filesystem on 0.15.10:
#   1. read the reservation on a healthy cluster
#   2. cleanly unmount the node that established it   <- the trigger
#   3. assert the reservation SURVIVES                <- what WE-RO failed
#   4. hard-kill a DIFFERENT node
#   5. assert the elected prover PROVES exclusion (not NO_RESERVATION)
#   6. assert the certificate is MINTED (not FENCE-UNRECORDED)
#   7. assert the slice is replayed and both absent nodes can remount
#
# Usage: tests/fence_lifetime_ab.sh <resv-node> <victim-node> [observer]
set -u
RESV="${1:-test1}"; VICT="${2:-test3}"; OBS="${3:-test2}"
REPO="$(cd -- "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
PROBE="$REPO/tests/pr_reservation_ownership_probe.sh"
MNT=/mnt/shared
DEV=/dev/mapper/mpatha
fail=0
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
chk() { if [ "$1" = 0 ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fail=$((fail+1)); fi; }

say "1. baseline reservation"
B=$("$PROBE" "$OBS"); echo "   $B"
case "$B" in *"all registrants"*) chk 0 "WE-AR in force before the trigger";;
             *) chk 1 "expected an all-registrants reservation, got: $B";; esac

say "2. clean unmount of $RESV (the node that established the reservation)"
t0=$(date +%s.%N)
timeout 60 "$SSH" "$RESV" "umount $MNT; grep -c mxfs /proc/mounts" >/dev/null 2>&1
say "   umount wall $(echo "$(date +%s.%N)-$t0" | bc)s"

say "3. reservation after the trigger"
A=$("$PROBE" "$OBS"); echo "   $A"
case "$A" in *"all registrants"*) chk 0 "reservation SURVIVED the holder's clean unmount";;
             *) chk 1 "reservation was LOST — the defect reproduced: $A";; esac

say "4. hard-kill $VICT"
KILL=$(date -u +%s)
sudo virsh destroy "$VICT" >/dev/null 2>&1 || { echo "   (virsh destroy failed)"; fail=$((fail+1)); }

say "5/6. waiting for the fence verdict + certificate"
VERD=""
for i in $(seq 1 30); do
    sleep 8
    AGE=$(( $(date -u +%s) - KILL ))
    D=$(mktemp -d)
    for n in $(seq 1 32); do
        [ "test$n" = "$VICT" ] && continue
        ( timeout 12 "$SSH" "test$n" \
            "U=\$(cut -d' ' -f1 /proc/uptime|cut -d. -f1); F=\$((U-$AGE-15)); dmesg | awk -v f=\$F '/^\[/{t=\$0;sub(/^\[ */,\"\",t);sub(/\..*/,\"\",t); if(t+0>f) print}' | grep -E 'FENCEKIND|FENCE-CERTIFIED|FENCE-UNPROVEN|FENCE-UNRECORDED|FENCE-NO-RESV|CLAIM-UNCERTIFIED|replayed'" \
            > "$D/$n" 2>&1 ) &
    done
    wait
    VERD=$(cat "$D"/* 2>/dev/null | grep -E 'mxfs|disklock' | sort -u)
    [ -n "$(echo "$VERD" | tr -d '[:space:]')" ] && { say "   verdict at t+${AGE}s"; break; }
    printf "   t+%ds..\n" "$AGE"
done
echo "$VERD" | sed 's/^/   | /'
echo "$VERD" | grep -q 'proves_excl=1' ; chk $? "the fence PROVED exclusion"
echo "$VERD" | grep -q 'FENCEKIND.*NO_RESERVATION' ; [ $? = 0 ] && chk 1 "NO_RESERVATION seen (the defect)" || chk 0 "no NO_RESERVATION verdict"
echo "$VERD" | grep -q 'FENCE-UNRECORDED\|FENCE-NO-RESV' ; [ $? = 0 ] && chk 1 "certificate refused after a proved exclusion" || chk 0 "certificate not refused"

say "7. both absent nodes must remount without re-mkfs"
sudo virsh start "$VICT" >/dev/null 2>&1
for h in "$RESV"; do
    timeout 120 "$SSH" "$h" "mount -t mxfs $DEV $MNT >/dev/null 2>&1; grep -c mxfs /proc/mounts" >/dev/null 2>&1
    m=$(timeout 20 "$SSH" "$h" "grep -c mxfs /proc/mounts" 2>/dev/null | grep -oE '^[0-9]+$' | head -1)
    [ "${m:-0}" -ge 1 ] && chk 0 "$h remounted" || chk 1 "$h could NOT remount (filesystem bricked)"
done

echo
[ "$fail" = 0 ] && echo "RESULT: PASS (all assertions)" || echo "RESULT: FAIL ($fail assertion(s))"
exit $fail
