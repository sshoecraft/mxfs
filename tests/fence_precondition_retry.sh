#!/bin/bash
# tests/fence_precondition_retry.sh
#
# The cause-exercising test for D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381.
#
# A fence that returns BEFORE submitting any command consumed nothing and is
# safe to repeat — but until sess381 the outcome was published as a durable,
# terminal "exclusion not proved" and NOTHING EVER RETRIED IT, so a transient
# precondition failure permanently bricked the filesystem.
#
# This drives exactly that: remove the reservation out of band, kill a node so
# the fence hits its NO_RESERVATION precondition with no command submitted,
# then RESTORE the reservation and assert the fence is re-driven automatically
# and certifies — with no re-mkfs and no operator action.
#
# Usage: tests/fence_precondition_retry.sh <spare-host> <victim-host> [observer]
#   <spare-host> is unmounted by the test and used to issue the out-of-band
#   PROUT with a scratch key, so no mounted node's own registration is touched.
set -u
SPARE="${1:-test1}"; VICT="${2:-test5}"; OBS="${3:-test2}"
REPO="$(cd -- "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
PROBE="$REPO/tests/pr_reservation_ownership_probe.sh"
DEV=/dev/mapper/mpatha; MNT=/mnt/shared; KS=0xfeed0381
fail=0
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
chk() { if [ "$1" = 0 ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fail=$((fail+1)); fi; }
sp()  { timeout 30 "$SSH" "$SPARE" "sg_persist $* /dev/sda 2>&1 | tail -3"; }
# per-node dmesg since KILL, using each node's OWN uptime
scan() {
    local pat="$1" age="$2" D; D=$(mktemp -d)
    local n
    for n in $(seq 1 32); do
        [ "test$n" = "$VICT" ] && continue
        ( timeout 12 "$SSH" "test$n" \
            "U=\$(cut -d' ' -f1 /proc/uptime|cut -d. -f1); F=\$((U-$age-15)); dmesg | awk -v f=\$F '/^\[/{t=\$0;sub(/^\[ */,\"\",t);sub(/\..*/,\"\",t); if(t+0>f) print}' | grep -E '$pat'" \
            > "$D/$n" 2>&1 ) &
    done
    wait 2>/dev/null
    cat "$D"/* 2>/dev/null | grep -E 'mxfs|disklock' | sort -u
}

say "0. baseline"; B=$("$PROBE" "$OBS"); echo "   $B"
case "$B" in *"all registrants"*) chk 0 "WE-AR held";; *) chk 1 "no WE-AR: $B";; esac

say "1. unmount the spare $SPARE so its nexus is free for a scratch key"
timeout 60 "$SSH" "$SPARE" "umount $MNT" >/dev/null 2>&1
sp --out --register-ignore --param-sark=$KS >/dev/null

say "2. RELEASE the reservation out of band — the transient precondition failure"
sp --out --release --param-rk=$KS --prout-type=7 >/dev/null
A=$("$PROBE" "$OBS"); echo "   $A"
case "$A" in *"NONE HELD"*) chk 0 "reservation removed (fencing precondition now absent)";;
             *) chk 1 "could not remove the reservation: $A";; esac

say "3. hard-kill $VICT while the precondition is absent"
KILL=$(date -u +%s)
sudo virsh destroy "$VICT" >/dev/null 2>&1
# VERIFY THE KILL.  `virsh destroy` can leave a domain wedged in "in shutdown"
# with the guest still running and serving I/O (observed on clyde, sess381);
# a test that proceeds from there measures a cluster that never lost a node and
# reports the absence of a fence as a failure of the code under test.
vst=""
for i in $(seq 1 15); do
    vst=$(sudo virsh domstate "$VICT" 2>&1 | tr -d '\r' | head -1)
    case "$vst" in *"shut off"*) break;; esac
    sleep 2
done
case "$vst" in
  *"shut off"*) chk 0 "$VICT is shut off (the kill actually took effect)";;
  *) chk 1 "$VICT did NOT die - virsh domstate='$vst'. HARNESS/HOST FAULT, not an MXFS result; aborting"
     echo; echo "RESULT: FAIL (harness could not kill the victim)"; exit 1;;
esac

say "4. the fence must report PENDING (retryable), not terminal UNPROVEN"
V=""
for i in $(seq 1 20); do
    sleep 8; AGE=$(( $(date -u +%s) - KILL ))
    V=$(scan 'P238-FENCE-PENDING|P238-FENCE-UNPROVEN|FENCEKIND' "$AGE")
    [ -n "$(echo "$V" | tr -d '[:space:]')" ] && { say "   at t+${AGE}s"; break; }
    printf "   t+%ds..\n" "$AGE"
done
echo "$V" | sed 's/^/   | /'
echo "$V" | grep -q 'FENCEKIND.*NO_RESERVATION'; chk $? "the fence hit its NO_RESERVATION precondition (the case under test)"
echo "$V" | grep -q 'P238-FENCE-PENDING.*command_may_have_run=no.*retry=automatic'; chk $? "published as RETRYABLE PENDING, not terminal"
echo "$V" | grep -q 'P238-FENCE-UNPROVEN'; [ $? = 0 ] && chk 1 "terminal UNPROVEN published for a pre-command failure (the defect)" || chk 0 "no terminal UNPROVEN for a pre-command failure"

say "5. the retry worker must actually re-drive it while the precondition is still absent"
AGE=$(( $(date -u +%s) - KILL ))
R=$(scan 'P304-FENCE-RETRY ' "$AGE")
echo "$R" | sed 's/^/   | /' | head -4
n=$(echo "$R" | grep -c 'P304-FENCE-RETRY ')
[ "$n" -ge 1 ] && chk 0 "fence re-driven $n time(s) while blocked" || chk 1 "no retry was ever attempted"

say "6. RESTORE the reservation — the precondition returns"
sp --out --reserve --param-rk=$KS --prout-type=7 >/dev/null
C=$("$PROBE" "$OBS"); echo "   $C"
case "$C" in *"all registrants"*) chk 0 "WE-AR restored";; *) chk 1 "restore failed: $C";; esac

say "7. the standing attempt must now certify BY ITSELF"
OK=""
for i in $(seq 1 20); do
    sleep 8; AGE=$(( $(date -u +%s) - KILL ))
    OK=$(scan 'P304-FENCE-RETRY-OK|P236-FENCE-CERTIFIED' "$AGE")
    [ -n "$(echo "$OK" | tr -d '[:space:]')" ] && { say "   at t+${AGE}s"; break; }
    printf "   t+%ds..\n" "$AGE"
done
echo "$OK" | sed 's/^/   | /'
echo "$OK" | grep -q 'P236-FENCE-CERTIFIED'; chk $? "the retried fence CERTIFIED exclusion with no operator action"

say "8. cleanup + the filesystem must not be bricked"
sp --out --register --param-rk=$KS --param-sark=0 >/dev/null
sudo virsh start "$VICT" >/dev/null 2>&1
timeout 120 "$SSH" "$SPARE" "mount -t mxfs $DEV $MNT" >/dev/null 2>&1
m=$(timeout 20 "$SSH" "$SPARE" "grep -c mxfs /proc/mounts" 2>/dev/null | grep -oE '^[0-9]+$' | head -1)
[ "${m:-0}" -ge 1 ] && chk 0 "$SPARE remounted (filesystem not bricked)" || chk 1 "$SPARE could NOT remount"

echo
[ "$fail" = 0 ] && echo "RESULT: PASS (all assertions)" || echo "RESULT: FAIL ($fail assertion(s))"
exit $fail
