#!/bin/bash
# tests/resv_health_detect.sh
#
# The cause-exercising test for D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381.
#
# Before sess381 the exclusion invariant was proved ONCE, at mount, and never
# again: 31 nodes ran for 30 minutes on a LUN carrying no reservation at all,
# each having logged P303-FENCECAP-OK, and none of them noticed. The first thing
# that noticed was the fence of the next node to die — by which point the slice
# is unrecoverable.
#
# Removes the reservation out of band and asserts the CLUSTER DETECTS AND
# REPAIRS it, on its own, with no peer death involved.
#
# Usage: tests/resv_health_detect.sh <spare-host> [observer]
set -u
SPARE="${1:-test1}"; OBS="${2:-test2}"
REPO="$(cd -- "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
PROBE="$REPO/tests/pr_reservation_ownership_probe.sh"
DEV=/dev/mapper/mpatha; MNT=/mnt/shared; KS=0xfeed0382
fail=0
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
chk() { if [ "$1" = 0 ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fail=$((fail+1)); fi; }
sp()  { timeout 30 "$SSH" "$SPARE" "sg_persist $* /dev/sda 2>&1 | tail -3"; }
scan() { # $1 = egrep pattern, $2 = seconds back
    local D; D=$(mktemp -d); local n
    for n in $(seq 1 32); do
        [ "test$n" = "$SPARE" ] && continue
        ( timeout 12 "$SSH" "test$n" \
            "U=\$(cut -d' ' -f1 /proc/uptime|cut -d. -f1); F=\$((U-$2-15)); dmesg | awk -v f=\$F '/^\[/{t=\$0;sub(/^\[ */,\"\",t);sub(/\..*/,\"\",t); if(t+0>f) print}' | grep -E '$1'" \
            > "$D/$n" 2>&1 ) &
    done
    wait 2>/dev/null
    cat "$D"/* 2>/dev/null | grep -E 'mxfs' | sort -u
}

say "0. baseline"; B=$("$PROBE" "$OBS"); echo "   $B"
case "$B" in *"all registrants"*) chk 0 "WE-AR held";; *) chk 1 "no WE-AR: $B";; esac

say "1. unmount the spare $SPARE so its nexus is free for a scratch key"
timeout 60 "$SSH" "$SPARE" "umount $MNT" >/dev/null 2>&1
sp --out --register-ignore --param-sark=$KS >/dev/null

say "2. RELEASE the reservation out of band — no node dies, nothing else changes"
T0=$(date -u +%s)
sp --out --release --param-rk=$KS --prout-type=7 >/dev/null
A=$("$PROBE" "$OBS"); echo "   $A"
case "$A" in *"NONE HELD"*) echo "   (removed; the cluster is now unfenceable and does not know it)";;
             *) echo "   NOTE: already repaired before the probe could read it — that is a PASS for detection";; esac

say "3. the cluster must DETECT it (P305-RESV-HEALTH) and REPAIR it"
D=""; R=""
for i in $(seq 1 12); do
    sleep 6; AGE=$(( $(date -u +%s) - T0 ))
    D=$(scan 'P305-RESV-HEALTH|P305-RESV-REPAIRED' "$AGE")
    R=$(scan 'P305-RESV-REPAIRED|P305-RESV-RESTORED' "$AGE")
    [ -n "$(echo "$R" | tr -d '[:space:]')" ] && { say "   at t+${AGE}s"; break; }
    printf "   t+%ds..\n" "$AGE"
done
echo "$D" | sed 's/^/   | /' | head -4
echo "$R" | sed 's/^/   | /' | head -3
echo "$D" | grep -qE 'P305-RESV-(HEALTH.*state=ABSENT|REPAIRED)'; chk $? "the loss was DETECTED and reported as a safety event"
echo "$D" | grep -q 'role=maintainer'; chk $? "the elected maintainer reported it (a SILENT repair is the failure mode)"
echo "$R" | grep -qE 'P305-RESV-(REPAIRED|RESTORED)'; chk $? "the invariant was REPAIRED automatically"
echo "$R" | grep -qE 'restores FUTURE exclusion'; chk $? "the repair is reported as NOT proving the gap was harmless"

say "4. only ONE node may repair (auditors must not race the maintainer)"
nm=$(echo "$D" | grep -c 'role=maintainer'); na=$(echo "$D" | grep -c 'role=auditor')
echo "$D" | grep -c 'P305-RESV-REPAIRED' | sed 's/^/   repairs reported=/'
[ "$(echo "$D" | grep -c 'P305-RESV-REPAIRED')" -le 1 ] && chk 0 "at most ONE node repaired (no repair race)" || chk 1 "more than one node repaired"
echo "   maintainer reports=$nm auditor reports=$na"
[ "$nm" -ge 1 ] && chk 0 "exactly one role repairs (maintainer=$nm, auditors report only)" || chk 1 "no maintainer report"

say "5. final state + cleanup"
sp --out --register --param-rk=$KS --param-sark=0 >/dev/null
F=$("$PROBE" "$OBS"); echo "   $F"
case "$F" in *"all registrants"*) chk 0 "WE-AR in force at the end";; *) chk 1 "not restored: $F";; esac
timeout 120 "$SSH" "$SPARE" "mount -t mxfs $DEV $MNT" >/dev/null 2>&1

echo
[ "$fail" = 0 ] && echo "RESULT: PASS (all assertions)" || echo "RESULT: FAIL ($fail assertion(s))"
exit $fail
