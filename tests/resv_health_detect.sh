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
MNT=/mnt/shared; KS=0xfeed0382
fail=0
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
chk() { if [ "$1" = 0 ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fail=$((fail+1)); fi; }

# The shared LUN is a different device on each rig condition, and the spare is
# about to be unmounted, so read it from the OBSERVER's live mount.  A wrong
# device here does not fail loudly — it makes every sg_persist error out and
# the probe report "no reservation" as though it had observed one absent.
DEV="${MXFS_DEV:-}"
[ -n "$DEV" ] || DEV=$(timeout 25 "$SSH" "$OBS" \
    "awk '\$3==\"mxfs\" {print \$1; exit}' /proc/mounts" 2>/dev/null | tr -d '\r\n')
[ -n "$DEV" ] || { echo "FATAL: no mxfs mount on $OBS and MXFS_DEV unset"; exit 2; }
say "device=$DEV spare=$SPARE observer=$OBS"
sp()  { timeout 30 "$SSH" "$SPARE" "sg_persist $* $DEV 2>&1 | tail -3"; }
# Which nodes to sweep.  Defaulting to all 32 costs 30 doomed ssh timeouts per
# sample on a 2-node rig, which both slows the lap and buries the evidence.
NODES="${MXFS_NODE_LIST:-$(seq -f 'test%g' 1 32 | tr '\n' ' ')}"

scan() { # $1 = egrep pattern, $2 = seconds back
    local D; D=$(mktemp -d); local n
    for n in $NODES; do
        [ "$n" = "$SPARE" ] && continue
        ( timeout 12 "$SSH" "$n" \
            "U=\$(cut -d' ' -f1 /proc/uptime|cut -d. -f1); F=\$((U-$2-15)); dmesg | awk -v f=\$F '/^\[/{t=\$0;sub(/^\[ */,\"\",t);sub(/\..*/,\"\",t); if(t+0>f) print}' | grep -E '$1'" \
            > "$D/$n" 2>&1 ) &
    done
    wait 2>/dev/null
    cat "$D"/* 2>/dev/null | grep -E 'mxfs' | sort -u
}

say "0. baseline"; B=$("$PROBE" "$OBS" "$DEV"); echo "   $B"
case "$B" in *"all registrants"*) chk 0 "WE-AR held";; *) chk 1 "no WE-AR: $B";; esac

say "1. unmount the spare $SPARE so its nexus is free for a scratch key"
timeout 60 "$SSH" "$SPARE" "umount $MNT" >/dev/null 2>&1
sp --out --register-ignore --param-sark=$KS >/dev/null

say "2. RELEASE the reservation out of band — no node dies, nothing else changes"
T0=$(date -u +%s)
sp --out --release --param-rk=$KS --prout-type=7 >/dev/null
A=$("$PROBE" "$OBS" "$DEV"); echo "   $A"
case "$A" in *"NONE HELD"*) echo "   (removed; the cluster is now unfenceable and does not know it)";;
             *) echo "   NOTE: already repaired before the probe could read it — that is a PASS for detection";; esac

# The bound is derived, not chosen for comfort.  The spare this harness
# unmounts is usually the node holding the LOWEST heartbeat slot, i.e. the
# elected maintainer, so the repair has to come from a stand-in: worst case is
# one full auditor audit interval before the survivor next looks (60 s), plus
# the maintainer's head start and one rank step before it may act (20 s).  A
# repair after that is the defect this harness exists to catch — the survivor
# reporting the loss and leaving the LU unreserved.
BOUND=100
say "3. the cluster must DETECT it (P305-RESV-HEALTH) and REPAIR it, within ${BOUND}s"
D=""; R=""; T_REPAIR=""
for i in $(seq 1 20); do
    sleep 6; AGE=$(( $(date -u +%s) - T0 ))
    D=$(scan 'P305-RESV-HEALTH|P305-RESV-REPAIRED' "$AGE")
    R=$(scan 'P305-RESV-REPAIRED|P305-RESV-RESTORED' "$AGE")
    [ -n "$(echo "$R" | tr -d '[:space:]')" ] && { T_REPAIR=$AGE; say "   at t+${AGE}s"; break; }
    [ "$AGE" -gt "$BOUND" ] && { say "   still unreserved at t+${AGE}s"; break; }
    printf "   t+%ds..\n" "$AGE"
done
echo "$D" | sed 's/^/   | /' | head -4
echo "$R" | sed 's/^/   | /' | head -3
echo "$D" | grep -qE 'P305-RESV-(HEALTH.*state=ABSENT|REPAIRED)'; chk $? "the loss was DETECTED and reported as a safety event"
echo "$R" | grep -qE 'P305-RESV-(REPAIRED|RESTORED)'; chk $? "the invariant was REPAIRED automatically"
echo "$R" | grep -qE 'restores FUTURE exclusion'; chk $? "the repair is reported as NOT proving the gap was harmless"
[ -n "$T_REPAIR" ] && [ "$T_REPAIR" -le "$BOUND" ]
chk $? "repaired within the derived bound (t+${T_REPAIR:-never}s, bound ${BOUND}s)"

say "4. exactly one node repairs, and it says which role it repaired in"
# Either role may be the repairer: the elected maintainer normally, or a
# stand-in that took over because the maintainer was gone.  What must NOT
# happen is a repair nobody attributes, or two nodes repairing at once.
nrep=$(echo "$D" | grep -c 'P305-RESV-REPAIRED')
nm=$(echo "$D" | grep -c 'role=maintainer'); na=$(echo "$D" | grep -c 'role=auditor')
nt=$(echo "$D" | grep -c 'role=auditor-takeover')
echo "   repairs reported=$nrep  maintainer=$nm auditor=$na takeover=$nt"
[ "$nrep" -le 1 ]; chk $? "at most ONE node repaired (no repair race)"
echo "$R" | grep -qE 'role=(maintainer|auditor-takeover)'
chk $? "the repair names the role that performed it (a SILENT repair is the failure mode)"

say "5. final state + cleanup"
sp --out --register --param-rk=$KS --param-sark=0 >/dev/null
F=$("$PROBE" "$OBS" "$DEV"); echo "   $F"
case "$F" in *"all registrants"*) chk 0 "WE-AR in force at the end";; *) chk 1 "not restored: $F";; esac
timeout 120 "$SSH" "$SPARE" "mount -t mxfs $DEV $MNT" >/dev/null 2>&1

echo
[ "$fail" = 0 ] && echo "RESULT: PASS (all assertions)" || echo "RESULT: FAIL ($fail assertion(s))"
exit $fail
