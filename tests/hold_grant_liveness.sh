#!/bin/bash
# incident474 hole (c): does the liveness oracle confuse "HB alive" with
# "filesystem serviceable"?                                        (sess382)
#
# THE CLAIM UNDER TEST (D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474):
#   P-WAIT-EXTEND (dlm/dlm_caw.c) consults v5_caw_holders_alive ->
#   mxfs_disklock_slot_live, which only knows whether the holder's disklock
#   heartbeat thread is still beating.  A victim wedged in AIL drain keeps
#   beating, so the oracle truthfully says "alive" while its filesystem is
#   unserviceable, and survivors extend their waits toward the 480s
#   liveness-extended cap on a lock that will never be handed off.
#
# WHY A FAULT IS NEEDED:
#   sess382's inode-wedge injection makes the victim force-shutdown and
#   WITHDRAW immediately, which STOPS the heartbeat -- measured: 31 survivors
#   stayed mounted, fleet P-WAIT-EXTEND = 0.  So that injection cannot
#   exercise hole (c).  mxfs.hold_grant_fault_ino produces the missing shape:
#   the holder keeps the grant forever while staying mounted and beating.
#
# READING THE RESULT
#   WAIT_EXTENDED  -- hole (c) CONFIRMED: survivors extended past the base
#                     timeout on an unserviceable holder.
#   NO_EXTENSION   -- survivors did not extend; either the oracle already
#                     distinguishes the two, or the waiter never got far
#                     enough.  Check waiter_errs before concluding.
#
# RULE 0: the wait window is derived from the thing being measured -- the base
# CAW acquire timeout, not a round number.  Default 200s covers the base
# timeout plus room to SEE an extension past it; it is a measurement window,
# not a pass/fail budget.
set -u
cd "$(dirname "$0")/.."

HOLDER=${1:-test1}
WAITER=${2:-test2}
WINDOW=${3:-200}

sh() { timeout "$1" tools/mxfs_sshpass.sh "$2" "$3" 2>&1 \
        | grep -vE 'Unauthor|not an auth|Warning: Perm'; }

echo "=== hole(c) probe: holder=$HOLDER waiter=$WAITER window=${WINDOW}s ==="
for h in "$HOLDER" "$WAITER"; do
  sh 15 "$h" "mountpoint -q /mnt/shared && echo OK" | grep -qx OK \
    || { echo "ABORT: $h not mounted -- re-prep first"; exit 2; }
done

D=/mnt/shared/.mxfs_holdgrant/run$(date +%s)
echo "--- 1. $HOLDER creates and holds a directory ---"
sh 30 "$HOLDER" "mkdir -p $D && touch $D/a && sync"
INO=$(sh 20 "$HOLDER" "stat -c '%i' $D" | tr -dc '0-9')
[ -n "$INO" ] || { echo "ABORT: no inode number"; exit 2; }
echo "    ino=$INO"

echo "--- 2. arm the hold-grant fault on $HOLDER ---"
sh 15 "$HOLDER" "echo $INO > /sys/module/mxfs/parameters/hold_grant_fault_ino; \
                 echo ARMED=\$(cat /sys/module/mxfs/parameters/hold_grant_fault_ino)"

echo "--- 3. $HOLDER touches it again so it owns the grant, then $WAITER demands it ---"
sh 30 "$HOLDER" "touch $D/b; echo HOLDER_DIRTIED"
sh 20 "$WAITER" "( ls -l $D >/dev/null 2>&1; touch $D/from_waiter >/dev/null 2>&1; \
                   echo WAITER_DONE ) & echo WAITER_LAUNCHED"

echo "--- 4. watch $WAITER for up to ${WINDOW}s ---"
END=$(( $(date +%s) + WINDOW ))
VERDICT=NO_EXTENSION
while [ "$(date +%s)" -lt "$END" ]; do
  N=$(sh 15 "$WAITER" "dmesg | grep -c P-WAIT-EXTEND || true" | tr -dc '0-9')
  if [ "${N:-0}" -gt 0 ] 2>/dev/null; then VERDICT=WAIT_EXTENDED; break; fi
  if ! sh 15 "$WAITER" "mountpoint -q /mnt/shared && echo OK" | grep -qx OK; then
    VERDICT=WAITER_LOST_MOUNT; break
  fi
  sleep 10
done

echo "--- 5. disarm (releases the holder's drain) ---"
sh 15 "$HOLDER" "echo 0 > /sys/module/mxfs/parameters/hold_grant_fault_ino; echo DISARMED"

echo "--- evidence ---"
echo "[$HOLDER]"; sh 25 "$HOLDER" \
  "echo P384=\$(dmesg|grep -c P384-HOLD-GRANT-FAULT || true); \
   mountpoint -q /mnt/shared && echo MOUNT=UP || echo MOUNT=DOWN; \
   dmesg | grep -m2 P384-HOLD-GRANT-FAULT || true"
echo "[$WAITER]"; sh 25 "$WAITER" \
  "echo WAIT_EXTEND=\$(dmesg|grep -c P-WAIT-EXTEND || true) \
        ACQ_SLOW=\$(dmesg|grep -c P34-ACQ-SLOW || true); \
   mountpoint -q /mnt/shared && echo MOUNT=UP || echo MOUNT=DOWN; \
   dmesg | grep -m2 'P-WAIT-EXTEND\|P34-ACQ-SLOW' || true"

echo "=== VERDICT: $VERDICT  (ino=$INO holder=$HOLDER waiter=$WAITER) ==="
