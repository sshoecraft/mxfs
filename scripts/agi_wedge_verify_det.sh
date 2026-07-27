#!/bin/bash
# agi_wedge_verify_det.sh — DETERMINISTIC verification of the AG-meta track-hold
# reclaim fix (one cycle; assumes a prepped, mounted 2/tcp cluster).
#
# Runs heavy inode alloc/free churn on BOTH nodes (so AG-meta buffers AGI /
# inobt / finobt are actively mxfs_ag_meta_track'd), then forces a NOLOGFLUSH
# shutdown on TARGET mid-churn via XFS_IOC_GOINGDOWN (xfs_io -x -c 'shutdown
# -f').  That aborts TARGET's in-flight dialloc/dfree transactions and their
# tracked AG-meta buffers WITHOUT writeback — the exact condition that leaked
# the track hold and wedged xfs_buftarg_drain.  Then unmounts TARGET and
# asserts the umount COMPLETES with zero P-DRAINSTUCK / P-HOLDRING (no leak);
# P-AGMETA-RECLAIM>0 additionally proves the reclaim path fired.
#
# Exit 0 = VERIFIED; 1 = wedged/leaked (FAIL); 2 = shutdown didn't take.
set -u
PASS=${MXFS_PASS:-/tmp/.proxmox_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
N1=${N1:-192.168.1.80}; N2=${N2:-192.168.1.81}
TARGET=${TARGET:-$N1}
OTHER=$([ "$TARGET" = "$N1" ] && echo "$N2" || echo "$N1")
DUR=${AGI_DUR:-25}; WORKERS=${AGI_WORKERS:-12}
ssh1(){ "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -v 'Permanently added'; }

BODY='mkdir -p "$HOT" 2>/dev/null
END=$(( $(date +%s) + DUR ))
for w in $(seq 1 $W); do
 ( k=0; while [ "$(date +%s)" -lt "$END" ]; do
     d="$HOT/w${w}_$((k%64))"
     mkdir "$d" 2>/dev/null; : > "$d/f" 2>/dev/null; rm -rf "$d" 2>/dev/null
     k=$((k+1))
   done ) &
done; wait; echo CHURN_DONE'
churn(){ ssh1 "$1" "HOT='$MNT/.agi_det' DUR=$DUR W=$WORKERS; $BODY"; }

MARK="AGIDET_$(date +%s%N)"
ssh1 "$TARGET" "echo $MARK > /dev/kmsg 2>/dev/null"
echo "[det] churn on $TARGET + $OTHER (dur=${DUR}s workers=${WORKERS}); GOINGDOWN on $TARGET at +6s"
( churn "$TARGET" >/tmp/agi_det_t.log 2>&1 ) & pt=$!
( churn "$OTHER"  >/tmp/agi_det_o.log 2>&1 ) & po=$!

sleep 6   # let churn ramp so AG-meta buffers are tracked/dirty at shutdown
echo "[det] forcing NOLOGFLUSH shutdown on $TARGET"
ssh1 "$TARGET" "xfs_io -x -c 'shutdown -f' $MNT 2>&1; echo goingdown_rc=\$?"
wait $pt $po 2>/dev/null

sd=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -Eic 'Shutting down filesystem|forced shutdown|Corruption of in-memory'")
echo "[det] $TARGET shutdown-signature lines=$sd"
[ "${sd:-0}" -gt 0 ] || { echo "[det] INCONCLUSIVE: shutdown did not take on $TARGET"; exit 2; }

ssh1 "$TARGET" "echo ${MARK}_UM > /dev/kmsg 2>/dev/null; sh -c 'nohup umount $MNT >/tmp/agi_det_umount.log 2>&1 & echo started pid=\$!'"
done_ok=0
for i in $(seq 1 15); do
  sleep 2
  st=$(ssh1 "$TARGET" "ps -C umount -o stat= --no-headers 2>/dev/null | head -1")
  mnt=$(ssh1 "$TARGET" "grep -q ' mxfs ' /proc/mounts && echo yes || echo no")
  [ -z "$st" ] && [ "$mnt" = no ] && { done_ok=1; echo "[det] umount completed by ~$((i*2))s"; break; }
done

rcl=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -c P-AGMETA-RECLAIM")
ds=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=${MARK}_UM 'f{print} \$0~m{f=1}' | grep -c P-DRAINSTUCK")
hr=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=${MARK}_UM 'f{print} \$0~m{f=1}' | grep -c P-HOLDRING")
echo "[det] RESULT $TARGET: umount_completed=$done_ok  P-AGMETA-RECLAIM=$rcl  P-DRAINSTUCK=$ds  P-HOLDRING=$hr"
ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep 'P-AGMETA-RECLAIM' | sed 's/.*P-AGMETA-RECLAIM/  P-AGMETA-RECLAIM/' | sort | uniq -c | head"
if [ "$done_ok" = 1 ] && [ "${ds:-1}" = 0 ] && [ "${hr:-1}" = 0 ]; then
  echo "[det] AGI-WEDGE-FIX VERIFIED (deterministic): umount clean after forced shutdown; reclaim fired $rcl time(s)"
  exit 0
fi
echo "[det] AGI-WEDGE-FIX FAIL: umount_completed=$done_ok drainstuck=$ds holdring=$hr"
ssh1 "$TARGET" "dmesg 2>/dev/null | grep -E 'P-DRAINSTUCK|P-HOLDRING|mxfs:   \[' | tail -60"
exit 1
