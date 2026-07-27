#!/bin/bash
# agi_wedge_verify_inject.sh — DETERMINISTIC AGI umount-wedge fix verification
# via the mxfs.dbg_dialloc_shutdown one-shot fault injection.
#
# Assumes a prepped, mounted 2/tcp cluster.  Arms the injection on TARGET, then
# does ONE create there -> xfs_dialloc logs + mxfs_ag_meta_track's the
# AGI/inobt/finobt -> injected dirty xfs_trans_cancel -> forced shutdown (the
# exact natural stale-inode dialloc signature, but deterministic).  Then
# unmounts TARGET and asserts: umount COMPLETES, ZERO P-DRAINSTUCK/P-HOLDRING,
# and P-AGMETA-RECLAIM > 0 (the shutdown-abort reclaim arm fired on the tracked
# AG-meta buffers). This is the causal proof the old build could not pass.
#
# Exit 0 = VERIFIED; 1 = wedged/leaked FAIL; 2 = injection didn't shut down.
set -u
PASS=${MXFS_PASS:-/tmp/.proxmox_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
TARGET=${TARGET:-192.168.1.80}
ssh1(){ "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -v 'Permanently added'; }

MARK="AGIINJ_$(date +%s%N)"
ssh1 "$TARGET" "echo $MARK > /dev/kmsg 2>/dev/null"
echo "[inj] arm mxfs.dbg_dialloc_shutdown=1 on $TARGET, then one create"
ssh1 "$TARGET" "echo 1 > /sys/module/mxfs/parameters/dbg_dialloc_shutdown; echo armed=\$(cat /sys/module/mxfs/parameters/dbg_dialloc_shutdown)"
ssh1 "$TARGET" "touch $MNT/agi_inject_probe 2>&1; echo touch_rc=\$?"

sleep 1
sd=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -Eic 'P-DBG-DIALLOC-SHUTDOWN|Shutting down filesystem|Corruption of in-memory'")
echo "[inj] $TARGET shutdown-signature lines=$sd"
ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -E 'P-DBG-DIALLOC-SHUTDOWN|P-CR3-CANCEL|Shutting down' | head -4 | sed 's/^/    /'"
[ "${sd:-0}" -gt 0 ] || { echo "[inj] INCONCLUSIVE: injection did not shut down $TARGET"; exit 2; }

UM="${MARK}_UM"
ssh1 "$TARGET" "echo $UM > /dev/kmsg 2>/dev/null; sh -c 'nohup umount $MNT >/tmp/agi_inj_um.log 2>&1 & echo started pid=\$!'"
done_ok=0
for i in $(seq 1 15); do
  sleep 2
  st=$(ssh1 "$TARGET" "ps -C umount -o stat= --no-headers 2>/dev/null | head -1")
  mnt=$(ssh1 "$TARGET" "grep -q ' mxfs ' /proc/mounts && echo yes || echo no")
  [ -z "$st" ] && [ "$mnt" = no ] && { done_ok=1; echo "[inj] umount completed by ~$((i*2))s"; break; }
done

rcl=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -c P-AGMETA-RECLAIM")
ds=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$UM 'f{print} \$0~m{f=1}' | grep -c P-DRAINSTUCK")
hr=$(ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$UM 'f{print} \$0~m{f=1}' | grep -c P-HOLDRING")
echo "[inj] RESULT $TARGET: umount_completed=$done_ok  P-AGMETA-RECLAIM=$rcl  P-DRAINSTUCK=$ds  P-HOLDRING=$hr"
ssh1 "$TARGET" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep 'P-AGMETA-RECLAIM' | sed 's/.*ops=//;s/ flags.*//' | sort | uniq -c | sed 's/^/    reclaimed ops=/'"
if [ "$done_ok" = 1 ] && [ "${ds:-1}" = 0 ] && [ "${hr:-1}" = 0 ] && [ "${rcl:-0}" -gt 0 ]; then
  echo "[inj] AGI-WEDGE-FIX VERIFIED: umount clean after forced shutdown; reclaim fired $rcl time(s), zero drain-stuck"
  exit 0
fi
echo "[inj] FAIL/incomplete: umount_completed=$done_ok reclaim=$rcl drainstuck=$ds holdring=$hr"
ssh1 "$TARGET" "dmesg 2>/dev/null | grep -E 'P-DRAINSTUCK|P-HOLDRING|mxfs:   \[' | tail -50"
exit 1
