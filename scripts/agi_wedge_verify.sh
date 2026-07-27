#!/bin/bash
# agi_wedge_verify.sh — verify the AG-meta track-hold reclaim fix.
#
# Assumes a prepped, mounted 2/tcp cluster.  Triggers a forced shutdown via
# agi_wedge_repro.sh (heavy 2-node AG-meta churn -> stale-inode dialloc
# corruption -> dirty xfs_trans_cancel -> shutdown), then unmounts the
# shut-down node and asserts the umount COMPLETES: the drain must NOT wedge on
# a leaked mxfs_ag_meta_track hold, and there must be ZERO P-DRAINSTUCK /
# P-HOLDRING for this umount.
#
# Exit 0 = FIX VERIFIED for this instance; 1 = still wedged (FAIL);
#          2 = could not trigger a shutdown to test (inconclusive).
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PASS=${MXFS_PASS:-/tmp/.proxmox_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
ATTEMPTS=${AGI_ATTEMPTS:-5}
DUR=${AGI_DUR:-45}; WORKERS=${AGI_WORKERS:-10}

ssh1(){ "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -v 'Permanently added'; }

# 1) trigger a forced shutdown on some node
ESC=""
for a in $(seq 1 "$ATTEMPTS"); do
  echo "--- churn attempt $a/$ATTEMPTS ---"
  out=$(MXFS_PASS="$PASS" "$HERE/agi_wedge_repro.sh" "$DUR" "$WORKERS")
  echo "$out" | grep -vE '^\[agi-amp\] launching'
  node=$(echo "$out" | sed -n 's/^AGI_AMP_ESC_NODE=//p')
  [ -n "$node" ] && { ESC="$node"; break; }
done
[ -n "$ESC" ] || { echo "VERIFY-INCONCLUSIVE: no forced shutdown in $ATTEMPTS attempts"; exit 2; }
echo ">>> forced shutdown on $ESC — unmounting to test the drain"

# 2) umount the shut-down node in the background; assert completion (no wedge)
UMARK="AGI_VERIFY_UMOUNT_$(date +%s%N)"
ssh1 "$ESC" "echo $UMARK > /dev/kmsg 2>/dev/null; sh -c 'nohup umount $MNT >/tmp/agi_verify_umount.log 2>&1 & echo started pid=\$!'"
done_ok=0
for i in $(seq 1 15); do          # up to 30s (native umount ~0.4s; healthy drain is quick)
  sleep 2
  st=$(ssh1 "$ESC" "ps -C umount -o stat= --no-headers 2>/dev/null | head -1")
  mnt=$(ssh1 "$ESC" "grep -q ' mxfs ' /proc/mounts && echo yes || echo no")
  [ -z "$st" ] && [ "$mnt" = no ] && { done_ok=1; echo "umount completed by ~$((i*2))s"; break; }
done

# 3) verdict + evidence
ds=$(ssh1 "$ESC" "dmesg 2>/dev/null | awk -v m=$UMARK 'f{print} \$0~m{f=1}' | grep -c P-DRAINSTUCK")
hr=$(ssh1 "$ESC" "dmesg 2>/dev/null | awk -v m=$UMARK 'f{print} \$0~m{f=1}' | grep -c P-HOLDRING")
echo "post-umount on $ESC: umount_completed=$done_ok  P-DRAINSTUCK=$ds  P-HOLDRING=$hr"
if [ "$done_ok" = 1 ] && [ "$ds" = 0 ] && [ "$hr" = 0 ]; then
  echo "AGI-WEDGE-FIX VERIFIED on $ESC: umount completed cleanly after forced shutdown, zero drain-stuck"
  exit 0
fi
echo "AGI-WEDGE-FIX FAIL on $ESC: umount_completed=$done_ok P-DRAINSTUCK=$ds P-HOLDRING=$hr"
ssh1 "$ESC" "dmesg 2>/dev/null | grep -E 'P-DRAINSTUCK|P-HOLDRING|P-HOLDRING|mxfs:   \[' | tail -80"
exit 1
