#!/bin/bash
# agi_wedge_repro.sh — amplified trigger for the AGI-buffer umount wedge.
#
# The wedge: after a *forced shutdown* on a node, `umount` hangs forever in
# xfs_buftarg_drain on ONE leaked xfs_agi b_hold (see ccmemory
# pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead).  The forced
# shutdown itself comes from a DLM inode/dir EX *conversion* that returns
# -EDEADLK (PR->EX convert-deadlock between the two nodes) AFTER its
# transaction has already dirtied, so xfs_trans_cancel of the dirty tx shuts
# the FS down (xfs_trans.c:1069, "Corruption of in-memory data 0x8").
#
# fence_during_write triggers this only probabilistically (0/10 some runs).
# This script amplifies the precondition: BOTH nodes hammer the SAME hot
# directory with concurrent create+write+unlink and mkdir/rmdir churn on
# shared names — constant PR->EX dir-inode conversion deadlocks + heavy inode
# alloc/free (AGI) traffic — maximizing the chance a *dirty* tx is cancelled
# on -EDEADLK.  It does NOT unmount; on escalation it stops so the caller can
# capture P-HOLDRING via a controlled umount.
#
# Usage (from clyde):
#   MXFS_PASS=/tmp/.proxmox_pass scripts/agi_wedge_repro.sh [DURATION] [WORKERS]
# Exit 42 = escalation detected on N2; 0 = no escalation this run.
set -u
N1=${N1:-192.168.1.80}
N2=${N2:-192.168.1.81}
PASS=${MXFS_PASS:-/tmp/.proxmox_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
DUR=${1:-45}
WORKERS=${2:-10}
HOT="$MNT/.agi_amp"
SIG='Shutting down filesystem|Corruption of in-memory|FS shut down|Internal error xfs|P-DRAINSTUCK|P-HOLDRING|P-WITHDRAW'

# Per-node churn body (single-quoted: expands on the node; R/DUR/W/HOT are set
# as leading vars by the caller).
BODY='
mkdir -p "$HOT" 2>/dev/null
END=$(( $(date +%s) + DUR ))
for w in $(seq 1 $W); do
 ( k=0
   while [ "$(date +%s)" -lt "$END" ]; do
     n=$((k % 24)); f="$HOT/s$n"; d="$HOT/d${R}_$n"
     printf x > "$f" 2>/dev/null
     mkdir "$d" 2>/dev/null && rmdir "$d" 2>/dev/null
     rm -f "$f" 2>/dev/null
     k=$((k+1))
   done ) &
done
wait; echo NODE_R${R}_DONE'

launch() {  # rank ip
  local r=$1 ip=$2
  timeout $((DUR + 40)) "$SSH" "$ip" "$PASS" \
    "R=$r DUR=$DUR W=$WORKERS HOT='$HOT'; $BODY" > "/tmp/agi_amp_r$r.log" 2>&1
}

"$SSH" "$N1" "$PASS" "mkdir -p $HOT; sync" >/dev/null 2>&1
echo "[agi-amp] launching churn on $N1 + $N2 (dur=${DUR}s workers=${WORKERS}, shared hot dir $HOT)"
launch 1 "$N1" & p1=$!
launch 2 "$N2" & p2=$!

MARK="AGI_AMP_$(date +%s%N)"
for NODE in "$N1" "$N2"; do
  "$SSH" "$NODE" "$PASS" "echo $MARK > /dev/kmsg 2>/dev/null" >/dev/null 2>&1
done
esc=""; esc_node=""
# ccloop-4dd7 sess2: DUR+8 missed an escalation landing seconds after the
# churn ended (deadlock timeouts mature ~180s after their trigger).  Watch
# through the workers' full lifetime plus the acquire-timeout tail.
end=$(( $(date +%s) + DUR + 60 ))
while [ "$(date +%s)" -lt "$end" ]; do
  for NODE in "$N1" "$N2"; do
    e=$("$SSH" "$NODE" "$PASS" "dmesg 2>/dev/null | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -Ei '$SIG' | head -4" 2>/dev/null | grep -v 'Permanently added')
    if [ -n "$e" ]; then esc="$e"; esc_node="$NODE"; break; fi
  done
  [ -n "$esc" ] && break
  sleep 2
done
wait $p1 $p2 2>/dev/null

if [ -n "$esc" ]; then
  echo "[agi-amp] >>> ESCALATION on $esc_node:"; echo "$esc" | sed 's/^/    /'
  echo "AGI_AMP_ESC_NODE=$esc_node"
  exit 42
fi
echo "[agi-amp] no escalation this run"
exit 0
