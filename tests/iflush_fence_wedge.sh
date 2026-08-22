#!/bin/bash
# Exercise the fenced-publication wedge chain DETERMINISTICALLY  (sess382)
# Defect: D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380
#
# THE CHAIN THIS DRIVES
#   xfs_iflush's "safe skip" fences abandon a flush with error=0 and WITHOUT
#   stamping i_mxfs_pub_flush_seq.  The publication obligation
#   (pending_seq != durable_seq) can then never close.  The release drain
#   re-logs the clean-but-unlanded core (P146V) on every attempt, and
#   xfs_trans_log_inode bumps pending_seq each time -- the drain's own repair
#   feeding the counter it waits on -- until the release-defer episode's 60s
#   no-progress bound fires P-INODE-WEDGE, pins the grant and force-shuts-down
#   the WHOLE mount.
#
#   Every natural trigger is luck-dependent (sess382: one wedge in three
#   attempts under knobs meant to force it).  mxfs.iflush_fence_fault_ino makes
#   a chosen inode's flush take exactly the fence shape on demand, so the cause
#   can be exercised instead of waited for.
#
# EXPECTED VERDICTS
#   PRE-FIX  : WEDGED   -- P-INODE-WEDGE fires and the victim's mount dies.
#   POST-FIX : NO_WEDGE -- the abandoned publication is resolved (or refused
#                          under its own name), and the mount survives.
#   Either way this script only REPORTS; it does not decide the disposition.
#
# NOTE the victim node's mount is destroyed on a WEDGED verdict.  Re-prep
# (./run.sh <n> caw prep_cluster) before running anything else.
#
# RULE 0: the 60s no-progress bound is the thing being waited on, so the poll
# window is derived from it (60s bound + 30s drain/BAST slack), not padded.
set -u
cd "$(dirname "$0")/.."

VICTIM=${1:-test1}
PEER=${2:-test2}
WINDOW=${3:-90}

sh() { timeout "$1" tools/mxfs_sshpass.sh "$2" "$3" 2>&1 \
        | grep -vE 'Unauthor|not an auth|Warning: Perm'; }

echo "=== fenced-publication wedge probe: victim=$VICTIM peer=$PEER window=${WINDOW}s ==="

for h in "$VICTIM" "$PEER"; do
  if ! sh 15 "$h" "mountpoint -q /mnt/shared && echo OK" | grep -qx OK; then
    echo "ABORT: $h has no mxfs mount -- re-prep first"; exit 2
  fi
done

D=/mnt/shared/.mxfs_fencefault/run$(date +%s)
echo "--- 1. create + dirty a directory on $VICTIM ($D) ---"
sh 30 "$VICTIM" "mkdir -p $D && touch $D/a && sync && stat -c 'INO=%i' $D"
INO=$(sh 20 "$VICTIM" "stat -c '%i' $D" | tr -dc '0-9')
[ -n "$INO" ] || { echo "ABORT: could not read inode number"; exit 2; }
echo "    victim inode = $INO"

echo "--- 2. arm the fenced-flush fault on $VICTIM only ---"
sh 15 "$VICTIM" "echo 0 > /sys/module/mxfs/parameters/iflush_fence_fault_n; \
                 echo $INO > /sys/module/mxfs/parameters/iflush_fence_fault_ino; \
                 echo ARMED=\$(cat /sys/module/mxfs/parameters/iflush_fence_fault_ino)"

echo "--- 3. dirty it again so pending_seq > durable_seq ---"
sh 30 "$VICTIM" "touch $D/b $D/c; echo DIRTIED"

echo "--- 4. force a peer BAST from $PEER (drives $VICTIM's release drain) ---"
sh 40 "$PEER" "ls -l $D >/dev/null 2>&1; touch $D/peer 2>/dev/null; echo BAST_DRIVEN"

echo "--- 5. watch $VICTIM for up to ${WINDOW}s (60s no-progress bound + slack) ---"
VERDICT=UNKNOWN
END=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$END" ]; do
  OUT=$(sh 15 "$VICTIM" "dmesg | grep -c P-INODE-WEDGE; mountpoint -q /mnt/shared && echo M1 || echo M0")
  W=$(echo "$OUT" | head -1 | tr -dc '0-9')
  M=$(echo "$OUT" | grep -o 'M[01]' | head -1)
  if [ "${W:-0}" -gt 0 ] 2>/dev/null; then VERDICT=WEDGED; break; fi
  if [ "$M" = "M0" ]; then
    # mount died -- re-read the ring before labelling; the wedge line and the
    # mount going down are the same event and the two greps can race.
    W=$(sh 15 "$VICTIM" "dmesg | grep -c P-INODE-WEDGE" | tr -dc '0-9')
    if [ "${W:-0}" -gt 0 ] 2>/dev/null; then VERDICT=WEDGED
    else VERDICT=MOUNT_LOST_NO_WEDGE_LINE; fi
    break
  fi
  sleep 5
done
[ "$VERDICT" = UNKNOWN ] && VERDICT=NO_WEDGE

echo "--- 6. disarm ---"
sh 15 "$VICTIM" "echo 0 > /sys/module/mxfs/parameters/iflush_fence_fault_ino; echo DISARMED"

echo "--- evidence from $VICTIM ---"
sh 25 "$VICTIM" "for p in P-IFLUSH-FENCE-FAULT P146V-UNLANDED P176-OBLIGATION-OPEN \
                          P228-RELBAR-DEFER P-INODE-WEDGE P177-OBLIGATION-DROPPED-AT-ADOPT; do \
                   echo \"\$p=\$(dmesg|grep -c \$p)\"; done; \
                 echo '--- terminal lines ---'; \
                 dmesg | grep -E 'P-INODE-WEDGE|P-IFLUSH-FENCE-FAULT|P176-OBLIGATION-OPEN' | tail -4; \
                 mountpoint -q /mnt/shared && echo MOUNT=UP || echo MOUNT=DOWN"

echo "=== VERDICT: $VERDICT  (ino=$INO victim=$VICTIM) ==="
[ "$VERDICT" = WEDGED ] && echo "NOTE: $VICTIM's mount is gone -- re-prep before further runs."
