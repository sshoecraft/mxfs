#!/bin/bash
# catch_create_stall.sh — fresh-format concurrent burst; at SNAP seconds in,
# freeze-dump EVERY task's full kernel stack (any state) on both nodes + dmesg,
# to catch which create is blocked and on what.  Run ON clyde.
set -u
P=/tmp/.mxfs_pass; S=/src/mxfs/tools/mxfs_sshpass.sh; BROKER=192.168.1.149
LOGD=/src/mxfs/.testlogs; SNAP="${1:-20}"
clean(){ grep -vE '^Warning:|^Unauthorized|^If you'; }
PFX="mxfs/coord/ccs/1"
timeout 5 mosquitto_sub -h $BROKER -t "$PFX/#" --remove-retained -W 2 >/dev/null 2>&1
for n in test1 test2; do bash $S $n $P "dmesg -C" >/dev/null 2>&1; done
timeout 120 bash $S test1 $P "MXFS_NODES=2 MXFS_RANK=1 MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=100 bash /src/mxfs/tests/repro_burst_timed.sh /mnt/shared" >"$LOGD/ccs1.out" 2>&1 &
timeout 120 bash $S test2 $P "MXFS_NODES=2 MXFS_RANK=2 MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=100 bash /src/mxfs/tests/repro_burst_timed.sh /mnt/shared" >"$LOGD/ccs2.out" 2>&1 &
sleep "$SNAP"
for n in test1 test2; do
  {
    echo "===== $n SNAP@${SNAP}s $(date +%T) ====="
    bash $S $n $P "echo '### test shells (bash/sh) full stack ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null)||continue; case \$c in bash|sh|touch) echo \"PID \$(basename \$t) \$c st=\$(awk '{print \$3}' \$t/stat) wchan=\$(cat \$t/wchan)\"; cat \$t/stack 2>/dev/null; echo --;; esac; done; echo '### any task with mxfs/dlm/xfs frame ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null)||continue; stk=\$(cat \$t/stack 2>/dev/null); if echo \"\$stk\"|grep -qiE 'pending_wait|caw_lock|mxfs_ag_dlm|ilock_begin|bast|drain_inode|ail_push|wait_unpin|log_force'; then echo \"PID \$(basename \$t) \$c st=\$(awk '{print \$3}' \$t/stat)\"; echo \"\$stk\"|head -22; echo --; fi; done; echo '### dmesg tail ###'; dmesg|tail -30" 2>&1 | clean
  } > "$LOGD/cstall_$n.log"
done
wait 2>/dev/null
echo "snap dumps: $LOGD/cstall_test1.log cstall_test2.log"
grep -hE 'SLOW|BURST' "$LOGD/ccs1.out" "$LOGD/ccs2.out"
