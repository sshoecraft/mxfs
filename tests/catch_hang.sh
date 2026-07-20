#!/bin/bash
# catch_hang.sh — run posix_multi repeatedly; on a run that HANGS (no RESULT in
# WINDOW s), freeze-dump every task's kernel stack + dmesg on both nodes while
# still wedged, to /src/mxfs/.testlogs/hang_<node>.log.  Stops at first catch.
set -u
P=/tmp/.mxfs_pass; S=/src/mxfs/tools/mxfs_sshpass.sh; BROKER=192.168.1.149
LOGD=/src/mxfs/.testlogs; ITERS="${1:-6}"; WINDOW="${2:-66}"
clean(){ grep -vE '^Warning:|^Unauthorized|^If you'; }
for k in $(seq 1 "$ITERS"); do
  PFX="mxfs/coord/chang/$k"
  timeout 5 mosquitto_sub -h $BROKER -t "$PFX/#" --remove-retained -W 2 >/dev/null 2>&1
  bash $S test1 $P "rm -rf /mnt/shared/.posix_multi; sync; dmesg -C" >/dev/null 2>&1
  bash $S test2 $P "dmesg -C" >/dev/null 2>&1
  # launch (long cap so kernel stays wedged for the dump)
  timeout 200 bash $S test1 $P "MXFS_NODES=2 MXFS_RANK=1 MXFS_DLM=tcp MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=120 bash /src/mxfs/tests/suite/posix_multi.sh /mnt/shared" >"$LOGD/ch1.out" 2>&1 &
  j1=$!
  timeout 200 bash $S test2 $P "MXFS_NODES=2 MXFS_RANK=2 MXFS_DLM=tcp MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=120 bash /src/mxfs/tests/suite/posix_multi.sh /mnt/shared" >"$LOGD/ch2.out" 2>&1 &
  j2=$!
  # wait WINDOW seconds, then check for RESULT
  for s in $(seq 1 "$WINDOW"); do
    if grep -q RESULT "$LOGD/ch1.out" "$LOGD/ch2.out" 2>/dev/null; then break; fi
    sleep 1
  done
  if grep -q RESULT "$LOGD/ch1.out" "$LOGD/ch2.out" 2>/dev/null; then
    echo "iter $k: completed (no hang) — $(grep -h RESULT "$LOGD/ch1.out" "$LOGD/ch2.out" | sed 's/.*reason=/r=/' | tr '\n' '|')"
    kill $j1 $j2 2>/dev/null; wait 2>/dev/null
    continue
  fi
  echo "iter $k: HANG detected at ${WINDOW}s — freezing state"
  for n in test1 test2; do
    {
      echo "===== $n FROZEN $(date +%T) ====="
      bash $S $n $P "echo '### blocked tasks (D + S with stack) ###'; for t in /proc/[0-9]*; do comm=\$(cat \$t/comm 2>/dev/null)||continue; st=\$(awk '{print \$3}' \$t/stat 2>/dev/null); stk=\$(cat \$t/stack 2>/dev/null); if [ -n \"\$stk\" ] && echo \"\$stk\"|grep -qiE 'mxfs|_dlm|xfs_|pending_wait|caw|down_|rwsem'; then echo \"PID \$(basename \$t) \$comm st=\$st\"; echo \"\$stk\"|head -20; echo --; fi; done; echo '### dmesg tail ###'; dmesg | tail -40" 2>&1 | clean
    } > "$LOGD/hang_$n.log"
  done
  echo "frozen dumps in $LOGD/hang_test1.log hang_test2.log"
  kill $j1 $j2 2>/dev/null; wait 2>/dev/null
  exit 0
done
echo "no hang in $ITERS iters"
