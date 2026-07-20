#!/bin/bash
# 4-node concurrent same-path mkdir + marker visibility (the cache_coherency barrier pattern).
set -u
ITERS="${1:-16}"; shift || true
NODES=(test1 test2 test3 test4)
SSH=/src/mxfs/tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass; MNT=/mnt/shared
rn(){ timeout 40 "$SSH" "$1" "$PASS" "$2" 2>/dev/null|grep -vE 'Warning|Unauth|disconn|^$'; }
fails=0
for i in $(seq 1 "$ITERS"); do
  P="$MNT/m4_$$_$i"
  for idx in "${!NODES[@]}"; do id=$((idx+1)); ( rn "${NODES[$idx]}" "mkdir -p $P 2>/dev/null; touch $P/node$id; sync" >/dev/null ) & done
  wait
  ok=1; det=""
  declare -A inos
  for idx in "${!NODES[@]}"; do n="${NODES[$idx]}"
    s=$(rn "$n" "ls $P/ 2>/dev/null|tr '\n' ','; echo -n '|'; stat -c %i $P 2>/dev/null")
    l="${s%%|*}"; ino="${s##*|}"; inos[$n]="$ino"
    for id in 1 2 3 4; do echo "$l"|grep -q "node$id" || { ok=0; det="$det $n!node$id"; }; done
  done
  u=$(printf '%s\n' "${inos[@]}"|sort -u|wc -l)
  [ "$u" = 1 ] || { ok=0; det="$det split_inos=${inos[*]}"; }
  if [ "$ok" = 1 ]; then echo "iter $i: OK ino=${inos[test1]}"; else echo "iter $i: FAIL$det"; fails=$((fails+1)); fi
  unset inos
done
echo "=== repro_modea4: $fails/$ITERS failed ==="
