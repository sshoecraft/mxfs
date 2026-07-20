#!/bin/bash
# Cluster reset for N nodes (sess34, generalizes cluster_reset.sh which is hard-coded for 2).
# Usage: cluster_reset_n.sh <n>   — destroys VMs test1..testN, restarts, preps each.
# Per RULE 3, this lives in the source tree because each session needs the same flow.

set -u
N="${1:?node count required}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass

echo "=== virsh destroy + start test1..test$N ==="
for n in $(seq 1 "$N"); do
  ( sudo virsh destroy test$n 2>&1 | grep -vE "^$"; sudo virsh start test$n 2>&1 | grep -vE "^$" ) &
done
wait 2>/dev/null

echo "=== wait for SSH on each + prep_tcm_node_scst.sh ==="
for n in $(seq 1 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  (
    for try in $(seq 1 30); do
      if timeout 3 "$SSH" "$ip" "$PF" 'echo R' 2>/dev/null | grep -q R; then break; fi
      sleep 3
    done
    out=$(cat /src/mxfs/tools/prep_tcm_node_scst.sh | timeout 60 "$SSH" "$ip" "$PF" 'sudo bash -s' 2>&1 | grep -E "PREP_OK|PREP_FAIL" | head -1)
    printf "test%-2s %s\n" "$n" "$out"
  ) &
done
wait 2>/dev/null

echo "=== verify all $N nodes loaded ==="
MODINFO=$(command -v modinfo || echo /usr/sbin/modinfo)
WANT_SV=$("$MODINFO" /src/mxfs/mxfs.ko 2>/dev/null | awk '/^srcversion/{print $2}')
if [ -z "$WANT_SV" ]; then
  echo "PREP_FAIL — cannot read srcversion from /src/mxfs/mxfs.ko"
  exit 1
fi
vdir=$(mktemp -d)
for n in $(seq 1 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  (
    sv=$(timeout 4 "$SSH" "$ip" "$PF" 'cat /sys/module/mxfs/srcversion 2>/dev/null' 2>/dev/null | tail -1 | tr -d "\r\n ")
    if [ "$sv" != "$WANT_SV" ]; then
      printf "test%-2s WRONG sv=%s want=%s\n" "$n" "${sv:-NOT_LOADED}" "$WANT_SV" > "$vdir/bad.$n"
    fi
  ) &
done
wait 2>/dev/null
all_ok=1
if ls "$vdir"/bad.* >/dev/null 2>&1; then cat "$vdir"/bad.*; all_ok=0; fi
rm -rf "$vdir"
if [ "$all_ok" = "1" ]; then
  echo "ALL_OK srcversion=$WANT_SV"
else
  echo "PREP_FAIL — some nodes did not load $WANT_SV"
  exit 1
fi
