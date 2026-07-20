#!/bin/bash
# reg2tcp.sh — regression check: 2/tcp dir_reuse_coherency N times (reboot test1/2 once).
set -u
cd /src/mxfs
N="${1:-3}"
for d in test1 test2; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in test1 test2; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
for t in $(seq 1 40); do ok=1; for n in test1 test2; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done; [ $ok = 1 ] && break; sleep 3; done
sleep 20
P=0; F=0
for i in $(seq 1 "$N"); do
  res=$(./run.sh 2 tcp dir_reuse_coherency 2>&1 | grep -E "dir_reuse_coherency" | tail -1)
  echo "iter $i: $res"
  echo "$res" | grep -q PASS && P=$((P+1)) || F=$((F+1))
done
echo "2TCP SUMMARY: PASS=$P FAIL=$F of $N"
