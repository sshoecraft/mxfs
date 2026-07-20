#!/bin/bash
# reboot_cluster.sh — hard virsh destroy+start of test1..testN, wait for SSH.
# Use before any 16-node run to guarantee a clean slate (sess77: orphaned
# run_tests procs leave D-state threads holding AGI locks that contaminate
# cluster-phase results). NEVER touches clyde (the host) — VMs only.
# Usage: tests/reboot_cluster.sh [N]   (default 16)
set -u
N=${1:-16}
SSH=/home/steve/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
VIRSH="virsh -c qemu:///system"

NODES=()
for i in $(seq 1 "$N"); do NODES+=("test$i"); done

echo "=== destroy ${NODES[*]} $(date -u +%T) ==="
for n in "${NODES[@]}"; do $VIRSH destroy "$n" >/dev/null 2>&1 & done
wait
sleep 3
echo "=== start ${NODES[*]} $(date -u +%T) ==="
for n in "${NODES[@]}"; do $VIRSH start "$n" >/dev/null 2>&1 & done
wait

echo "=== waiting for ssh + /src nfs on all nodes ==="
deadline=$((SECONDS+240))
pending=("${NODES[@]}")
while [ ${#pending[@]} -gt 0 ] && [ $SECONDS -lt $deadline ]; do
    sleep 8
    still=()
    for n in "${pending[@]}"; do
        ok=$(timeout 8 $SSH "$n" "$PF" 'mountpoint -q /src && [ -f /src/mxfs/mxfs.ko ] && echo UP || (mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; [ -f /src/mxfs/mxfs.ko ] && echo UP)' 2>/dev/null | grep -c UP)
        [ "${ok:-0}" = "1" ] || still+=("$n")
    done
    pending=("${still[@]}")
    echo "  still pending: ${pending[*]:-none} ($((deadline-SECONDS))s left)"
done

if [ ${#pending[@]} -gt 0 ]; then
    echo "REBOOT_FAIL: not up: ${pending[*]}"; exit 1
fi
echo "REBOOT_OK: $N nodes up with /src mounted $(date -u +%T)"
