#!/bin/bash
# pve_alloc_under_load.sh — how long a Proxmox disk allocation on the MXFS
# storage takes while both hosts of the pair run a VM-like load on it.
#
# For D-DRBD-VM-DISK-ALLOCATION-OUTLASTS-PROXMOX-LOCK-UNDER-GUEST-LOAD: on
# 2026-10-06 `qm create --scsi0 shared:1` on pve2 failed after Proxmox's 60 s
# cluster storage lock ('storage-shared'-locked command timed out) while both
# hosts ran fio O_DIRECT 4 KiB randrw 60/40 at QD16 on a 1 GiB file each;
# idle, the same allocation took 0.54 s.
#
# Each host runs that fio load in a directory of its own on the storage for
# LOAD_S seconds.  After WARM_S, participant 1 (the host that failed) runs
# ALLOCS rounds of `pvesm alloc <storage> <vmid> <name> 1G` and `pvesm free`,
# each timed, with a stack sampler on the allocating task every 0.5 s.  The
# same rounds then run with the loads gone, for the idle figure.
#
# Usage: tests/pve_alloc_under_load.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default the physical pair; participant 1 second)
#   STORAGE    Proxmox storage id (shared)
#   VMID       an id no VM uses (990)
#   ALLOCS     rounds under load (5)
#   LOAD_S     seconds the fio loads run (150)
#   WARM_S     seconds of load before the first round (15)
#   MNT        where STORAGE keeps its files, and the loads run (/mnt/shared);
#              PVE_PAIR may name one host twice (both loads and the rounds on
#              it), the shape a single-host XFS yardstick can run in too
#   ALLOC_BUDGET  seconds one allocation may take (10: Proxmox's lock aborts
#              at 60; idle is ~0.5 s, so this is well past twice that)
# Exit 0 when every allocation under load finished within ALLOC_BUDGET.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
STORAGE=${STORAGE:-shared}
VMID=${VMID:-990}
ALLOCS=${ALLOCS:-5}
LOAD_S=${LOAD_S:-150}
WARM_S=${WARM_S:-15}
BUDGET=${ALLOC_BUDGET:-10}
MNT=${MNT:-/mnt/shared}
EVID="$REPO/tests/evidence/pve_alloc_under_load/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1
STAMP=$(date -u +%H%M%S)

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }

# one allocation round on participant 1, its task's kernel stack sampled
# every 0.5 s into the round's own file
ROUND='t0=$(date +%s%N); pvesm alloc '"$STORAGE $VMID"' vm-'"$VMID"'-disk-$1.raw 1G > /dev/null 2>&1 & a=$!; while kill -0 $a 2>/dev/null; do for t in /proc/$a/task/*; do echo "$(( ($(date +%s%N) - t0) / 1000000 ))ms $(cat $t/comm) $(head -5 $t/stack 2>/dev/null | sed "s/^\[<[0-9a-f]*>\] //; s/+0x.*//" | tr "\n" ,)"; done; for c in $(cat /proc/$a/task/*/children 2>/dev/null); do echo "$(( ($(date +%s%N) - t0) / 1000000 ))ms child $(cat /proc/$c/comm 2>/dev/null) $(head -5 /proc/$c/stack 2>/dev/null | sed "s/^\[<[0-9a-f]*>\] //; s/+0x.*//" | tr "\n" ,)"; done; sleep 0.5; done; wait $a; rc=$?; echo "ALLOC rc=$rc ms=$(( ($(date +%s%N) - t0) / 1000000 ))"; pvesm free '"$STORAGE"':'"$VMID"'/vm-'"$VMID"'-disk-$1.raw > /dev/null 2>&1'

rounds() {  # <tag> <n>
    local i out ms
    for i in $(seq 1 "$2"); do
        out=$(on "${H[1]}" "bash -c '$ROUND' x $i" $(( BUDGET + 70 )))
        printf '%s\n' "$out" > "$EVID/$1-$i.samples"
        ms=$(grep -o 'ALLOC rc=[0-9]* ms=[0-9]*' <<<"$out")
        say "$1 round $i: ${ms:-no answer}"
        echo "$1 ${ms:-ALLOC rc=timeout ms=$(( (BUDGET + 70) * 1000 ))}" >> "$EVID/allocs"
    done
}

say "evidence $EVID"
FIO="fio --name=vmlike --directory=$MNT/allocload/$STAMP/p\$P --size=1G --bs=4k --rw=randrw --rwmixread=60 --direct=1 --ioengine=libaio --iodepth=16 --time_based --runtime=$LOAD_S --output-format=terse"
for p in 0 1; do
    on "${H[$p]}" "P=$p; mkdir -p $MNT/allocload/$STAMP/p\$P && $FIO > /dev/null 2>&1; echo FIO_RC=\$?" $(( LOAD_S + 120 )) > "$EVID/fio-p$p.out" 2>&1 &
done
sleep "$WARM_S"
rounds load "$ALLOCS"
wait
for p in 0 1; do sed "s/^/${H[$p]} p$p /" "$EVID/fio-p$p.out" | tee -a "$EVID/log"; done
on "${H[0]}" "rm -rf $MNT/allocload/$STAMP && echo CLEANED" 120 | tee -a "$EVID/log"
rounds idle 3

worst=$(grep '^load ' "$EVID/allocs" | grep -o 'ms=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
failed=$(grep '^load ' "$EVID/allocs" | grep -vc 'rc=0 ')
say "under load: worst ${worst:-?} ms, $failed failed; idle: $(grep '^idle ' "$EVID/allocs" | grep -o 'ms=[0-9]*' | tr '\n' ' ')"
if [ "$failed" = 0 ] && [ -n "$worst" ] && [ "$worst" -le $(( BUDGET * 1000 )) ]; then
    say "PASS"; exit 0
fi
say "FAIL"; exit 1
