#!/bin/bash
# ccloop_reset.sh — robust teardown of testN nodes for the tcp-dlm criterion work.
# After a metadata-corruption SHUTDOWN, the mount goes EIO and umount wedges in
# D-state, holding the mxfs module refcount so rmmod fails forever.  A plain
# teardown loop then reports WEDGED and the next mkfs fails ("device is busy").
# This helper tears down, and on a wedge it hard-resets that VM via virsh
# (RULE 2: rebooting test VMs is allowed; only the host is off-limits) and waits
# for it to come back clean.
#
# Usage: scripts/ccloop_reset.sh <N>      # reset test1..testN
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
N="${1:?usage: ccloop_reset.sh <N>}"
VIRSH="virsh -c qemu:///system"

run() { timeout 30 "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

teardown_one() {
    local n="$1"
    run "$n" '
      umount -f /mnt/shared 2>/dev/null; umount -l /mnt/shared 2>/dev/null; sleep 1
      for t in 1 2 3 4 5 6; do lsmod|grep -q "^mxfs " || break; rmmod mxfs 2>/dev/null; sleep 2; done
      lsmod|grep -q "^mxfs " && echo WEDGED || echo CLEAN'
}

wait_up() {
    local n="$1" t out
    for t in $(seq 1 48); do
        out=$(timeout 6 "$SSH" "$n" "$PF" 'echo H=$(hostname); lsmod|grep -q "^mxfs " && echo L || echo C' 2>&1 | grep -vE '^Warning|^Unauthorized|^If you')
        echo "$out" | grep -q "H=$n" && { echo "$out" | grep -q '^C$' && { echo "$n up+clean"; return 0; }; }
        sleep 5
    done
    echo "$n DID NOT COME BACK CLEAN"; return 1
}

reset_one() {
    local n="$1" r
    r=$(teardown_one "$n" | tail -1)
    if echo "$r" | grep -q CLEAN; then echo "$n clean"; return 0; fi
    echo "$n wedged -> virsh reset"
    $VIRSH destroy "$n" >/dev/null 2>&1; sleep 3; $VIRSH start "$n" >/dev/null 2>&1
    wait_up "$n"
}

rc=0
for i in $(seq 1 "$N"); do reset_one "test$i" & done
wait
echo "=== ccloop_reset done for $N node(s) ==="
