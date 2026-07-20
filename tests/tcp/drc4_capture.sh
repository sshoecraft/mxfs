#!/bin/bash
# drc4_capture.sh — clean 4-node reset + prep (TCP, dirwr=2 content traces) then
# run drc4_repro to capture the dir_reuse single-dirent loss with classification
# + per-daddr release/acquire timeline probes.  RULE-4 decisive experiment for
# Rank1 (grant-before-flush ordering) vs Rank2 (drain coverage hole).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
SSH="$REPO/tools/mxfs_sshpass.sh"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
NODES=(test1 test2 test3 test4)
V="virsh -c qemu:///system"
ROUNDS="${1:-24}"
r() { local n="$1"; shift; timeout 90 bash "$SSH" "$n" "$P" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

echo "=== reset test1-4 ==="
for n in "${NODES[@]}"; do $V destroy "$n" >/dev/null 2>&1; done; sleep 4
for n in "${NODES[@]}"; do $V start "$n" >/dev/null 2>&1; done
for i in $(seq 1 50); do
    ok=0; for n in "${NODES[@]}"; do timeout 5 bash "$SSH" "$n" "$P" true >/dev/null 2>&1 && ok=$((ok+1)); done
    [ "$ok" -eq 4 ] && { echo "up after $((i*5))s"; break; }; sleep 5
done
[ "$ok" -eq 4 ] || { echo "BOOT FAIL"; exit 1; }

echo "=== clean slate (umount+rmmod) ==="
for n in "${NODES[@]}"; do r "$n" "umount /mnt/shared 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null; true" >/dev/null & done; wait

echo "=== mkfs on test1 ==="
r test1 "MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_fs.sh" | grep -E 'FS_PREP_OK|FAIL'

echo "=== form test1 (tcp dirwr=2) ==="
r test1 "MXFS_REPO=/src/mxfs MXFS_EXTRA_MODARGS='dirwr=2' bash /src/mxfs/tests/setup/prep_node.sh tcp" | grep -E 'NODE_PREP_OK|FAIL'
sleep 2
echo "=== join test2-4 (tcp dirwr=2) ==="
for n in test2 test3 test4; do r "$n" "MXFS_REPO=/src/mxfs MXFS_EXTRA_MODARGS='dirwr=2' bash /src/mxfs/tests/setup/prep_node.sh tcp" | grep -E 'NODE_PREP_OK|FAIL' & done; wait

echo "=== confirm srcversion + dirwr ==="
for n in "${NODES[@]}"; do echo -n "$n: "; r "$n" "cat /sys/module/mxfs/srcversion; cat /sys/module/mxfs/parameters/dirwr; mount|grep -c 'type mxfs'" | tr '\n' ' '; echo; done

echo "=== run drc4_repro $ROUNDS rounds ==="
bash tests/tcp/drc4_repro.sh 4 50 "$ROUNDS"
