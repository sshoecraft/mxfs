#!/bin/bash
# caw_preflight.sh — make test1..testN clean + ready for a CAW-multipath run.sh.
#
# Why: run.sh's prep power-cycles any node whose mxfs won't rmmod, but a
# power-cycled VM boots WITHOUT /src (NFS is deliberately not an fstab
# automount — see ccmemory feedback-src-nfs-not-fstab-automount) and often
# WITHOUT a 2-path mpatha (post-reboot self-heal frequently lands only 1
# iSCSI session).  run.sh then dies in step 2/4 ("prep_fs.sh / prep_node.sh:
# No such file or directory") or the DEV wait.  This pre-flight guarantees,
# BEFORE run.sh, that every node in the set is:
#   - mxfs UNLOADED (wedged nodes power-cycled),
#   - /src (192.168.1.4:/src) mounted,
#   - /dev/mapper/mpatha present with >=2 paths (via mpath_up.sh up N).
# Then run.sh's own teardown succeeds cleanly and it never power-cycles.
#
# Usage: scripts/caw_preflight.sh <N>
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
N="${1:?usage: caw_preflight.sh <N>}"
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] && [ "$N" -le 32 ] || { echo "N out of range 1..32"; exit 2; }

# Restore the SSH password file if a reboot wiped /tmp.
[ -s "$PASS" ] || cp /home/steve/.mxfs/pass "$PASS" 2>/dev/null

ssh_q(){ timeout "${2:-25}" "$SSH" "$1" "$PASS" "$3" 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'; }

NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

echo "=== caw_preflight: $N node(s) ==="

# 1. Teardown mxfs on every node; collect the ones that won't release.
TD='
  for t in 1 2 3 4 5; do
    mountpoint -q '"$MNT"' || break
    fuser -km '"$MNT"' 2>/dev/null; sleep 1
    umount '"$MNT"' 2>/dev/null && break
    timeout 20 umount -f '"$MNT"' 2>/dev/null && break
    sleep 1
  done
  mountpoint -q '"$MNT"' && umount -l '"$MNT"' 2>/dev/null
  for t in 1 2 3 4 5; do
    lsmod | grep -q "^mxfs " || break
    rmmod mxfs 2>/dev/null && break
    sleep 2
  done
  lsmod | grep -q "^mxfs " && echo MXFS_STILL_LOADED || echo MXFS_CLEAN'
dirty=""
tmpd=$(mktemp -d)
for n in "${NODES[@]}"; do ( ssh_q "$n" 40 "$TD" > "$tmpd/$n" 2>&1 || echo UNREACHABLE > "$tmpd/$n" ) & done
wait
for n in "${NODES[@]}"; do
    if grep -q MXFS_CLEAN "$tmpd/$n" 2>/dev/null; then
        echo "  $n: clean"
    else
        echo "  $n: DIRTY ($(tr -d '\n' < "$tmpd/$n" | tail -c 40)) — will power-cycle"
        dirty="$dirty $n"
    fi
done
rm -rf "$tmpd"

# 2. Power-cycle the dirty nodes and wait for ssh to return.
if [ -n "$dirty" ]; then
    echo "=== power-cycling:$dirty ==="
    for n in $dirty; do virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    sleep 2
    for n in $dirty; do virsh -c qemu:///system start "$n" >/dev/null 2>&1; done
    for n in $dirty; do
        dl=$(( SECONDS + 180 ))
        while [ "$SECONDS" -lt "$dl" ]; do
            ssh_q "$n" 8 "echo UP" | grep -q UP && { echo "  $n: ssh back"; break; }
            sleep 3
        done
    done
fi

# 3. Mount /src on every node (reboots lose it; mkfs/prep_node need it).
echo "=== mounting /src on all $N ==="
for n in "${NODES[@]}"; do ( ssh_q "$n" 40 'mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }' >/dev/null 2>&1 ) & done
wait

# 4. Assemble /dev/mapper/mpatha (2 paths) on every node — idempotent, retries.
echo "=== mpath_up up $N ==="
bash "$SCRIPT_DIR/mpath_up.sh" up "$N" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you' | grep -E 'MPATH|OK|FAIL|host'
rc=${PIPESTATUS[0]}
if [ "$rc" != 0 ]; then
    echo "=== mpath_up first pass rc=$rc — second pass (post-reboot nodes settle) ==="
    bash "$SCRIPT_DIR/mpath_up.sh" up "$N" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you' | grep -E 'MPATH UP|FAIL'
    rc=${PIPESTATUS[0]}
fi

# 5. Final readiness verdict.
echo "=== readiness ==="
bad=0
for n in "${NODES[@]}"; do
    r=$(ssh_q "$n" 15 'echo "src=$(mountpoint -q /src && echo y || echo n) mp=$([ -b /dev/mapper/mpatha ] && echo y || echo n) ko=$([ -f /src/mxfs/mxfs.ko ] && echo y || echo n) mxfs=$(lsmod|grep -q "^mxfs " && echo y || echo n)"')
    case "$r" in *src=y*mp=y*ko=y*mxfs=n*) echo "  $n: READY ($r)";; *) echo "  $n: NOT-READY ($r)"; bad=$((bad+1));; esac
done
if [ "$bad" = 0 ]; then echo "=== PREFLIGHT OK: all $N ready ==="; exit 0; else echo "=== PREFLIGHT INCOMPLETE: $bad node(s) not ready ==="; exit 1; fi
