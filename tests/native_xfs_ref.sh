#!/bin/bash
# tests/native_xfs_ref.sh — native-XFS reference numbers for the RULE-0 pace
# ratios, taken on the SAME LUN via run.sh's `1 xfs` mode (test1, no mxfs.ko).
# Mirrors the mxfs measurement shapes so the pairing is honest:
#   - create: N sequential creates into one dir (create_scale_curve shape)
#   - cold per-syscall pass over K dirs: stat / open / getdents / rmdir
#     (shared_unlink_pace phase-C shape; "cold" via echo 3 > drop_caches,
#     the native equivalent of "created by another node, not in cache")
# PRECONDITION: test1 has native XFS mounted at /mnt/shared
#   (MXFS_FORCE_PREP=1 ./run.sh 1 xfs prep_cluster)
# usage: native_xfs_ref.sh [node=test1] [K=32]
set -u
N="${1:-test1}"
K="${2:-32}"
SSH=tools/mxfs_sshpass.sh
D="/mnt/shared/.nref_$(date +%s)"

$SSH "$N" "mount | grep -q ' /mnt/shared type xfs ' || { echo NOT-NATIVE-XFS; exit 9; }" 2>/dev/null | grep -q NOT-NATIVE-XFS && { echo "ABORT: /mnt/shared on $N is not native xfs"; exit 1; }

$SSH "$N" "mkdir -p $D" >/dev/null 2>&1
echo "=== native XFS reference on $N (same LUN), K=$K ==="

$SSH "$N" "python3 - <<'EOF'
import os, time
D='$D'; K=$K
def ms(f):
    t=time.perf_counter(); f(); return (time.perf_counter()-t)*1000
# --- create: K sequential creates in one dir ---
os.mkdir(D+'/cr')
samples=[]
for i in range(K):
    samples.append(ms(lambda i=i: (open(f'{D}/cr/f{i}','w').write('x'))))
os.sync()
samples.sort()
print(f'create        n={K} p50={samples[K//2]:.2f}ms mean={sum(samples)/K:.2f}ms max={samples[-1]:.2f}ms')
# --- K dirs each with one entry (peer-created-dir shape) ---
for i in range(K):
    os.mkdir(f'{D}/d{i}'); open(f'{D}/d{i}/e','w').write('x')
os.sync()
EOF" 2>/dev/null

for PHASE in "stat:stat" "open:open" "getdents:ls" "rmdir:rmdir"; do
  P="${PHASE%%:*}"
  $SSH "$N" "sync; echo 3 > /proc/sys/vm/drop_caches; python3 - <<'EOF'
import os, time
D='$D'; K=$K
res=[]
for i in range(K):
    p=f'{D}/d{i}'
    t=time.perf_counter()
    if '$P'=='stat': os.stat(p)
    elif '$P'=='open':
        fd=os.open(p, os.O_RDONLY|os.O_DIRECTORY); os.close(fd)
    elif '$P'=='getdents': os.listdir(p)
    elif '$P'=='rmdir':
        os.unlink(p+'/e'); os.rmdir(p)
    res.append((time.perf_counter()-t)*1000)
res.sort()
print(f'{'$P':13s} n={K} cold p50={res[K//2]:.2f}ms mean={sum(res)/K:.2f}ms max={res[-1]:.2f}ms')
EOF" 2>/dev/null
done
$SSH "$N" "rm -rf $D" >/dev/null 2>&1
echo "=== done ==="
