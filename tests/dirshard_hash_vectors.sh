#!/bin/bash
# dirshard_hash_vectors.sh — pin the three SipHash-2-4 implementations the
# directory-sharding router depends on to each other (sess466,
# docs/dir-sharding.md, format include/mxfs/mxfs_dirshard.h):
#   1. tools/chk_mxfs --dirshard-hash (the userspace reference mirror)
#      against the PUBLISHED SipHash-2-4 test vector (Aumasson & Bernstein,
#      key 00..0f, message 00..0e -> 0xa129ca6149be45e5);
#   2. the kernel's <linux/siphash.h> routing (MXFS_IOC_DIRSHARD_INFO
#      name_hash/name_shard for a real sharded directory on <node>) against
#      chk_mxfs under that directory's key (root-only; the ioctl returns the
#      key only with CAP_SYS_ADMIN);
#   3. the shard index formula (hash & (N-1)) in both.
# Usage: tests/dirshard_hash_vectors.sh [node] [sharded-dir-on-node]
#   with no node: vector check only (no device, no rig).
# Exit 0 PASS, 1 FAIL, 2 INFRA.  budget: whole script < 10 s.
set -u
NODE=${1:-}
SDIR=${2:-/mnt/shared/dirshard_vectors}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CHK=$REPO/tools/chk_mxfs
SSH=$REPO/tools/mxfs_sshpass.sh
fails=0
say() { echo "[dirshard_hash] $*"; }
fail() { say "FAIL: $*"; fails=$((fails+1)); }
pass() { say "PASS: $*"; }

[ -x "$CHK" ] || { say "INFRA: $CHK missing (make tools)"; exit 2; }

# 1. published vector
want=0xa129ca6149be45e5
out=$("$CHK" --dirshard-hash 000102030405060708090a0b0c0d0e0f hex:000102030405060708090a0b0c0d0e 2>&1)
got=$(echo "$out" | grep -oE 'hash=0x[0-9a-f]+' | cut -d= -f2)
if [ "$got" = "$want" ]; then pass "published SipHash-2-4 vector: $got"; else fail "published vector: got '$got' want $want ($out)"; fi
# 3. index formula on the vector: low bits of the hash
h=$(( got ))
s16=$(( h & 15 )); s32=$(( h & 31 )); s64=$(( h & 63 ))
echo "$out" | grep -q "shard16=$s16 shard32=$s32 shard64=$s64" && pass "shard index formula (16/32/64 = $s16/$s32/$s64)" || fail "shard index fields: $out"

# 2. kernel vs userspace on a live sharded directory
if [ -n "$NODE" ]; then
    names="a b hello.txt file-0001 $(printf 'x%.0s' $(seq 1 200)) Ünïcödé.名"
    j=$(timeout 20 "$SSH" "$NODE" "python3 /src/mxfs/tests/dirshard_ioctl.py info $SDIR" 2>/dev/null | sed -n '/^{/,$p')
    key=$(echo "$j" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("hash_key",""))' 2>/dev/null)
    n=$(echo "$j" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("nshards",0))' 2>/dev/null)
    if [ -z "$key" ] || [ "$key" = "$(printf '0%.0s' $(seq 1 32))" ] || [ "${n:-0}" = 0 ]; then
        fail "INFO on $NODE:$SDIR returned no key/nshards (key='$key' n='$n'): $(echo "$j" | head -c 200)"
    else
        for nm in $names; do
            kj=$(timeout 20 "$SSH" "$NODE" "python3 /src/mxfs/tests/dirshard_ioctl.py info $SDIR '$nm'" 2>/dev/null | sed -n '/^{/,$p')
            kh=$(echo "$kj" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["name_hash"], d["name_shard"])' 2>/dev/null)
            uh=$("$CHK" --dirshard-hash "$key" "$nm" | grep -oE 'hash=0x[0-9a-f]+ .*shard'"$n"'=[0-9]+' | sed -E 's/hash=(0x[0-9a-f]+).*shard'"$n"'=([0-9]+)/\1 \2/')
            if [ -n "$kh" ] && [ "$kh" = "$uh" ]; then pass "kernel == chk for '$nm': $kh"; else fail "kernel '$kh' != chk '$uh' for '$nm'"; fi
        done
    fi
fi
say "fails=$fails"
[ "$fails" -eq 0 ] && { echo "VERDICT PASS dirshard_hash_vectors"; exit 0; } || { echo "VERDICT FAIL dirshard_hash_vectors fails=$fails"; exit 1; }
