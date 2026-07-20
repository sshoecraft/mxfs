#!/bin/bash
# mmap_coherency — agnostic multi-node mmap coherency test.
#
# Each node MMAP-writes a known pattern into its own file and msync()s it;
# after a barrier every node mmap/reads EVERY node's file and verifies the
# pattern — so an mmap write that doesn't become cross-node visible (page-cache
# coherency gap) is caught.  Uses python3 for the mmap+msync (no bash mmap).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.mmap_coherency"
mkdir -p "$D" 2>/dev/null

PAGES=16            # 64KB file
SZ=$((PAGES * 4096))

ck "mc barrier ready" coord_barrier "mc_ready"

# mmap-write a rank-specific repeating pattern, msync to make durable+visible.
python3 - "$D/node${R}.bin" "$R" "$SZ" <<'PY'
import sys, mmap, os
path, rank, sz = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
os.ftruncate(fd, sz)
m = mmap.mmap(fd, sz)
pat = bytes([ (rank * 37 + i) & 0xff for i in range(256) ])
for off in range(0, sz, 256):
    m[off:off+256] = pat
m.flush()            # msync
m.close(); os.close(fd)
PY
sync

ck "mc barrier write-done" coord_barrier "mc_write_done"

# Every node mmap-reads EVERY node's file and verifies the expected pattern.
for n in $(seq 1 "$T"); do
    rc=$(python3 - "$D/node${n}.bin" "$n" "$SZ" <<'PY'
import sys, mmap, os
path, rank, sz = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    fd = os.open(path, os.O_RDONLY)
except FileNotFoundError:
    print("MISSING"); sys.exit(0)
st = os.fstat(fd)
if st.st_size != sz:
    print("BADSIZE:%d" % st.st_size); os.close(fd); sys.exit(0)
m = mmap.mmap(fd, sz, prot=mmap.PROT_READ)
pat = bytes([ (rank * 37 + i) & 0xff for i in range(256) ])
ok = all(m[off:off+256] == pat for off in range(0, sz, 256))
print("OK" if ok else "MISMATCH")
m.close(); os.close(fd)
PY
)
    ckeq "mc r${R} reads node${n} mmap pattern" "OK" "$rc"
done

ck "mc barrier verify" coord_barrier "mc_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
