#!/bin/bash
# tests/d0532_peer_conflict.sh <file> — runs ON the peer node, driven by
# tests/d0532_nowait_iomap_probe.sh (PEER=...).  Forces grant conflicts on
# <file> while the node under test runs its io_uring phases: O_DIRECT reads
# (PR) and whole-block O_DIRECT writes of a 'p' pattern (EX) at random 4 KiB
# offsets inside the first 64 KiB.
#
# Handshake (files next to <file>):
#   waits up to 10 s for <file> to exist, then loops until <file>.stop
#   appears; then drops caches, prints its image line, touches <file>.peerdone.
# Prints: PEER reads=<n> writes=<n> failed=<n>
#         IMG ... (tests/d0532_img_check.py)
# budget: bounded by the probe's own window (<= 170 s) and by 200 s here.
set -u
F=${1:?file}
DL=$(( SECONDS + 200 ))
python3 -c "open('/tmp/d0532_pblk','wb').write(b'p'*4096)" || exit 1
for i in $(seq 1 100); do [ -f "$F" ] && break; sleep 0.1; done
n=0; w=0; bad=0
while [ ! -f "$F.stop" ] && [ "$SECONDS" -lt "$DL" ]; do
  if dd if="$F" of=/dev/null bs=4k count=16 iflag=direct status=none; then n=$((n+1)); else bad=$((bad+1)); fi
  if dd if=/tmp/d0532_pblk of="$F" bs=4k seek=$((RANDOM % 16)) count=1 conv=notrunc oflag=direct status=none; then w=$((w+1)); else bad=$((bad+1)); fi
done
echo "PEER reads=$n writes=$w failed=$bad"
sync; echo 3 > /proc/sys/vm/drop_caches
python3 /src/mxfs/tests/d0532_img_check.py "$F"
: > "$F.peerdone"
