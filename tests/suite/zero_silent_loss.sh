#!/bin/bash
# zero_silent_loss — agnostic multi-node "no silent data/dirent loss" test.
#
# Each node writes N files of known random content (+md5), barrier, then EVERY
# node cross-verifies EVERY node's files (content md5 + size) and the global
# count/uniqueness — so a silently lost dirent or truncated/clobbered file is
# caught from every reader's view.  Ported from tests/cluster/test_concurrent_write.sh
# into the agnostic + coord_barrier suite format.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.zero_silent_loss"
mkdir -p "$D" 2>/dev/null

FSIZE=262144   # 256KB
FPN=10

ck "zsl barrier ready" coord_barrier "zsl_ready"

for i in $(seq 1 "$FPN"); do
    dd if=/dev/urandom of="/tmp/zsl_${R}_${i}" bs="$FSIZE" count=1 2>/dev/null
    cp "/tmp/zsl_${R}_${i}" "$D/node${R}_data${i}"
    md5sum "/tmp/zsl_${R}_${i}" | awk '{print $1}' > "$D/node${R}_data${i}.md5"
    rm -f "/tmp/zsl_${R}_${i}"
done
sync

ck "zsl barrier write-done" coord_barrier "zsl_write_done"

# Every node cross-verifies EVERY node's data (content + size = no silent loss).
for n in $(seq 1 "$T"); do
    for i in $(seq 1 "$FPN"); do
        ckeq "zsl r${R} md5 node${n}_data${i}" \
             "$(cat "$D/node${n}_data${i}.md5" 2>/dev/null)" \
             "$(md5sum "$D/node${n}_data${i}" 2>/dev/null | awk '{print $1}')"
        ckeq "zsl r${R} size node${n}_data${i}" "$FSIZE" \
             "$(stat -c%s "$D/node${n}_data${i}" 2>/dev/null)"
    done
done

# Rank 1 asserts the global count + uniqueness (no dirent lost or duplicated).
if [ "$R" = 1 ]; then
    ckeq "zsl total file count" "$((T * FPN))" \
         "$(ls "$D"/node*_data[0-9]* 2>/dev/null | grep -vc '\.md5$' )"
fi

ck "zsl barrier verify" coord_barrier "zsl_verify"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
