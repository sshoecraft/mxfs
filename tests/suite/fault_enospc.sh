#!/bin/bash
# fault_enospc — fill the filesystem and verify it returns ENOSPC cleanly
# (no hang/crash), stays mounted, and recovers when space is freed. Agnostic.
SUITE_TEST_NAME=fault_enospc
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"
W="$MNT/.suite_enospc.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || { echo "RESULT: FAIL | test=$SUITE_TEST_NAME | nodes=$NODES | measured=setup | reason=mkdir"; exit 1; }
trap 'rm -rf "$W" 2>/dev/null' EXIT

# consume most free space fast (fallocate), then dd the remainder to hit ENOSPC
avail_kb=$(df -P "$MNT" | awk 'NR==2{print $4}')
resv=$(( (avail_kb - 131072) * 1024 ))
[ "$resv" -gt 0 ] && fallocate -l "$resv" "$W/reserve" 2>/dev/null
dd if=/dev/zero of="$W/fill" bs=1M 2>"$W/dd.err"; ddrc=$?
usepct=$(df -P "$MNT" | awk 'NR==2{gsub(/%/,"",$5);print $5}')

enospc(){ [ "$ddrc" -ne 0 ] && grep -qi 'no space left' "$W/dd.err"; }
ck "write past capacity -> ENOSPC" enospc
ck "fs reports near-full (>=98%)"  test "${usepct:-0}" -ge 98
ck "fs still mounted under ENOSPC" mountpoint -q "$MNT"

rm -f "$W/fill" "$W/reserve"; sync
recover(){ echo ok > "$W/after" 2>/dev/null && [ "$(cat "$W/after" 2>/dev/null)" = ok ]; }
ck "writable again after freeing"  recover
finish
