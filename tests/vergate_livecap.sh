#!/bin/bash
# vergate_livecap.sh — run one tests/vergate.sh arm on a probe node while its
# kernel log is STREAMED to clyde (sess421).  Twice (sess419, sess420 rerun)
# the mixed_build arm failed at its own dirty-mount step with
# 'mount(2): Transport endpoint is not connected' followed by
# '/usr/bin/umount: Input/output error' (the node's root fs dying), and both
# times the post-mortem `dmesg` capture was EMPTY because the node had
# already been power-cycled by the next prep.  A live `dmesg -w` over ssh
# lands the lines on clyde as they are printed, so a root-fs death or a
# reboot can no longer erase them.
#
# budget: vergate mixed_build ~90 s + prep restore; caller bound 200 s.
#
# Usage: tests/vergate_livecap.sh <label> [probe=test32] [arm=mixed_build]
set -u
LABEL=${1:?label}; PN=${2:-test32}; ARM=${3:-mixed_build}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_vergate_livecap_$ARM
mkdir -p "$OUT"
MARK="VGLIVE-$LABEL-$$"
echo "=== vergate_livecap label=$LABEL probe=$PN arm=$ARM out=$OUT $(date -u +%FT%TZ) ==="
timeout 12 $SSH "$PN" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1
# pre-state of the probe node's root fs and loop device
timeout 20 $SSH "$PN" "df -h / /tmp; losetup -l; mount | grep -c ' / '; dmesg | grep -ac 'EXT4-fs error\|I/O error\|Oops\|BUG:'" > "$OUT/pre.txt" 2>&1
# live stream: dmesg -w over ssh, detached from this shell's lifetime
timeout 400 $SSH "$PN" "dmesg -w" > "$OUT/dmesg_live_$PN.txt" 2>&1 &
CAP=$!
sleep 2
timeout 150 tests/vergate.sh "$PN" "$ARM" > "$OUT/vergate.txt" 2>&1; rc=$?
echo "STAGE vergate $ARM rc=$rc"
grep -a 'RESULT:\|SUMMARY:' "$OUT/vergate.txt"
sleep 3
kill $CAP 2>/dev/null
timeout 20 $SSH "$PN" "df -h / /tmp; losetup -l; dmesg | grep -ac 'EXT4-fs error\|I/O error\|Oops\|BUG:'; uptime" > "$OUT/post.txt" 2>&1
echo "  INFO live capture lines=$(wc -l < "$OUT/dmesg_live_$PN.txt") since-mark=$(sed -n "/$MARK/,\$p" "$OUT/dmesg_live_$PN.txt" | wc -l)"
sed -n "/$MARK/,\$p" "$OUT/dmesg_live_$PN.txt" | grep -a 'ENOTCONN\|Transport\|P-VERGATE\|EXT4\|I/O error\|Oops\|BUG:\|loop7\|vgate\|mxfs: .*ERR\|refus' | head -40
echo "=== vergate_livecap $LABEL $ARM: rc=$rc out=$OUT $(date -u +%FT%TZ) ==="
exit $rc
