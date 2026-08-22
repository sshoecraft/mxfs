#!/bin/bash
# delay_selftest.sh — validate the delayed LUN stack STANDALONE, before any arm.
#
# The sess133 RULE-5 ruling makes this a precondition of every A/B run:
#
#   "validate the delay stack standalone first (single write, no P&A, nothing
#    below before ~W, landing after ~W)"
#
# WHY IT IS NOT OPTIONAL.  Both properties the A/B scores are statements about
# WHEN a write becomes observable below dm-delay.  If the delay is not actually
# in force — dm table reloaded to 0, the write not really queued above the
# boundary, the observation offset resolving to the wrong physical block — then
# the arm measures nothing and both a PASS and a FAIL are meaningless.  This
# check establishes the instrument before the instrument is trusted.
#
# It writes through the VICTIM path to a scratch LBA no arm ever uses (arms live
# at 131072..170000; this uses 65536) and reads the device immediately BELOW
# dm-delay with aligned O_DIRECT, which is the only sound observation (there are
# five cache aliases between target and backing file).
#
# Usage:  delay_selftest.sh [W_MS]     default 12000, matching inflight_ab.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
P="$HERE/prprobe"
STACK="$HERE/stack.sh"

W_MS=${1:-12000}
LBA=65536                       # scratch: below every arm's LBA range
NBLK=8                          # 4 KiB at blocksize 512
PAT=0x5a

eval "$(sudo bash "$STACK" devmap)"
[ -n "${LOOP:-}" ] && [ -n "${VICTIM:-}" ] \
  || { echo "stack not up — run: sudo bash $STACK up" >&2; exit 2; }

OFF=$((LBA * 512))
# In fileio mode the LUN is a file, so the below-delay offset is its FIEMAP
# physical offset.  blockio reports identity, so this is uniform.
PHYS=$(sudo bash "$STACK" fiemap "$OFF" 4096 | sed -n "s/.* phys=\([0-9]*\).*/\1/p")
[ -n "$PHYS" ] || { echo "FAIL: could not resolve physical offset for $OFF" >&2; exit 1; }
echo "mode=$MODE gen=${GEN:-n/a} lun_off=$OFF phys_off=$PHYS loop=$LOOP victim=$VICTIM W=${W_MS}ms"

# Clean the observation block from BELOW the delay so the pattern we look for
# cannot be left over from an earlier run.
sudo "$P" dwrite "$LOOP" "$PHYS" 4096 0x00 >/dev/null || { echo "FAIL: could not clear block"; exit 1; }
pre=$(sudo "$P" dread "$LOOP" "$PHYS" 4096 | sed -n 's/.*first=\([^ ]*\).*/\1/p')
[ "$pre" = "0x0" ] || [ "$pre" = "0x00" ] || echo "note: pre-state first=$pre (expected 0x0)"

sudo bash "$STACK" delay "$W_MS" >/dev/null || { echo "FAIL: could not set delay"; exit 1; }

t0=$(date +%s.%N)
sudo "$P" write "$VICTIM" "$LBA" "$NBLK" "$PAT" 120000 512 >/tmp/mxfs_delay_selftest_write.txt 2>&1 &
wpid=$!

# Poll below the delay for 2x W.  The pattern must NOT appear before ~W.
DUR=$((W_MS * 2))
poll=$(sudo "$P" poll "$LOOP" "$PHYS" 4096 "$PAT" "$DUR" 100)
wait "$wpid" 2>/dev/null
t1=$(date +%s.%N)

echo "$poll"
first=$(echo "$poll" | sed -n 's/.*t_first_present=\([0-9.-]*\).*/\1/p' | head -1)
# prprobe reports t_first_present=-1 when the pattern never appeared.
case "$first" in -1*) first="" ;; esac
sudo bash "$STACK" delay 0 >/dev/null

if [ -z "$first" ]; then
    echo "RESULT: FAIL — pattern never became observable below the delay in ${DUR}ms"
    exit 1
fi
# The poll reports an absolute CLOCK_MONOTONIC stamp; convert to seconds after
# the write was submitted using the poll's own start stamp.
start=$(echo "$poll" | sed -n 's/^poll_start .* t=\([0-9.]*\).*/\1/p' | head -1)
lat=$(awk -v a="$first" -v b="$start" 'BEGIN{printf "%.3f", a-b}')
lo=$(awk -v w="$W_MS" 'BEGIN{printf "%.3f", w/1000*0.8}')
hi=$(awk -v w="$W_MS" 'BEGIN{printf "%.3f", w/1000*1.6+2}')
echo "landing latency below delay: ${lat}s   (expected ${lo}..${hi}s for W=${W_MS}ms)"
ok=$(awk -v l="$lat" -v lo="$lo" -v hi="$hi" 'BEGIN{print (l>=lo && l<=hi) ? 1 : 0}')
if [ "$ok" = "1" ]; then
    echo "RESULT: PASS — delay is in force, nothing landed early, observation offset is correct"
    exit 0
fi
echo "RESULT: FAIL — landing at ${lat}s is outside the delay window; the instrument is not sound"
exit 1
