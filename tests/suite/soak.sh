#!/bin/bash
# soak — mixed FS workload for a duration; no errors, FS stays healthy.
# Agnostic. SOAK_SECONDS controls length (default 30 for a smoke run).
SUITE_TEST_NAME=soak
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
DUR="${SOAK_SECONDS:-30}"
W="$MNT/.suite_soak.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || { echo "RESULT: FAIL | test=soak | nodes=$NODES | measured=setup | reason=mkdir"; exit 1; }
trap 'rm -rf "$W" 2>/dev/null' EXIT
# Pass criterion (per tests/criteria/soak): no op failures AND no kernel
# errors/fences/shutdowns in dmesg during the run. Mark the kernel log so we
# only inspect this run's window.
MARKER="MXFS_SOAK_$(date +%s)_$$"
echo "$MARKER" > /dev/kmsg 2>/dev/null
DPAT='Internal error|Corruption|SHUTDOWN|shutting down|Free inode|reservation conflict|BUG:|Oops|stuck for|call trace'
end=$(( $(date +%s) + DUR )); ops=0; errs=0
while [ "$(date +%s)" -lt "$end" ]; do
  f="$W/f$((ops % 50))"
  { head -c $(( (RANDOM * 64) + 1 )) /dev/urandom > "$f" \
      && cp "$f" "$f.cp" && cmp -s "$f" "$f.cp" && rm -f "$f.cp" \
      && mkdir -p "$W/d$((ops % 10))"; } || errs=$((errs + 1))
  ops=$((ops + 1))
done
echo ok > "$W/final" 2>/dev/null && [ "$(cat "$W/final" 2>/dev/null)" = ok ] || errs=$((errs + 1))
# dmesg hits since our marker — persist the matching lines for forensics
# (count/threshold unchanged; a FAIL without the lines is undiagnosable
# once the VM reboots, since virsh destroy loses the unflushed journal).
HITFILE="/root/soak_hits.$MARKER.txt"
dmesg 2>/dev/null | awk -v m="$MARKER" 'f{print} $0 ~ m{f=1}' | grep -iE "$DPAT" > "$HITFILE"
dmesg_hits=$(grep -c . "$HITFILE")
if [ "${dmesg_hits:-0}" -gt 0 ]; then
  echo "SOAK-HIT-SAMPLE ($(hostname), first 5 of $dmesg_hits):"
  head -5 "$HITFILE" | sed 's/^/  SOAK-HIT: /'
fi
st=PASS; reason=""
if [ "$errs" -gt 0 ]; then st=FAIL; reason="$errs op failures"; fi
if [ "${dmesg_hits:-0}" -gt 0 ]; then st=FAIL; reason="${reason:+$reason; }$dmesg_hits dmesg error hits"; fi
echo "RESULT: $st | test=soak | nodes=$NODES | measured=dur=${DUR}s ops=$ops errs=$errs dmesg_hits=${dmesg_hits:-0} | reason=$reason"
[ "$st" = PASS ]
