#!/bin/bash
# pve_klog_sweep.sh — count chosen kernel-log patterns on each host of a
# Proxmox pair, boot by boot, since a given time.
#
# A verification that rests on something NOT happening (no RCU warning at a
# peer exclusion, no heartbeat stall, no authority closure, no oops) has to
# read every boot in its window: a crash step resets a host, so the boot that
# had the event is usually not the current one.  `journalctl --list-boots`
# names the boots, and each is read on its own with `-k -b <id> --since`.
#
# Usage: tools/pve_klog_sweep.sh <since> [pattern ...]
#   since    anything `journalctl --since` accepts, in the HOST's clock (after
#            a reset a Proxmox host's clock can run minutes off until chrony
#            slews it, so leave a margin)
#   pattern  extended regular expressions to count; default the set below
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81")
#
# Output: per host, one BOOT line per boot with kernel lines in the window
# (index, boot id, first and last line's time, the line count, and each
# pattern's count), then per host a TOTAL line, and the patterns by number.
# It grades nothing.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
[ $# -ge 1 ] || { echo "usage: $0 <since> [pattern ...]"; exit 2; }
SINCE=$1
shift
if [ $# -gt 0 ]; then
    PATS=("$@")
else
    PATS=('Voluntary context switch within RCU'
          'BUG:|Oops|general protection fault|Kernel panic|kernel BUG'
          'WARNING: CPU'
          'blocked for more than|hung_task'
          'P278-HB-STALL'
          'P290-AUTH-CLOSED|P290-AUTH-REFUSED'
          'P163-WITHDRAW-STAMP|AUTHORITY_LEASE_EXPIRED'
          'P-TAUTH-RELEASE-WAIT|P958-ACQ-CANCEL-UNACKED'
          'P-TAUTH-TAKEOVER-UNDER-JUDGEMENT.*via=takeover'
          'P960-AUTH-TRANSITION-STALLED|P960-STALLED-PAGE'
          'I/O error|Buffer I/O error'
          'P163-RECOVERY-COMPLETE')
fi
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"

i=0
for p in "${PATS[@]}"; do
    i=$((i + 1))
    echo "pattern $i: $p"
done
for h in "${PAIR[@]}"; do
    {
        printf 'set -- %q' "$SINCE"
        printf ' %q' "${PATS[@]}"
        printf '\n'
        cat <<'EOF'
since=$1; shift
journalctl --list-boots --no-pager 2>/dev/null | awk '$1 ~ /^-?[0-9]+$/ {print $1, $2}' |
while read -r idx id; do
    log=$(journalctl -k -b "$id" --since "$since" --no-pager -o short-iso 2>/dev/null | grep -v '^-- ')
    [ -n "$log" ] || continue
    line="BOOT $idx $id $(head -1 <<<"$log" | cut -d' ' -f1)..$(tail -1 <<<"$log" | cut -d' ' -f1) lines=$(wc -l <<<"$log")"
    n=0
    for p in "$@"; do
        n=$((n + 1))
        line="$line p$n=$(grep -cE -- "$p" <<<"$log")"
    done
    echo "$line"
done
EOF
    } | timeout 180 "$SSHP" "$h" 'bash -s' 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$' > /dev/shm/pve_klog_sweep.$$
    sed "s/^/$h /" /dev/shm/pve_klog_sweep.$$
    python3 -I - "$h" /dev/shm/pve_klog_sweep.$$ <<'PY'
import collections, re, sys
host, path = sys.argv[1], sys.argv[2]
tot = collections.Counter()
boots = 0
for line in open(path):
    if not line.startswith("BOOT "):
        continue
    boots += 1
    for k, v in re.findall(r" (p\d+)=(\d+)", line):
        tot[k] += int(v)
print("%s TOTAL boots=%d %s" % (host, boots, " ".join("%s=%d" % (k, tot[k]) for k in sorted(tot, key=lambda s: int(s[1:])))))
PY
    rm -f /dev/shm/pve_klog_sweep.$$
done
