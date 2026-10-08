#!/bin/bash
# pve_late_deny.sh — a master's would-block answer to a no-queue AG probe
# arrives after the probe gave up, while the same host is waiting on a blocking
# acquire of that AG.  The blocking acquire must stay pending for its own
# answer; before 0.90.102 the late deny completed it with -EAGAIN, and inside a
# deferred-op chain that shut the mount down (physical pair, 2026-10-07
# 20:14:54, 'DLM AG lock failed: ag=2 rc=-11' in xfs_defer_finish_noroll).
#
# For D-TCP-LATE-WOULD-BLOCK-DENY-FAILS-A-BLOCKING-AG-ACQUIRE-AND-SHUTS-THE-MOUNT.
# On hardware the race needed a master slow enough to answer after the
# requester's one-attempt wait (1000 ms); here the test knob dl_deny_delay_ms
# holds every AG would-block deny on both hosts past it, for the next
# dl_deny_delay_left denies, so every no-queue AG probe that meets a held AG is
# answered late.  Both hosts then allocate at once in a tree of their own
# (many files, each written and fsynced), which is what makes the allocator
# probe AGs the peer holds.
#
# Usage: tests/pve_late_deny.sh
# Env:
#   PVE_PAIR      "<addr> <addr>" (default nested pair A; the physical pair
#                 is "192.168.1.80 192.168.1.81")
#   DELAY_MS      the deny's hold (1500: past the 1000 ms attempt)
#   DENIES        denies held per host (60)
#   LOAD_S        seconds each host allocates (60)
#   FILES_PER     files per directory per round (20), each WRITE_MB MiB (4)
# Exit 0 only if denies were held, no AG lock failed and neither mount shut
# down or withdrew, AND at least one late deny reached a blocking acquire
# (P-DENY-NOT-ASKED); 3 = clean but that never happened (NOT EXERCISED).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a H <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
[ "${#H[@]}" = 2 ] || { echo "PVE_PAIR must name two hosts" >&2; exit 2; }
MNT=/mnt/shared
DELAY_MS=${DELAY_MS:-1500}
DENIES=${DENIES:-60}
LOAD_S=${LOAD_S:-60}
FILES_PER=${FILES_PER:-20}
WRITE_MB=${WRITE_MB:-4}
EVID="$REPO/tests/evidence/pve_late_deny/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1
STAMP=$(date -u +%H%M%S)
PARAM=/sys/module/mxfs/parameters

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
count() {  # <host> <egrep>: kernel lines since this run's mark
    on "$1" "journalctl -k -b --no-pager | sed -n '/mxfs-test: late deny $STAMP/,\$p' | grep -a -c -E '$2'" 20 | tail -1
}

say "evidence $EVID"
for h in "${H[@]}"; do
    s=$(on "$h" "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion; cat /sys/module/mxfs/version; [ -e $PARAM/dl_deny_delay_ms ] && echo KNOB" 15)
    echo "$s" | tr '\n' ' ' | sed "s/^/$h: /" | tee -a "$EVID/log"; echo | tee -a "$EVID/log"
    [ "$(head -1 <<<"$s")" = 1 ] || { say "ABORT: $h has no MXFS mount"; exit 2; }
    grep -q KNOB <<<"$s" || { say "ABORT: $h's module has no dl_deny_delay_ms"; exit 2; }
done

for h in "${H[@]}"; do
    on "$h" "echo '<5>mxfs-test: late deny $STAMP' > /dev/kmsg; echo 'module mxfs format \"P-TEST-DENY-DELAY\" +p' > /proc/dynamic_debug/control; echo $DENIES > $PARAM/dl_deny_delay_left && echo $DELAY_MS > $PARAM/dl_deny_delay_ms && echo ARMED" 15 | sed "s/^/$h /" | tee -a "$EVID/log"
done

# both hosts allocate at once, each in its own tree, until LOAD_S has passed
LOAD="mkdir -p $MNT/latedeny/$STAMP/\$(hostname) && cd $MNT/latedeny/$STAMP/\$(hostname) && end=\$(( SECONDS + $LOAD_S )); r=0; while [ \$SECONDS -lt \$end ]; do mkdir r\$r; for f in \$(seq 1 $FILES_PER); do dd if=/dev/zero of=r\$r/f\$f bs=1M count=$WRITE_MB conv=fsync status=none || echo WRITE_FAIL r\$r/f\$f; done; r=\$((r+1)); done; echo ROUNDS=\$r"
for i in 0 1; do
    on "${H[$i]}" "$LOAD" $(( LOAD_S + 120 )) > "$EVID/load-$i.out" 2>&1 &
done
wait
for i in 0 1; do sed "s/^/${H[$i]} /" "$EVID/load-$i.out" | tail -5 | tee -a "$EVID/log"; done

for h in "${H[@]}"; do
    on "$h" "echo 0 > $PARAM/dl_deny_delay_ms; echo 0 > $PARAM/dl_deny_delay_left; echo 'module mxfs format \"P-TEST-DENY-DELAY\" -p' > /proc/dynamic_debug/control; echo DISARMED" 15 | sed "s/^/$h /" | tee -a "$EVID/log"
done
# cleaned up BEFORE the logs are read: a removal is allocator work too, and a
# failure it causes must be counted (the 20:14:54 shutdown came one second
# after a test that read its logs first had printed PASS)
on "${H[0]}" "rm -rf $MNT/latedeny/$STAMP && echo CLEANED" 120 | tee -a "$EVID/log"

held=0; notasked=0; bad=0
for h in "${H[@]}"; do
    d=$(count "$h" 'P-TEST-DENY-DELAY ')
    n=$(count "$h" 'P-DENY-NOT-ASKED')
    f=$(count "$h" 'AG lock failed')
    s=$(count "$h" 'Shutting down|P-WITHDRAW|BUG:|blocked for more')
    m=$(on "$h" "grep -c ' $MNT mxfs ' /proc/mounts" 15)
    say "$h held-denies=$d deny-not-asked=$n ag-lock-failed=$f shutdown/withdraw/bug=$s mounted=$m"
    on "$h" "journalctl -k -b --no-pager | sed -n '/mxfs-test: late deny $STAMP/,\$p' | grep -aE 'P-DENY-NOT-ASKED|AG lock failed|Shutting down|P-WITHDRAW|Corruption' | head -8" 20 | cut -c1-260 | tee -a "$EVID/log"
    held=$(( held + ${d:-0} )); notasked=$(( notasked + ${n:-0} ))
    [ "${f:-1}" = 0 ] && [ "${s:-1}" = 0 ] && [ "$m" = 1 ] || bad=1
done
grep -h WRITE_FAIL "$EVID"/load-*.out | head -5 | tee -a "$EVID/log"
grep -q WRITE_FAIL "$EVID"/load-*.out && bad=1

[ "$bad" = 0 ] || { say "FAIL"; exit 1; }
[ "$held" -gt 0 ] || { say "NOT EXERCISED: no deny was held (no no-queue AG probe met a held AG)"; exit 3; }
[ "$notasked" -gt 0 ] || { say "NOT EXERCISED: $held denies held, none reached a blocking acquire"; exit 3; }
say "PASS: $held denies held, $notasked reached a blocking acquire and left it pending"
exit 0
