#!/bin/bash
#
# caw_acquire_closure.sh — does a task parked in the CAW acquire leave when its
# mount's authority closes, or does it wait out the acquire?
#
# D-A-REVOKED-MOUNTS-BLOCKED-DLM-WAITERS-ARE-NOT-ABORTED, item (4).  On TCP the
# acquire re-reads the authority at the head of every attempt (0.89.21: closure
# to waiter exit went from 72 s to 3 s, tests/tcp_lockreq_blackhole.sh lease
# arm).  The CAW acquire (dlm/dlm_caw.c) is a different wait, with its own
# exits, and had never been measured against a closure.
#
# On a 2-node CAW cluster mounted at MNT (run.sh 2 caw|cawd|cawp):
#   1. H writes F and holds its grant with the release drain paused
#      (dbg_rel_pause_*, stage 1, PAUSE_MS): a live holder W must wait behind
#   2. W reads F in the background; the lap proves W is parked in the CAW
#      acquire (the reader is alive and W logs P-ACQ-STUCK for F's inode) or
#      stops as VACUOUS: closing a lease under a task that is not waiting
#      measures nothing
#   3. W's heartbeat is parked (dl_inject_hb_pause_ms = LEASE_PARK_MS), so its
#      30 s authority lease closes under the waiter
#   4. every 2 s: is the reader alive, has P290-AUTH-CLOSED printed, has the
#      filesystem shut down
# Verdict: the lease closed, the reader left, and closure-to-exit is within
# BOUND_S (10, the TCP arm's bound).  Also: zero BUG/Oops on either node, and H
# still serves its own I/O afterwards.  W is left closed/withdrawn by design;
# the next lap must prep the cluster again.
#
# Budget (derived): setup ~20 s, the block check 20 s, the lease 30 s plus a
# 250 ms tick, WATCH_S (default 120) for the exit, the rest of the park, and
# captures ~20 s.  PAUSE_MS must outlast all of it so the holder is still live
# when the closure lands: default 300000.
#
# Usage: tests/caw_acquire_closure.sh [H=test1] [W=test2]
# Env:   MXFS_MNT (/mnt/shared), PAUSE_MS (300000), LEASE_PARK_MS (120000),
#        WATCH_S (120), BOUND_S (10).  Evidence: tests/evidence/caw_closure/<stamp>/.
#        Exit 0 PASS, 1 FAIL, 2 INFRA, 3 VACUOUS.
#
set -u

H="${1:-test1}"
W="${2:-test2}"
MNT="${MXFS_MNT:-/mnt/shared}"
PAUSE_MS="${PAUSE_MS:-300000}"
LEASE_PARK_MS="${LEASE_PARK_MS:-120000}"
WATCH_S="${WATCH_S:-120}"
BOUND_S="${BOUND_S:-10}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
P=/sys/module/mxfs/parameters
EV="$HERE/tests/evidence/caw_closure/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
say() { echo "[$(date +%T) +$(el)s] $*"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>&1 | grep -v -E "^Warning: Permanently|Unauthorized access|authorized user"; return "${PIPESTATUS[0]}"; }
MARK="CAWCLOSE-$(date +%s)-$$"
DM="dmesg | awk '/$MARK/{f=1} f'"
F="$MNT/.cawclose_$MARK"
disarm() {
    on $W 20 "echo 0 > $P/dl_inject_hb_pause_ms" >/dev/null
    on $H 20 "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino" >/dev/null
}
trap disarm EXIT

say "H=$H W=$W mnt=$MNT pause_ms=$PAUSE_MS lease_park_ms=$LEASE_PARK_MS watch_s=$WATCH_S bound_s=$BOUND_S evidence=$EV"
for h in $H $W; do
    on $h 20 "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted; echo ft=\$(cat $P/force_transport); echo sv=\$(cat /sys/module/mxfs/srcversion)" > "$EV/pre_$h.txt"
    grep -q mounted "$EV/pre_$h.txt" || { say "INFRA: $h has no MXFS mount at $MNT"; exit 2; }
    grep -q 'ft=0' "$EV/pre_$h.txt" || { say "INFRA: $h is not on the CAW transport"; exit 2; }
done
for h in $H $W; do on $h 10 "echo $MARK > /dev/kmsg" >/dev/null; done

# 1. H writes F and holds it with the release paused
on $H 30 "dd if=/dev/urandom of='$F' bs=4096 count=8 conv=fsync status=none && stat -c %i '$F'" > "$EV/h_create.txt"
ino=$(grep -aoE '^[0-9]+$' "$EV/h_create.txt" | head -1)
[ -n "$ino" ] || { say "INFRA: H could not create $F"; exit 2; }
on $H 30 "echo $ino > $P/dbg_rel_pause_ino; echo 1 > $P/dbg_rel_pause_stage; echo $PAUSE_MS > $P/dbg_rel_pause_ms
          dd if=/dev/urandom of='$F' bs=4096 count=8 status=none && md5sum '$F' | cut -d' ' -f1" > "$EV/h_hold.txt"
md5_h=$(grep -aoE '^[0-9a-f]{32}' "$EV/h_hold.txt" | head -1)
[ -n "$md5_h" ] || { say "INFRA: H could not arm the pause and re-dirty $F"; exit 2; }
say "H holds ino=$ino (md5 $md5_h) with its release paused ${PAUSE_MS} ms"

# 2. W reads F in the background and must be parked in the acquire
on $W 15 "rm -f /tmp/cac_read.out; nohup setsid bash -c 'md5sum \"$F\" > /tmp/cac_read.out 2>&1; echo rc=\$? >> /tmp/cac_read.out' >/dev/null 2>&1 < /dev/null & echo \$!" > "$EV/w_launch.txt"
RPID=$(grep -aoE '^[0-9]+$' "$EV/w_launch.txt" | head -1)
[ -n "$RPID" ] || { say "INFRA: could not start the reader on $W"; exit 2; }
sleep 20   # P-ACQ-STUCK first prints ~15 s into a stuck acquire (caw0912_s2: el_ms=15101)
on $W 20 "echo alive=\$(test -d /proc/$RPID && echo 1 || echo 0) stuck=\$($DM | grep -a 'P-ACQ-STUCK' | grep -ac 'ino=$ino ')
          echo --- stack; for t in /proc/$RPID/task/*; do cat \$t/stack 2>/dev/null; done | head -20" > "$EV/w_preclose.txt"
alive0=$(grep -aoE 'alive=[01]' "$EV/w_preclose.txt" | cut -d= -f2)
stuck0=$(grep -aoE 'stuck=[0-9]+' "$EV/w_preclose.txt" | cut -d= -f2)
say "before the closure: reader alive=$alive0 P-ACQ-STUCK(ino=$ino)=$stuck0"
if [ "${alive0:-0}" != 1 ] || [ "${stuck0:-0}" -lt 1 ]; then
    say "RESULT VACUOUS: the reader is not parked in the CAW acquire, so a closure under it measures nothing"
    exit 3
fi

# 3. close W's lease under the waiter
on $W 20 "echo $LEASE_PARK_MS > $P/dl_inject_hb_pause_ms" >/dev/null
tpark=$(el)
say "parked $W's heartbeat for ${LEASE_PARK_MS} ms: the 30 s lease closes under the waiter"

# 4. watch
closed_s=""; exit_s=""
: > "$EV/w_watch.txt"
w=0
while [ "$w" -lt $(( 30 + WATCH_S )) ]; do
    sleep 2; w=$(( w + 2 ))
    s=$(on $W 15 "echo alive=\$(test -d /proc/$RPID && echo 1 || echo 0) closed=\$($DM | grep -ac 'P290-AUTH-CLOSED') shut=\$($DM | grep -ac 'Shutting down filesystem')" | tr -d '\r')
    echo "+$(el)s $s" >> "$EV/w_watch.txt"
    a=$(echo "$s" | grep -aoE 'alive=[0-9]+' | cut -d= -f2)
    c=$(echo "$s" | grep -aoE 'closed=[0-9]+' | cut -d= -f2)
    [ -z "$closed_s" ] && [ "${c:-0}" -ge 1 ] && { closed_s=$(el); say "the lease CLOSED"; }
    [ -z "$exit_s" ] && [ "${a:-1}" = 0 ] && { exit_s=$(el); say "the parked reader EXITED"; }
    [ -n "$closed_s" ] && [ -n "$exit_s" ] && break
done
delta=""
[ -n "$closed_s" ] && [ -n "$exit_s" ] && delta=$(( exit_s - closed_s ))
say "closed_at=+${closed_s:-never}s exit_at=+${exit_s:-never}s delta=${delta:-n/a}s (bound ${BOUND_S}s)"
on $W 20 "cat /tmp/cac_read.out 2>/dev/null | head -c 300" > "$EV/w_result.txt"
say "the reader's own result: $(tr '\n' ' ' < "$EV/w_result.txt" | cut -c1-160)"

# the rest of the park, then disarm; H must still serve its own I/O
rem=$(( LEASE_PARK_MS / 1000 - ( $(el) - tpark ) ))
[ "$rem" -gt 0 ] && { say "waiting out the remaining ${rem}s of the heartbeat park"; sleep "$rem"; }
disarm
on $H 60 "f='$MNT/.cawclose_h_$MARK'; dd if=/dev/urandom of=\$f bs=4096 count=4 conv=fsync status=none && md5sum \$f >/dev/null && echo h_io_ok; rm -f \$f" > "$EV/h_health.txt"
for h in $H $W; do on $h 30 "$DM" > "$EV/dmesg_$h.log"; done
grep -aE 'P290-AUTH-CLOSED|P290-AUTH-WITHDRAW|P292-ACQ-AUTH-CLOSED|P131-SELF-FENCE|Shutting down filesystem|disk lock acquisition timed out' "$EV/dmesg_$W.log" | cut -c1-200 | head -8

FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
[ -n "$closed_s" ] || fail "the lease never closed (P290-AUTH-CLOSED) inside the watch"
[ -n "$exit_s" ] || fail "the parked reader never left inside the watch"
[ -n "$delta" ] && [ "$delta" -gt "$BOUND_S" ] && fail "closure to exit took ${delta}s (bound ${BOUND_S}s)"
for h in $H $W; do
    s=$(grep -acE 'BUG:|Oops|WARNING: CPU' "$EV/dmesg_$h.log")
    [ "$s" = 0 ] || fail "$s BUG/Oops/WARNING line(s) on $h"
done
grep -q h_io_ok "$EV/h_health.txt" || fail "$H could not write and read its own file afterwards"
[ $FAILS = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
