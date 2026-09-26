#!/bin/bash
#
# fua_deadline_lap.sh — does an expired per-task I/O budget end a FUA read?
#
# D-THE-PER-TASK-IO-DEADLINE-IS-UNSIGNED-AND-CAN-NEVER-FIRE: the helper that
# reports "budget exhausted" returned a huge positive number instead, so the
# FUA-read retry loop handed msecs_to_jiffies ~49.7 days at exactly the moment
# it should have given up.  The only budgeted FUA read is the CAW cached-grant
# ownership verify, so this runs on a CAW cluster.
#
# On W, with the cluster already prepped (run.sh <N> caw|cawd|cawp) and mounted
# at MNT on H and W:
#   1. dlm_verify_deadline_ms=DEADLINE_MS (default 20) and
#      dbg_fua_read_fail_budgeted=INJECT (default 40): each budgeted FUA-read
#      attempt fails as a short transfer, so the loop retries with its 5/10/15
#      ms backoff and the budget runs out inside it
#   2. a workload that makes W verify cached grants: H creates FILES files,
#      then W reads and stats them for WORK_S seconds while H rewrites them
#   3. both knobs restored (deadline 1000, injector 0)
# Asserts, from W's kernel log after a marker:
#   a. P302-INJECT fired (else the workload never drove a budgeted read and
#      the lap measured nothing: INCONCLUSIVE, exit 2)
#   b. P302-FUA-READ-DEADLINE fired: the expired budget ended the read
#   c. no P-FUA-READ-RETRY carries budget_ms=4294967295, and every budgeted
#      one is within DEADLINE_MS
#   d. no P-FUA-READ-ERR with tries=21 (the read ran out its retries instead)
#   e. P303-VERIFY-BREAKER fired (the verify recorded no sample and backed off)
#   f. both mounts healthy afterwards: still mounted, a write on W reads back
#      on H, no shutdown or corruption line on either node
#
# Budget: setup ~5 s + WORK_S (30) + captures ~10 s; each remote step has its
# own timeout derived from that.
#
# Usage: tests/fua_deadline_lap.sh [H=test1] [W=test2]
# Env:   MXFS_MNT (default /mnt/shared), DEADLINE_MS, INJECT, FILES (20),
#        WORK_S (30).  Evidence: tests/evidence/fua_deadline/<stamp>/.
#        Exit 0 PASS, 1 FAIL, 2 INCONCLUSIVE/INFRA.
#
set -u

H="${1:-test1}"
W="${2:-test2}"
MNT="${MXFS_MNT:-/mnt/shared}"
DEADLINE_MS="${DEADLINE_MS:-20}"
INJECT="${INJECT:-40}"
FILES="${FILES:-20}"
WORK_S="${WORK_S:-30}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/fua_deadline/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" </dev/null 2>&1 | grep -v -E "^Warning: Permanently|Unauthorized access|authorized user"; return "${PIPESTATUS[0]}"; }
P=/sys/module/mxfs/parameters
MARK="FUADL-$(date +%s)-$$"
FD="$MNT/fdl_$MARK"          # a directory per lap: a leftover from the last one is not counted
disarm() { on $W 20 "echo 0 > $P/dbg_fua_read_fail_budgeted; echo 1000 > $P/dlm_verify_deadline_ms" >/dev/null; }
trap disarm EXIT

say "H=$H W=$W mnt=$MNT deadline_ms=$DEADLINE_MS inject=$INJECT files=$FILES work_s=$WORK_S evidence=$EV"
for h in $H $W; do
    on $h 20 "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted; cat $P/force_transport" > "$EV/pre_$h.txt"
    grep -q mounted "$EV/pre_$h.txt" || { say "INFRA: $h has no MXFS mount at $MNT"; exit 2; }
    [ "$(tail -1 "$EV/pre_$h.txt")" = 0 ] || { say "INFRA: $h is not on the CAW transport (force_transport=$(tail -1 "$EV/pre_$h.txt"))"; exit 2; }
done

on $H 60 "mkdir -p $FD && for i in \$(seq 1 $FILES); do dd if=/dev/urandom of=$FD/f\$i bs=4k count=4 conv=fsync status=none; done; ls $FD | wc -l" > "$EV/create.txt"
[ "$(tail -1 "$EV/create.txt")" = "$FILES" ] || { say "INFRA: creating the files on $H (see create.txt)"; exit 2; }

for h in $H $W; do on $h 10 "echo $MARK > /dev/kmsg" >/dev/null; done
on $W 10 "echo $DEADLINE_MS > $P/dlm_verify_deadline_ms; echo $INJECT > $P/dbg_fua_read_fail_budgeted; echo armed=\$(cat $P/dbg_fua_read_fail_budgeted) deadline=\$(cat $P/dlm_verify_deadline_ms)" | tee "$EV/arm.txt"
t0=$(date +%s)
on $H $((WORK_S + 20)) "end=\$(( \$(date +%s) + $WORK_S )); n=0; while [ \$(date +%s) -lt \$end ]; do i=\$(( n % $FILES + 1 )); dd if=/dev/urandom of=$FD/f\$i bs=4k count=1 conv=notrunc,fsync status=none; n=\$((n+1)); sleep 0.2; done; echo h_writes=\$n" > "$EV/work_$H.txt" &
HW=$!
on $W $((WORK_S + 20)) "end=\$(( \$(date +%s) + $WORK_S )); n=0; while [ \$(date +%s) -lt \$end ]; do for f in $FD/f*; do stat -c %s \$f >/dev/null; cat \$f >/dev/null; done; n=\$((n+1)); sleep 0.1; done; echo w_passes=\$n" > "$EV/work_$W.txt"
wrc=$?
wait $HW
hrc=$?
say "workload $(( $(date +%s) - t0 )) s: $(cat "$EV/work_$H.txt" "$EV/work_$W.txt" | tr '\n' ' ') rc_h=$hrc rc_w=$wrc"
on $W 10 "echo left=\$(cat $P/dbg_fua_read_fail_budgeted)" | tee "$EV/injector_left.txt"
disarm

# health: still mounted, a write on W is read back on H
on $W 30 "echo $MARK > $FD/health && sync && cat $FD/health" > "$EV/health_$W.txt"
on $H 30 "cat $FD/health" > "$EV/health_$H.txt"
for h in $H $W; do
    on $h 30 "dmesg | awk '/$MARK/{f=1} f'" > "$EV/dmesg_$h.log"
    on $h 10 "grep -c ' $MNT mxfs ' /proc/mounts" > "$EV/mounted_$h.txt"
done

D="$EV/dmesg_$W.log"
inj=$(grep -c 'P302-INJECT' "$D")
dl=$(grep -c 'P302-FUA-READ-DEADLINE' "$D")
retries=$(grep -c 'P-FUA-READ-RETRY' "$D")
huge=$(grep -c 'budget_ms=4294967295' "$D")
over=$(grep -o 'P-FUA-READ-RETRY.*budget_ms=[0-9]*' "$D" | sed 's/.*budget_ms=//' | awk -v d="$DEADLINE_MS" '$1 > d' | wc -l)
err21=$(grep -c 'P-FUA-READ-ERR.*tries=21' "$D")
brk=$(grep -c 'P303-VERIFY-BREAKER' "$D")
bad=$(cat "$EV/dmesg_$H.log" "$D" | grep -ciE 'shutting down filesystem|Corruption of in-memory|xfs_do_force_shutdown|BUG:|Oops|WARNING: CPU')
say "P302-INJECT=$inj P302-FUA-READ-DEADLINE=$dl P-FUA-READ-RETRY=$retries budget_huge=$huge budget_over_deadline=$over P-FUA-READ-ERR_tries21=$err21 P303-VERIFY-BREAKER=$brk shutdown_or_splat=$bad"
grep -m3 'P-FUA-READ-RETRY' "$D" | cut -c1-200
grep -m2 'P302-FUA-READ-DEADLINE' "$D" | cut -c1-200

[ "$inj" -gt 0 ] || { say "RESULT INCONCLUSIVE: no budgeted FUA read was driven (P302-INJECT=0)"; exit 2; }
FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
[ "$dl" -gt 0 ] || fail "the expired budget never ended a read (no P302-FUA-READ-DEADLINE)"
[ "$huge" = 0 ] || fail "$huge retry line(s) carry budget_ms=4294967295"
[ "$over" = 0 ] || fail "$over budgeted retry line(s) report more than the ${DEADLINE_MS} ms deadline"
[ "$err21" = 0 ] || fail "$err21 read(s) ran out all 21 tries instead of the deadline"
[ "$brk" -gt 0 ] || fail "the verify breaker never opened (no P303-VERIFY-BREAKER)"
[ "$bad" = 0 ] || fail "$bad shutdown/corruption/splat line(s) after the marker"
for h in $H $W; do [ "$(tail -1 "$EV/mounted_$h.txt")" = 1 ] || fail "$h lost its mount"; done
grep -q "$MARK" "$EV/health_$H.txt" || fail "a write on $W did not read back on $H"
[ $FAILS = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
