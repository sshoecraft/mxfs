#!/bin/sh
# d512_incarn_gate_verify.sh — cycle-1 verification arm for
#   D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 (sess414)
#
# Exercises the sess413 design-consult ruling's poison-time revocation +
# gate-set components against a debug-forced poison:
#   - dbg_incarn_poison_ino (self-clearing module param) poisons the
#     nominated inode at its next open, exactly as a protective reload
#     does on a genuine cross-incarnation detection
#   - tests/d512_ref_matrix.c (shipped to the node, run there) holds the
#     long-lived-ref set across the poison and asserts every old ref
#     fails safely; see its header for the assertion list
#
# PASS iff the matrix exits 0 AND node dmesg shows P34H-DBG-POISON +
# P34H-INCARN-REVOKED for the inode AND no BUG/Oops/lockdep splat.
#
# the budget rule (derived): compile 2s + ship 2s + phase1 2s + trigger 2s +
# revocation wait <=15s (matrix-internal poll) + asserts 2s + dmesg 5s
# => ~30s. Caller bound 90s.
#
# Usage: tests/d512_incarn_gate_verify.sh <label> [node]
# Env: D512_OUT (evidence dir), MXFS_MNT (default /mnt/shared)
set -u
LABEL=${1:?label}; NODE=${2:-test1}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D512_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d512}
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
echo "=== d512_incarn_gate_verify label=$LABEL node=$NODE out=$OUT $(date -u +%FT%TZ) ==="

cc -O2 -Wall -o "$OUT/d512_ref_matrix" tests/d512_ref_matrix.c || {
    echo "VERDICT FAIL: helper compile failed"; exit 2; }

MARK="D512-$LABEL-$$-$(date -u +%s)"
timeout 20 $SSH "$NODE" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

timeout 20 $SSH "$NODE" "cat > /root/d512_ref_matrix && chmod +x /root/d512_ref_matrix" \
    < "$OUT/d512_ref_matrix" 2>/dev/null || {
    echo "VERDICT FAIL: helper ship failed"; exit 2; }

# run the matrix; it prints READY ino=<n> then polls for the trigger file.
# RAW capture (no filt in the pipeline): a block-buffered grep held READY
# back until process exit, so the driver's poll never saw it (first run,
# 20260824T043753Z).  The banner lines are filtered at read time instead.
DATF="$MNT/d512_${LABEL}_$$.dat"
( timeout 75 $SSH "$NODE" \
    "rm -f /tmp/d512.go; /root/d512_ref_matrix '$DATF' /tmp/d512.go; echo MATRIX_RC=\$?" \
    > "$OUT/matrix.txt" 2>/dev/null ) &
MPID=$!

ino=""
n=0
while [ $n -lt 30 ]; do
    ino=$(grep -a '^READY ino=' "$OUT/matrix.txt" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$ino" ] && break
    sleep 1; n=$((n+1))
done
if [ -z "$ino" ]; then
    echo "VERDICT FAIL: matrix never reached READY (see $OUT/matrix.txt)"
    kill "$MPID" 2>/dev/null; exit 1
fi
echo "ready ino=$ino — arming knob + trigger"

timeout 20 $SSH "$NODE" \
    "echo $ino > /sys/module/mxfs/parameters/dbg_incarn_poison_ino && touch /tmp/d512.go" \
    >/dev/null 2>&1 || {
    echo "VERDICT FAIL: knob arm failed"; kill "$MPID" 2>/dev/null; exit 1; }

wait "$MPID"
mrc=$(grep -a 'MATRIX_RC=' "$OUT/matrix.txt" | tail -1 | cut -d= -f2)
fails=$(grep -ac 'ASSERT .* FAIL' "$OUT/matrix.txt")
passes=$(grep -ac 'ASSERT .* PASS' "$OUT/matrix.txt")
sed -n '/ASSERT\|MATRIX/p' "$OUT/matrix.txt"

timeout 25 $SSH "$NODE" \
    "dmesg | sed -n \"/$MARK/,\\\$p\"" 2>/dev/null | filt > "$OUT/node_dmesg.txt"
poisoned=$(grep -ac "P34H-DBG-POISON ino=$ino" "$OUT/node_dmesg.txt")
revoked=$(grep -ac "P34H-INCARN-REVOKED ino=$ino" "$OUT/node_dmesg.txt")
splat=$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep|possible circular' "$OUT/node_dmesg.txt")
echo "dmesg: dbg_poison=$poisoned revoked=$revoked splats=$splat"

# scratch file cleanup (best effort; the fresh incarnation is mountable)
timeout 20 $SSH "$NODE" "rm -f '$DATF' /tmp/d512.go /root/d512_ref_matrix" >/dev/null 2>&1

if [ "${mrc:-2}" = 0 ] && [ "$fails" = 0 ] && [ "$passes" -ge 6 ] && \
   [ "$poisoned" -ge 1 ] && [ "$revoked" -ge 1 ] && [ "$splat" = 0 ]; then
    echo "VERDICT PASS: matrix rc=0 asserts=$passes/0fail poison+revoke observed, no splats"
    exit 0
fi
echo "VERDICT FAIL: mrc=${mrc:-none} fails=$fails passes=$passes poisoned=$poisoned revoked=$revoked splat=$splat"
exit 1
