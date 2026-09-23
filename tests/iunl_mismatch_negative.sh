#!/bin/bash
# iunl_mismatch_negative.sh — NEGATIVE-MISMATCH ARM for the iunlink item
# (ledger D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN closure item "negative-
# mismatch test", sess396 design-consult ruling; injector landed sess402:
# iunl_mismatch_inject in xfs/xfs_iunlink_item.c).
#
# Question answered: did the sess396 INSERT-mode iunlink item blind the strict
# equality check for NON-INSERT items?  The arm perturbs only the comparand the
# strict check sees (the buffer is untouched) for exactly ONE non-INSERT item on
# ONE node and asserts the check fires: P53-IUNLINK-MISMATCH must be logged, and
# the follow-up must be either the store-proven repair (P-IUNL-PRECOMMIT-
# FOSSILFIX, the expected outcome: the store's committed value IS the captured
# old_agino) or the -EFSCORRUPTED shutdown.  SILENCE (injection consumed, no
# P53) is the FAIL.
#
# How a non-INSERT item is produced: a process opens NFDS O_TMPFILE fds in a
# private dir — every one is nlink=0 on the AGI unlinked lists, NFDS=200 across
# 64 buckets gives depth 3-4 — then closes them; each close runs inactivate ->
# ifree -> xfs_iunlink_remove, whose backref update of the predecessor (or the
# head's own NULL-out when it has a successor) is a non-INSERT item.
#
# the budget rule (derived): open 200 tmpfiles ~0.2 s + close 200 ~1-2 s (5-8 ms each,
# D-400 numbers) -> node wall budget 20 s; whole script <= 90 s.  the unkillable-wedge rule: every
# remote call bounded.  the source-tree rule: lives in tests/.  Leaves the knob at 0.  If the
# outcome is a shutdown the node's mount is dead: the script reports it, tries a
# bounded umount there and the next run.sh/prep re-forms the cluster
# (MXFS_FORCE_PREP=1).
#
# Usage: tests/iunl_mismatch_negative.sh <label> [node=test5] [nfds=200]
# Env:   IMN_OUT (evidence dir — put it under tests/evidence/, NOT the scratchpad)

LABEL=${1:?label}; NODE=${2:-test5}; NFDS=${3:-200}
cd "$(dirname "$0")/.." || exit 2
OUT=${IMN_OUT:-$(mktemp -d)}; mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
MARK="mxfs-IMN-$LABEL-$(date -u +%s)"
echo "=== iunl_mismatch_negative label=$LABEL node=$NODE nfds=$NFDS out=$OUT $(date -u +%FT%TZ) ==="

PY='import os,sys,time
d=sys.argv[1]; n=int(sys.argv[2]); mark=sys.argv[3]
os.makedirs(d, exist_ok=True)
fds=[]; t0=time.time(); errs=0
for i in range(n):
    try: fds.append(os.open(d, os.O_TMPFILE|os.O_RDWR, 0o644))
    except OSError as e: errs+=1; print("ERR open", e, file=sys.stderr, flush=True)
for fd in fds:
    try: os.write(fd, b"n"*512)
    except OSError as e: errs+=1
topen=time.time()-t0
# arm exactly one injection, then a kmsg marker, then close everything
open("/sys/module/mxfs/parameters/iunl_mismatch_inject","w").write("1\n")
open("/dev/kmsg","w").write(mark+" ARMED opened=%d\n" % len(fds))
t1=time.time()
for fd in fds:
    try: os.close(fd)
    except OSError as e: errs+=1; print("ERR close", e, file=sys.stderr, flush=True)
tclose=time.time()-t1
left=open("/sys/module/mxfs/parameters/iunl_mismatch_inject").read().strip()
open("/sys/module/mxfs/parameters/iunl_mismatch_inject","w").write("0\n")
open("/dev/kmsg","w").write(mark+" DONE\n")
print("opened=%d errs=%d topen=%.2f tclose=%.2f inject_left=%s" % (len(fds), errs, topen, tclose, left), flush=True)'
PYB=$(printf '%s' "$PY" | base64 -w0)

pre=$(timeout 30 $SSH "$NODE" "mountpoint -q $MNT && echo MOUNTED || echo NOTMOUNTED; cat /sys/module/mxfs/srcversion; echo inject=\$(cat /sys/module/mxfs/parameters/iunl_mismatch_inject 2>/dev/null || echo ABSENT)" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' | tr '\n' ' ')
echo "pre: $pre"
case "$pre" in *MOUNTED*) ;; *) echo "FAIL precondition: $NODE not mounted"; exit 2;; esac
case "$pre" in *inject=ABSENT*) echo "FAIL precondition: running build has no iunl_mismatch_inject knob"; exit 2;; esac

S=$SECONDS
res=$(timeout 40 $SSH "$NODE" "echo $PYB | base64 -d > /root/imn_churn.py; python3 /root/imn_churn.py $MNT/imn_$LABEL/$NODE $NFDS $MARK 2>&1 | tail -5" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you')
rc=$?
echo "churn rc=$rc wall=$((SECONDS-S))s :: $res"
echo "$res" > "$OUT/churn.txt"

# Harvest the kernel log from the ARMED marker on (one dmesg read).
timeout 40 $SSH "$NODE" "dmesg > /root/klog_imn.txt; awk '/$MARK ARMED/{f=1} f' /root/klog_imn.txt" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' > "$OUT/klog_after_mark.txt"
inj=$(grep -c 'P-IUNL-MISMATCH-INJECT' "$OUT/klog_after_mark.txt")
p53=$(grep -c 'P53-IUNLINK-MISMATCH' "$OUT/klog_after_mark.txt")
ffx=$(grep -c 'P-IUNL-PRECOMMIT-FOSSILFIX' "$OUT/klog_after_mark.txt")
idem=$(grep -c 'P53-IUNLINK-IDEMPOTENT' "$OUT/klog_after_mark.txt")
sd=$(grep -c 'Shutting down filesystem' "$OUT/klog_after_mark.txt")
corr=$(grep -c 'Corruption of in-memory' "$OUT/klog_after_mark.txt")
insf=$(grep -c 'P-IUNL-INSFAIL' "$OUT/klog_after_mark.txt")
echo "sweep: inject=$inj p53=$p53 fossilfix=$ffx idempotent=$idem shutdown=$sd corr=$corr insfail=$insf"
grep -m3 -E 'P-IUNL-MISMATCH-INJECT|P53-IUNLINK-MISMATCH|P-IUNL-PRECOMMIT-FOSSILFIX|Shutting down|Corruption of in-memory' "$OUT/klog_after_mark.txt" | cut -c1-330
inj_ino=$(grep -m1 -oE 'P-IUNL-MISMATCH-INJECT ino=0x[0-9a-f]+' "$OUT/klog_after_mark.txt" | grep -oE '0x[0-9a-f]+$')
p53_ino=$(grep -m1 -oE 'P53-IUNLINK-MISMATCH ino=0x[0-9a-f]+' "$OUT/klog_after_mark.txt" | grep -oE '0x[0-9a-f]+$')
echo "inject_ino=$inj_ino p53_ino=$p53_ino"

# Fleet-wide side effects (one bounded read per node, parallel).
N=${IMN_NODES:-32}
for i in $(seq 1 "$N"); do
    ( timeout 30 $SSH "test$i" "echo test$i mounted=\$(mountpoint -q $MNT && echo 1 || echo 0) sd=\$(dmesg | grep -c 'Shutting down filesystem') corr=\$(dmesg | grep -c 'Corruption of in-memory') p53=\$(dmesg | grep -c 'P53-IUNLINK-MISMATCH')" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' > "$OUT/fleet_test$i.txt" ) &
done
wait
cat "$OUT"/fleet_test*.txt | sort -V > "$OUT/fleet.txt"
echo "fleet: $(grep -c 'mounted=1' "$OUT/fleet.txt")/$N mounted; nodes with sd>0: $(grep -v 'sd=0' "$OUT/fleet.txt" | awk '{print $1}' | tr '\n' ' ')"

verdict=PASS; why=""
[ "$inj" -eq 1 ] || { verdict=FAIL; why="$why inject_count=$inj(want 1);"; }
[ "$p53" -ge 1 ] || { verdict=FAIL; why="$why P53 silent;"; }
[ -n "$inj_ino" ] && [ "$inj_ino" != "$p53_ino" ] && { verdict=FAIL; why="$why P53 ino $p53_ino != injected $inj_ino;"; }
if [ "$ffx" -lt 1 ] && [ "$sd" -lt 1 ]; then verdict=FAIL; why="$why no FOSSILFIX and no shutdown after P53;"; fi
[ "$insf" -eq 0 ] || { verdict=FAIL; why="$why P-IUNL-INSFAIL=$insf;"; }
outcome=repair; [ "$sd" -ge 1 ] && outcome=shutdown
echo "=== VERDICT $verdict outcome=$outcome inject=$inj p53=$p53 fossilfix=$ffx shutdown=$sd corr=$corr $why ==="
if [ "$sd" -ge 1 ]; then
    echo "node $NODE shut down as designed by the arm — bounded umount; next prep must MXFS_FORCE_PREP=1"
    timeout 60 $SSH "$NODE" "timeout 40 umount $MNT; echo umount_rc=\$?" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you'
fi
[ "$verdict" = PASS ]
