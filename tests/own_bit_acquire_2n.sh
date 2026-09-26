#!/bin/bash
#
# own_bit_acquire_2n.sh — what does a CAW acquire do when the slot already
# carries THIS node's own holder bit while the node holds no in-core tenure?
#
# D-AG-RETAINED-OWN-BIT-ADOPTION-MOUNT-WINDOW-ONLY-NO-ACQUIRE-RECONCILIATION-0528
# claims that outside the mount adoption window nothing at acquire time
# reconciles such a bit: the node would treat its own bit as a peer's hold,
# retry with -EAGAIN, BAST itself and depend on the rx-side strand repair
# (P5N ... repair=1, gated on a 3 s pending floor).  The CAW lock path read
# today has an own-bit arm (dlm/dlm_caw.c: our_mode == requested) that either
# reaffirms a live tenure or, for an attested AG caller whose published epoch
# is 0, mints a fresh epoch through a real CAS (P294-READOPT-MINT).  This lap
# decides between the two by driving the state and reading what happens.
#
# THE STATE is made with the existing one-shot mxfs.ag_strand_inject=-1 on
# test1: the next AG test1 releases skips its wire unlock, leaving test1's bit
# on the platter with the in-core tenure torn down (P200-STRAND-INJECT ag=X).
# THE LOAD keeps both nodes creating files in one shared directory, and test2
# also removes the oldest of test1's files on every op.  Each node allocates
# inodes in its own AG, so creates alone never make test1 release an AG (the
# first lap of this harness: no P200 at all).  Freeing an inode needs ITS AG,
# so test2's removes BAST test1 off its own AG (the release that strands it),
# and test1's next create wants that AG again within milliseconds — normally
# long before the 3 s floor lets the rx path call the strand a strand.  Every
# op's wall is recorded per node.
#
# VERDICT, from test1's kernel log after its P200 line, for AG X:
#   RECONCILED-AT-ACQUIRE  P294-READOPT-MINT ag=X precedes any P5N ... ag=X
#                          repair line: the acquire itself adopted the bit.
#   REPAIR-ONLY            the first reconciliation of X is the rx repair
#                          (P5N repair=1): the gap the record describes.
#   NOT-EXERCISED          no P200, or test1 never acquired X afterwards.
# PASS needs RECONCILED-AT-ACQUIRE plus: both nodes' loops completed every op,
# no op on either node slower than OPMS_CEIL, both unmount rc=0, chk_mxfs
# clean, zero BUG/Oops/shutdown.  OPMS_CEIL (default 3000) sits at the rx
# repair floor: an op that waited out the floor was served by the repair.
#
# Budget (derived): prep 57-71 s measured (bound 180); load DUR 20 s + ssh
# setup ~10 s -> 45 s; captures 30 s; two unmounts ~15 s in parallel -> 60;
# chk_mxfs 240 (the unmount lap's bound).  Caller bound 560 s.
#
# Usage: MXFS_DEV=<by-id path> tests/own_bit_acquire_2n.sh LABEL
#   Env: DUR (20), OPMS_CEIL (3000).  Evidence under
#   tests/evidence/own_bit_acquire/<stamp>_<LABEL>/.  Exit 0 PASS, 1 FAIL,
#   2 INFRA, 3 NOT-EXERCISED.
#
set -u

LABEL="${1:?usage: own_bit_acquire_2n.sh LABEL}"
DUR="${DUR:-20}"
OPMS_CEIL="${OPMS_CEIL:-3000}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 2
SSH="$HERE/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
A=test1; B=test2
EV="$HERE/tests/evidence/own_bit_acquire/$(date +%Y%m%dT%H%M%S)_$LABEL"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
say() { echo "[$(date +%T) +$(el)s] $*"; }
rsh() { local n=$1; shift; timeout "$1" "$SSH" "$n" "$2" </dev/null 2>/dev/null | grep -avE '^Warning|Unauthorized|authorized user'; }

say "label=$LABEL dur=$DUR opms_ceil=$OPMS_CEIL dev=${MXFS_DEV:-run.sh default} evidence=$EV"
MXFS_FORCE_PREP=1 timeout 180 ./run.sh 2 cawd prep_cluster > "$EV/prep.log" 2>&1
rc=$?
say "prep rc=$rc ($(grep -a 'prep_cluster OK' "$EV/prep.log" | tail -1 | cut -c1-120))"
[ $rc = 0 ] || { say "RESULT INFRA: prep failed"; exit 2; }

D="$MNT/obit_$$"
rsh $A 20 "mkdir -p $D && sync && stat -c DIRINO=%i $D" > "$EV/setup.txt"
grep -q DIRINO= "$EV/setup.txt" || { say "RESULT INFRA: could not create $D"; exit 2; }
say "shared dir $D $(cat "$EV/setup.txt")"
rsh $A 15 "echo -1 > /sys/module/mxfs/parameters/ag_strand_inject; cat /sys/module/mxfs/parameters/ag_strand_inject" > "$EV/arm.txt"
[ "$(tr -dc '0-9-' < "$EV/arm.txt")" = "-1" ] || { say "RESULT INFRA: could not arm ag_strand_inject on $A ($(cat "$EV/arm.txt"))"; exit 2; }
say "armed ag_strand_inject=-1 on $A"
# P294-READOPT-MINT is a debug-level line: with dynamic debug off for mxfs the
# acquire's mint is invisible and the verdict would read REPAIR-ONLY or
# NOT-EXERCISED however the acquire behaved.  Turn it on and prove it took.
rsh $A 15 "echo 'module mxfs +p' > /sys/kernel/debug/dynamic_debug/control; grep -c 'mxfs.*=p' /sys/kernel/debug/dynamic_debug/control" > "$EV/dyndbg.txt"
[ "$(tr -dc '0-9' < "$EV/dyndbg.txt")" -gt 0 ] 2>/dev/null || { say "RESULT INFRA: could not enable mxfs debug lines on $A ($(cat "$EV/dyndbg.txt"))"; exit 2; }
say "mxfs debug lines on $A: $(cat "$EV/dyndbg.txt") sites enabled"

for n in $A $B; do
    ( rsh $n $(( DUR + 40 )) "cd $D || exit 1; end=\$(( \$(date +%s) + $DUR )); i=0; mx=0; bad=0
        while [ \$(date +%s) -lt \$end ]; do
          s=\$(date +%s%N); : > ${n}_\$i || bad=\$((bad+1))
          if [ $n = $B ]; then v=\$(ls ${A}_* 2>/dev/null | head -1); [ -n \"\$v\" ] && { rm -f \"\$v\" || bad=\$((bad+1)); }; fi
          e=\$(( (\$(date +%s%N) - s) / 1000000 ))
          [ \$e -gt \$mx ] && mx=\$e; [ \$e -gt $OPMS_CEIL ] && echo SLOW op=\$i ms=\$e at=\$(date +%T.%N)
          i=\$((i+1)); sleep 0.02
        done; echo OPS=\$i BAD=\$bad MAXMS=\$mx" > "$EV/load_$n.txt" ) &
    PIDS="${PIDS:-} $!"
done
wait $PIDS
for n in $A $B; do say "$n load: $(tr '\n' ' ' < "$EV/load_$n.txt" | cut -c1-300)"; done
rsh $A 15 "echo 0 > /sys/module/mxfs/parameters/ag_strand_inject" >/dev/null

for n in $A $B; do
    ( rsh $n 60 "T=\$(date +%s%N); umount $MNT 2>&1; echo RC=\$?; echo UMOUNT_MS=\$(( (\$(date +%s%N) - T) / 1000000 ))" > "$EV/umount_$n.txt" ) &
    UP="${UP:-} $!"
done
wait $UP
for n in $A $B; do
    rsh $n 60 "journalctl -k --since=@$(( t0 - 5 )) --no-pager -o short-monotonic" | gzip > "$EV/kernlog_$n.gz"
done
CHKDEV=${MXFS_DEV:-$(python3 -c 'import json; print(json.load(open(".cluster_marker.json"))["dev"])')}
rsh $A 240 "/src/mxfs/tools/chk_mxfs $CHKDEV >/dev/null 2>&1; echo CHK_RC=\$?" | grep -a CHK_RC > "$EV/chk.txt"

FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
for n in $A $B; do
    l=$(grep -a '^OPS=' "$EV/load_$n.txt")
    [ -n "$l" ] || { fail "$n load produced no summary"; continue; }
    [ "$(echo "$l" | grep -ao 'BAD=[0-9]*' | cut -d= -f2)" = 0 ] || fail "$n had failed creates ($l)"
    [ "$(echo "$l" | grep -ao 'MAXMS=[0-9]*' | cut -d= -f2)" -le "$OPMS_CEIL" ] || fail "$n op slower than ${OPMS_CEIL} ms ($l)"
    grep -q '^RC=0' "$EV/umount_$n.txt" || fail "$n umount: $(tr '\n' ' ' < "$EV/umount_$n.txt")"
    k=$(zcat "$EV/kernlog_$n.gz" | grep -acE 'BUG:|Oops|Shutting down filesystem')
    [ "$k" = 0 ] || fail "$n logged $k BUG/Oops/shutdown lines"
done
grep -q 'CHK_RC=0' "$EV/chk.txt" || fail "chk_mxfs: $(cat "$EV/chk.txt")"

zcat "$EV/kernlog_$A.gz" > "$EV/kernlog_$A.txt"
p200=$(grep -an 'P200-STRAND-INJECT' "$EV/kernlog_$A.txt" | head -1)
if [ -z "$p200" ]; then
    say "RESULT NOT-EXERCISED: no P200-STRAND-INJECT on $A — no release ran, so no strand was made"
    [ $FAILS = 0 ] && exit 3 || exit 1
fi
ln=${p200%%:*}
X=$(echo "$p200" | grep -ao 'ag=[0-9]*' | head -1 | cut -d= -f2)
say "strand: $(echo "$p200" | cut -d: -f2- | cut -c1-160)"
tail -n +"$ln" "$EV/kernlog_$A.txt" | grep -aE "(P294-READOPT-MINT|P294-REAFFIRM|P5N-AG-ORPHAN-NAK|P5G-AGLOCK|P275-AG-DEMOTE-STUCK|P12-AGBAST-RX).* ag=$X( |$)" > "$EV/after_strand_$A.txt"
say "after the strand on $A, ag=$X: $(wc -l < "$EV/after_strand_$A.txt") lines; first five:"
head -5 "$EV/after_strand_$A.txt" | cut -c1-220
first=$(grep -aE 'P294-READOPT-MINT|P5N-AG-ORPHAN-NAK.*repair=1' "$EV/after_strand_$A.txt" | head -1)
case "$first" in
    *P294-READOPT-MINT*)
        if grep -aq 'P5N-AG-ORPHAN-NAK.*repair=1' "$EV/after_strand_$A.txt" &&
           [ "$(grep -anE 'P294-READOPT-MINT|P5N-AG-ORPHAN-NAK.*repair=1' "$EV/after_strand_$A.txt" | head -1 | grep -c P294)" = 1 ]; then
            say "note: a P5N repair=1 line also appears, after the acquire's mint"
        fi
        say "VERDICT RECONCILED-AT-ACQUIRE: the first reconciliation of ag=$X is the acquire's own-bit mint" ;;
    *P5N*)
        fail "VERDICT REPAIR-ONLY: the first reconciliation of ag=$X was the rx strand repair, not the acquire" ;;
    *)
        say "RESULT NOT-EXERCISED: $A never reconciled ag=$X after the strand"
        [ $FAILS = 0 ] && exit 3 || exit 1 ;;
esac
[ $FAILS = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
