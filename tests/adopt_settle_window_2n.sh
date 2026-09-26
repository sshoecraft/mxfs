#!/bin/bash
#
# adopt_settle_window_2n.sh — can the own-slot settle purge strip a bit that a
# direct-handoff adopt has validated but not yet recorded in ctx->held?
#
# D-TRACK-PUBLISH-ORDERING.  The direct-handoff adopt in mxfs_dlm_caw_lock
# validates the slot image the PEER's release CAS wrote (lreq_clr_still_good)
# and only afterwards calls track_held().  The own-slot settle
# (mxfs_v5_dlm_settle_own_slot -> purge SKIP_TRACKED over this node's bit)
# decided "leftover" from ctx->held alone, so a settle landing in that gap met
# a set, untracked bit of ours and cleared it: the adopter then held a grant
# with no bit on the platter.  The settle now opens a clear window per slot and
# leaves any resource with a live local attempt or tenure in place
# (P226-SETTLE-LIVE-SKIP).
#
# THE INSTRUMENT is mxfs.caw_inject_adopt_settle (one-shot): the next direct-
# handoff adopt runs the whole own-slot settle purge itself, inside that gap,
# then re-reads the slot and prints P250-INJECT-ADOPT-SETTLE ... slot=X
# own_bit_after=0|1.  A P226-SETTLE-LIVE-SKIP for slot X is printed only after
# the slot has passed the settle's leftover test (own bit set, not tracked), so
# it is the direct evidence that the pre-fix settle would have cleared it.
#
# THE LOAD keeps both nodes creating files in one shared directory, so the
# directory inode and its AG pass back and forth by direct handoff.  A loop on
# test1 re-arms the knob every REARM seconds while the load runs.
#
# PASS needs: at least one P250-INJECT-ADOPT-SETTLE on test1; EVERY one with
# own_bit_after=1 and a P226-SETTLE-LIVE-SKIP for the same slot; no P231
# incomplete purge; both loads complete with zero failed creates; both
# unmounts rc=0; chk_mxfs clean; zero BUG/Oops/shutdown on either node.
#
# Budget (derived): prep 57-71 s measured (bound 180); load DUR 30 s + ssh
# setup ~10 s -> 80 s (each injected settle scans the 65536-slot table in
# well under 1 s); captures 30 s; two unmounts in parallel 60 s; chk_mxfs
# 240 s.  Caller bound 600 s.
#
# Usage: MXFS_DEV=<by-id path> tests/adopt_settle_window_2n.sh LABEL
#   Env: DUR (30), REARM (2).  Evidence under
#   tests/evidence/adopt_settle/<stamp>_<LABEL>/.  Exit 0 PASS, 1 FAIL,
#   2 INFRA, 3 NOT-EXERCISED.
#
set -u

LABEL="${1:?usage: adopt_settle_window_2n.sh LABEL}"
DUR="${DUR:-30}"
REARM="${REARM:-2}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 2
SSH="$HERE/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
A=test1; B=test2
EV="$HERE/tests/evidence/adopt_settle/$(date +%Y%m%dT%H%M%S)_$LABEL"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
say() { echo "[$(date +%T) +$(el)s] $*"; }
rsh() { local n=$1; shift; timeout "$1" "$SSH" "$n" "$2" </dev/null 2>/dev/null | grep -avE '^Warning|Unauthorized|authorized user'; }
KNOB=/sys/module/mxfs/parameters/caw_inject_adopt_settle

say "label=$LABEL dur=$DUR rearm=$REARM dev=${MXFS_DEV:-run.sh default} evidence=$EV"
MXFS_FORCE_PREP=1 timeout 180 ./run.sh 2 cawd prep_cluster > "$EV/prep.log" 2>&1
rc=$?
say "prep rc=$rc ($(grep -a 'prep_cluster OK' "$EV/prep.log" | tail -1 | cut -c1-120))"
[ $rc = 0 ] || { say "RESULT INFRA: prep failed"; exit 2; }
rsh $A 15 "test -w $KNOB && echo KNOB_OK" | grep -q KNOB_OK ||
    { say "RESULT INFRA: $A's module has no $KNOB (not this build?)"; exit 2; }

D="$MNT/adset_$$"
rsh $A 20 "mkdir -p $D && sync && stat -c DIRINO=%i $D" > "$EV/setup.txt"
grep -q DIRINO= "$EV/setup.txt" || { say "RESULT INFRA: could not create $D"; exit 2; }
say "shared dir $D $(cat "$EV/setup.txt")"

( rsh $A $(( DUR + 30 )) "end=\$(( \$(date +%s) + $DUR )); n=0
    while [ \$(date +%s) -lt \$end ]; do echo 1 > $KNOB; n=\$((n+1)); sleep $REARM; done
    echo 0 > $KNOB; echo ARMED=\$n" > "$EV/arm_$A.txt" ) &
PIDS="$!"
for n in $A $B; do
    ( rsh $n $(( DUR + 40 )) "cd $D || exit 1; end=\$(( \$(date +%s) + $DUR )); i=0; bad=0
        while [ \$(date +%s) -lt \$end ]; do
          : > ${n}_\$i || bad=\$((bad+1)); i=\$((i+1)); sleep 0.02
        done; echo OPS=\$i BAD=\$bad" > "$EV/load_$n.txt" ) &
    PIDS="$PIDS $!"
done
wait $PIDS
say "arm loop: $(cat "$EV/arm_$A.txt")"
for n in $A $B; do say "$n load: $(tr '\n' ' ' < "$EV/load_$n.txt" | cut -c1-200)"; done

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
    grep -q '^RC=0' "$EV/umount_$n.txt" || fail "$n umount: $(tr '\n' ' ' < "$EV/umount_$n.txt")"
    k=$(zcat "$EV/kernlog_$n.gz" | grep -acE 'BUG:|Oops|Shutting down filesystem')
    [ "$k" = 0 ] || fail "$n logged $k BUG/Oops/shutdown lines"
done
grep -q 'CHK_RC=0' "$EV/chk.txt" || fail "chk_mxfs: $(cat "$EV/chk.txt")"

zcat "$EV/kernlog_$A.gz" > "$EV/kernlog_$A.txt"
grep -a 'P250-INJECT-ADOPT-SETTLE' "$EV/kernlog_$A.txt" > "$EV/hits.txt"
grep -a 'P226-SETTLE-LIVE-SKIP' "$EV/kernlog_$A.txt" > "$EV/liveskip.txt"
p231=$(grep -ac 'P231-PURGE-INCOMPLETE' "$EV/kernlog_$A.txt")
[ "$p231" = 0 ] || fail "$A logged $p231 incomplete-purge lines"
nh=$(wc -l < "$EV/hits.txt")
say "injected settles: $nh; live-skips logged: $(wc -l < "$EV/liveskip.txt")"
head -5 "$EV/hits.txt" | cut -c1-240
if [ "$nh" = 0 ]; then
    say "RESULT NOT-EXERCISED: no direct-handoff adopt reached the injector on $A"
    [ $FAILS = 0 ] && exit 3 || exit 1
fi
while IFS= read -r h; do
    s=$(echo "$h" | grep -ao ' slot=[0-9]*' | head -1 | cut -d= -f2)
    ob=$(echo "$h" | grep -ao 'own_bit_after=[0-9-]*' | cut -d= -f2)
    [ "$ob" = 1 ] || fail "slot $s: own bit after the injected settle = $ob (the adopted bit was stripped or unread)"
    grep -aq "P226-SETTLE-LIVE-SKIP slot=$s " "$EV/liveskip.txt" ||
        fail "slot $s: no P226-SETTLE-LIVE-SKIP — the settle never met the adopted bit as a leftover candidate, so this hit does not exercise the window"
done < "$EV/hits.txt"
[ $FAILS = 0 ] && { say "RESULT PASS ($nh injected settles, every adopted bit kept)"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
