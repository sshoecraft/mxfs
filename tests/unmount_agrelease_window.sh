#!/bin/bash
#
# unmount_agrelease_window.sh — does an unmount write allocation-group metadata
# after it has published its AG grants?  Two nodes, either transport.
#
# D-UNMOUNT-AG-RELEASE-SKIPS-DRAIN-PIPELINE-INVARIANT1-482 (and the removed
# D-0483 it shares a fix with).  Up to 0.69.2 put_super published every AG
# grant first and only then ran deferred inode inactivation, the SB summary
# sync and xfs_unmountfs's AIL push — writing AGI, inobt, finobt and inode
# clusters for AGs a peer may already own.  0.69.3 moved that work above the
# publication, and put_super prints P483-AGFREE-WINDOW with the proof:
#   every after-publication counter (nodlm_*, dlm_*, iclus_*, nulldlm_acquires,
#   aglock_after, inodegc_after_stop) must be zero, and pre_wr — the same
#   work done under live grants — must be nonzero, or the zeros measure an
#   unmount that had nothing to do.  A violation prints at alert level; the
#   clean line is a debug probe (prep loads the module with dyndbg=+p).
#
# THE WORKLOAD makes the inactivation certainly pending at put_super (the
# method tests/sess485_chain133_agfree_hoist_ab.sh proved on 32 nodes): per
# node, a background shell creates FILES files, holds an fd on each, unlinks
# them all and blocks on a FIFO; the foreground syncs, releases it, waits for
# it to exit — closing every fd queues every inactivation — and runs umount at
# once.  Both nodes do it at the same time.
#
# Then: per-node umount rc and wall, the P482/P483 lines, chk_mxfs on the
# quiescent image, zero BUG/Oops.  PASS needs all of it.
#
# Budget (derived): prep 60-180 s (run.sh's own); FILES creates at ~30 ms each
# (400 -> ~12 s) + umount (a clean 2-node unmount is 1-15 s) -> 120 s per node,
# in parallel; chk 240 s; captures 30 s.
#
# Usage: tests/unmount_agrelease_window.sh LABEL DLM
#   DLM is tcp or cawd (CAW needs MXFS_DEV for the device, e.g. the QNAP
#   by-id path).  Env: FILES (400), MXFS_NODE_LIST (test1,test2).
#   Evidence: tests/evidence/unmount_agrelease/<stamp>_<LABEL>/.  Exit 0 PASS,
#   1 FAIL, 2 INFRA, 3 VACUOUS (pre_wr zero on both nodes).
#
set -u

LABEL="${1:?usage: unmount_agrelease_window.sh LABEL tcp|cawd}"
DLM="${2:?usage: unmount_agrelease_window.sh LABEL tcp|cawd}"
FILES="${FILES:-400}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 2
SSH="$HERE/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
NODES=$(echo "${MXFS_NODE_LIST:-test1,test2}" | tr ',' ' ')
EV="$HERE/tests/evidence/unmount_agrelease/$(date +%Y%m%dT%H%M%S)_$LABEL"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
say() { echo "[$(date +%T) +$(el)s] $*"; }
fld() { echo "$2" | grep -aoE "(^| )$1=[0-9-]+" | head -1 | cut -d= -f2; }

say "label=$LABEL dlm=$DLM files=$FILES nodes=$NODES dev=${MXFS_DEV:-run.sh default} evidence=$EV"
timeout 400 ./run.sh 2 "$DLM" prep_cluster > "$EV/prep.log" 2>&1
rc=$?
say "prep rc=$rc ($(grep -a 'prep OK\|converged' "$EV/prep.log" | tail -1 | cut -c1-120))"
[ $rc = 0 ] || { say "RESULT INFRA: prep failed"; exit 2; }
MARK="UAW-$LABEL-$$"
for n in $NODES; do timeout 15 "$SSH" "$n" "echo $MARK > /dev/kmsg" </dev/null >/dev/null 2>&1; done

for n in $NODES; do
    ( d="$MNT/uaw_$n"
      timeout 120 "$SSH" "$n" \
        "ulimit -n \$(( $FILES + 64 )) || { echo ULIMIT_FAIL; exit 1; }; mkdir -p $d && cd $d && rm -f /run/uaw_ready /run/uaw_fifo && mkfifo /run/uaw_fifo || { echo SETUP_FAIL; exit 1; }
         ( n=0; h=0; for k in \$(seq 1 $FILES); do : > f\$k && n=\$((n+1)) && exec {fd}<f\$k && h=\$((h+1)); done
           rm -f $d/f*; echo WORK made=\$n held=\$h; : > /run/uaw_ready; read -t 100 x < /run/uaw_fifo ) & HP=\$!
         w=0; while [ ! -e /run/uaw_ready ] && [ \$w -lt 600 ]; do sleep 0.1; w=\$((w+1)); done
         cd /; sync
         echo HELD_FDS=\$(for p in \$HP \$(cat /proc/\$HP/task/\$HP/children 2>/dev/null); do ls /proc/\$p/fd 2>/dev/null; done | wc -l)
         echo go > /run/uaw_fifo; wait \$HP; T=\$(date +%s%N); umount $MNT 2>&1; echo RC=\$?
         mountpoint -q $MNT && echo STILL_MOUNTED || echo UNMOUNTED
         echo UMOUNT_MS=\$(( (\$(date +%s%N) - T) / 1000000 ))" </dev/null 2>/dev/null \
        | grep -avE '^Warning|Unauthorized|authorized user' > "$EV/work_$n.txt" ) &
    PIDS="${PIDS:-} $!"
done
# the node jobs only: a bare `wait` also waits for the tee behind
# `exec > >(tee ...)`, which never exits
wait $PIDS
for n in $NODES; do say "$n: $(tr '\n' ' ' < "$EV/work_$n.txt" | cut -c1-200)"; done
for n in $NODES; do
    # the journal, from the lap's start: a large FILES overflows the kernel ring
    # before this runs (uaw_caw_s3: 3000 held files, marker and P483 both gone
    # from dmesg), and journald can drop the marker itself in the same burst
    timeout 60 "$SSH" "$n" "journalctl -k --since=@$(( t0 - 5 )) --no-pager -o cat | grep -aE 'P483-AGFREE-WINDOW|P482-UMOUNT-AGREL|P485-UMOUNT-DRAIN|BUG:|Oops|Shutting down filesystem' | cut -c1-900" </dev/null 2>/dev/null \
        | grep -avE '^Warning|Unauthorized|authorized user' > "$EV/p483_$n.txt"
done
first=$(echo $NODES | cut -d' ' -f1)
# the device run.sh used: MXFS_DEV, else the QNAP LUN named in data/rigs.json
# (never /dev/sda: which target enumerates as sda on these nodes is not fixed)
CHKDEV=${MXFS_DEV:-/dev/disk/by-id/wwn-0x$(python3 -c 'import json; print(json.load(open("data/rigs.json"))["qnap"]["lun_wwid"].replace("naa.",""))')}
timeout 240 "$SSH" "$first" "/src/mxfs/tools/chk_mxfs $CHKDEV >/dev/null 2>&1; echo CHK_RC=\$?" </dev/null 2>/dev/null | grep -a CHK_RC > "$EV/chk.txt"

FAILS=0
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
prewr_total=0
for n in $NODES; do
    w="$EV/work_$n.txt"; p="$EV/p483_$n.txt"
    grep -q "made=$FILES held=$FILES" "$w" || fail "$n did not create and hold $FILES files ($(grep -ao 'made=[0-9]* held=[0-9]*' "$w"))"
    [ "$(grep -ao 'HELD_FDS=[0-9]*' "$w" | cut -d= -f2)" -ge "$FILES" ] 2>/dev/null || fail "$n had fewer than $FILES fds open at the release"
    grep -q '^RC=0' "$w" && grep -q '^UNMOUNTED' "$w" || fail "$n did not unmount cleanly"
    line=$(grep -a 'P483-AGFREE-WINDOW' "$p" | tail -1)
    [ -n "$line" ] || { fail "$n printed no P483-AGFREE-WINDOW (a module without dyndbg, or put_super never reached it)"; continue; }
    grep -aq 'after publishing its AG grants as free and after its DLM was gone\|after the grants were published; whatever' "$p" \
        && fail "$n printed a VIOLATION-level P483 line"
    for c in nodlm_wr nodlm_rd iclus_nodlm_wr iclus_nodlm_rd dlm_wr dlm_rd iclus_dlm_wr iclus_dlm_rd nulldlm_acquires aglock_after inodegc_after_stop; do
        v=$(fld "$c" "$line"); [ "${v:-0}" = 0 ] || fail "$n $c=$v after publication"
    done
    pw=$(fld pre_wr "$line"); prewr_total=$(( prewr_total + ${pw:-0} ))
    say "$n P483: $(echo "$line" | grep -aoE '(dlm_wr|nodlm_wr|pre_wr|pre_iclus_wr|aglock_after|inodegc_after_stop)=[0-9]+' | tr '\n' ' ')umount_ms=$(grep -ao 'UMOUNT_MS=[0-9]*' "$w" | cut -d= -f2)"
    [ "$(grep -acE 'BUG:|Oops|Shutting down filesystem' "$p")" = 0 ] || fail "$n logged BUG/Oops/shutdown"
done
grep -q 'CHK_RC=0' "$EV/chk.txt" || fail "chk_mxfs on the quiescent image: $(cat "$EV/chk.txt")"
if [ "$prewr_total" = 0 ] && [ $FAILS = 0 ]; then
    say "RESULT VACUOUS: pre_wr is zero on every node, so the unmount had no pending metadata work and the zeros measure nothing"
    exit 3
fi
[ $FAILS = 0 ] && { say "RESULT PASS (pre_wr total $prewr_total)"; exit 0; }
say "RESULT FAIL ($FAILS failed)"
exit 1
