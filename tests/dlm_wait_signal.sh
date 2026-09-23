#!/bin/bash
# dlm_wait_signal.sh — closure arm for
# D-DLM-WAIT-SPINS-UNKILLABLE-WITH-SIGNAL-PENDING-0913.
#
# A signal that lands while a task waits in a DLM lock wait
# (mxfs_pal_cond_timedwait, TASK_INTERRUPTIBLE) used to make every later
# wait return at once: the DLM loops on "not done", the task spins at 100 %
# CPU in the kernel and never returns to user space to take the signal.
# Measured s518g: the AG-mask probe's SIGALRM inside a root-inode lock wait,
# 30+ minutes of spin, every root op parked behind it.
#
# Shape: H holds F's grant with its release drain paused (D-512 T2
# pausepoint, PAUSE_MS); W runs `timeout -s TERM SIG_AT md5sum F`, so SIGTERM
# lands while W's read waits in the DLM.  Verdict: W's md5sum task must NOT
# accumulate kernel CPU while the pause runs (a spinning task gains ~100
# ticks/s), it must be GONE within 20 s of the pause end (the signal is
# taken when the read returns), and neither node logs a splat or shutdown.
#
# the budget rule (derived): setup ~5 s + PAUSE_MS + 20 s grace + captures.  Default
# PAUSE_MS=40000 keeps the wait well inside the 180 s acquire budget so the
# only thing under test is the signal.
#
# Usage: tests/dlm_wait_signal.sh <label> [H=test1] [W=test2]
# Env:   MXFS_MNT (default /mnt/shared), PAUSE_MS (default 40000), SIG_AT
#        (seconds into the read at which SIGTERM is sent, default 5).
# Leaves both nodes mounted and clears the pause knobs.  Exit 0 PASS, 1 FAIL,
# 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
H=${2:-test1}; W=${3:-test2}
PAUSE_MS=${PAUSE_MS:-40000}
SIG_AT=${SIG_AT:-5}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_waitsig_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): the kernel-log captures
# a verdict is counted from cross the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
hd() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }   # polling only; never counted
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
clear_knobs() { timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1; }

echo "=== dlm_wait_signal label=$LABEL H=$H W=$W pause_ms=$PAUSE_MS sig_at=${SIG_AT}s out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$H" "$W"; do
    info=$(timeout 15 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' mxfs ' /proc/mounts)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]] || { echo "ABORT: $n not mounted ($info)"; exit 2; }
done
MARK="WAITSIG-$LABEL-$$"
for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done

# 1. H writes F, arms the pause on F's inode, re-dirties.
F="$MNT/.waitsig_$LABEL.dat"
timeout 25 $SSH "$H" "
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd1_rc=\$? >&2; exit 1; }
    ino=\$(stat -c %i '$F'); echo \$ino
    echo \$ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo $PAUSE_MS > $P/dbg_rel_pause_ms
    dd if=/dev/urandom of='$F' bs=4096 count=8 || { echo dd2_rc=\$? >&2; exit 1; }
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
ino=$(sed -n 1p "$OUT/h_setup.txt" | tr -dc '0-9')
[ -n "$ino" ] || { echo "ABORT: H setup failed: $(filt < "$OUT/h_setup.err" | tail -3 | tr '\n' ' ')"; clear_knobs; exit 2; }
echo "  INFO ino=$ino at +$(el)s"
tpause=$(date +%s)

# 2. W's reader, signalled SIG_AT seconds into its DLM wait.  The remote
#    script samples the reader's kernel CPU ticks (field 15 of /proc/pid/stat)
#    every 5 s until the pause is over, then reports whether it is gone.
WPY="set -u
timeout -s TERM $SIG_AT md5sum '$F' > /root/waitsig_$LABEL.out 2>&1 &
rp=\$!
sleep 2
mp=\$(ps -o pid= --ppid \$rp -C md5sum | tr -d ' ' | head -1)
[ -n \"\$mp\" ] || mp=\$(ps -o pid= -C md5sum | tr -d ' ' | head -1)
echo md5_pid=\${mp:-none}
end=\$(( $PAUSE_MS / 1000 + 20 ))
for s in \$(seq 5 5 \$end); do
    sleep 5
    if [ -n \"\$mp\" ] && [ -d /proc/\$mp ]; then
        echo sample t=\$s state=\$(cut -d' ' -f3 /proc/\$mp/stat) stime=\$(cut -d' ' -f15 /proc/\$mp/stat) shdpnd=\$(grep -a '^ShdPnd' /proc/\$mp/status | cut -f2)
    else
        echo sample t=\$s gone=1
    fi
done
wait \$rp; echo timeout_rc=\$?
echo alive_after=\$([ -n \"\$mp\" ] && [ -d /proc/\$mp ] && echo 1 || echo 0)
echo md5out=\$(head -c 80 /root/waitsig_$LABEL.out | tr '\n' ' ')
"
timeout $(( PAUSE_MS / 1000 + 60 )) $SSH "$W" "$WPY" 2>"$OUT/w_reader.err" | filt > "$OUT/w_reader.txt"
wrc=$?
sleep 3
measure "$H" 20 "$OUT/dmesg_$H.txt" '^DMESG_END$' "the kernel log on $H from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$W" 20 "$OUT/dmesg_$W.txt" '^DMESG_END$' "the kernel log on $W from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
max_stime=$(grep -ao 'stime=[0-9]*' "$OUT/w_reader.txt" | cut -d= -f2 | sort -n | tail -1)
nsamples=$(grep -ac '^sample' "$OUT/w_reader.txt")
alive_after=$(grep -ao 'alive_after=[01]' "$OUT/w_reader.txt" | cut -d= -f2)
timeout_rc=$(grep -ao 'timeout_rc=[0-9]*' "$OUT/w_reader.txt" | cut -d= -f2)
paused=$(grep -ac "P-D512-RELPAUSE ino=$ino stage=1" "$OUT/dmesg_$H.txt")
ended=$(grep -ac "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_$H.txt")
# Since the remote-acquire abandonment protocol (0.82, D-0958) a killed task
# at a fallible boundary — a read is one — leaves its lock wait at once with
# an exact CANCEL to the master (P958-ACQ-KILLED, P958-ACQ-CANCEL-ACK), so
# the reader may be GONE at the first sample after the signal rather than
# parked in D until the pause ends (the sess518 shape, when the wait was not
# fallible).  Both are "did not spin"; what must be established is that the
# signal reached a reader that was still in its wait (timeout_rc=124: the
# timeout wrapper delivered TERM to a live md5sum, so the read had not
# completed on its own), and then either kernel-CPU samples of the live
# reader stayed flat or the reader left through the cancel path.  A reader
# that finished before SIG_AT measured nothing: ABORT, not a verdict.
gone_first=$(grep -a '^sample ' "$OUT/w_reader.txt" | head -1 | grep -ac 'gone=1')
# a CANCEL goes on the wire only when the request was queued at a REMOTE
# master (s57b-9: acq=82 CANCEL-SENT + ACK); an inode W masters itself is
# abandoned locally with no CANCEL at all (s57c: ino 136), so what is
# required is the abandonment line, and that every CANCEL sent was acked
count_file_into cancel_sent "$OUT/dmesg_$W.txt" "P958-ACQ-CANCEL-SENT .*ino=$ino "
count_file_into cancel_ack "$OUT/dmesg_$W.txt" "P958-ACQ-CANCEL-ACK .*ino=$ino "
count_file_into acq_killed "$OUT/dmesg_$W.txt" "P958-ACQ-KILLED ino=$ino "
echo "  INFO reader: ssh_rc=$wrc samples=$nsamples max_stime_ticks=${max_stime:-none} gone_at_first_sample=$gone_first acq_killed=$acq_killed cancel_sent=$cancel_sent cancel_ack=$cancel_ack alive_after=${alive_after:-none} timeout_rc=${timeout_rc:-none}; H paused=$paused ended=$ended; $(grep -a 'md5_pid=\|md5out=' "$OUT/w_reader.txt" | tr '\n' ' ')"
[ "$timeout_rc" = 124 ] || { echo "ABORT: the reader was not in its wait when SIGTERM was due (timeout_rc=${timeout_rc:-none}, not 124): the read completed or never started, so the signal path was not exercised"; echo "RESULT: ABORT label=$LABEL stage=reader evidence=$OUT"; clear_knobs; exit 2; }
ck "H entered the release-drain pause (BAST from W landed)" "$paused" "1"
ck "reader was observed while the pause ran (>= 3 samples)" "$([ "$nsamples" -ge 3 ] && echo 1 || echo 0)" "1"
if [ "$gone_first" = 1 ]; then
    ck "reader left its wait at the signal through the abandonment path (P958-ACQ-KILLED for ino $ino)" "$([ "$acq_killed" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "every CANCEL the abandonment sent to a remote master was acknowledged (sent=$cancel_sent)" "$([ "$cancel_sent" = 0 ] || [ "$cancel_ack" -ge 1 ] && echo 1 || echo 0)" "1"
else
    ck "reader did not spin in the kernel while signalled (max stime < 100 ticks over $nsamples samples)" "$([ -n "$max_stime" ] && [ "$max_stime" -lt 100 ] && echo 1 || echo 0)" "1"
fi
ck "reader is gone once the pause ended (signal taken at return, or the wait abandoned)" "$alive_after" "0"
ck "H's pause ended (the release drain completed)" "$ended" "1"
for n in "$H" "$W"; do
    s=$(grep -aEc 'BUG:|Oops|Shutting down filesystem|Corruption of in-memory|unrecoverable' "$OUT/dmesg_$n.txt"); ck "zero splats/shutdowns on $n" "$s" "0"
done
clear_knobs
timeout 15 $SSH "$H" "rm -f '$F'" >/dev/null 2>&1
echo "=== dlm_wait_signal $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
