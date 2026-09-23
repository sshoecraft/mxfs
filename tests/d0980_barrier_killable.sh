#!/bin/bash
# d0980_barrier_killable.sh — the deterministic arm for D-0980: a joiner's
# mount(2) that outlived its own `timeout` by more than a minute inside the
# admission barrier and could not be ended by SIGTERM (s65f, the sole-survivor
# gate probe; the kernel evidence of that lap was lost).
#
# WHAT WAS WRONG.  The barrier bounded its admission wait by COUNTING its own
# 1 s poll sleeps.  Everything a round did between two polls — sector reads,
# PR commands, the 6 s abandonment observation inside every takeover, a slice
# stability proof of up to 45 s, the replay, the ledger takeover scan — was
# invisible to the bound, so a 122-poll ghost extension held the mount for as
# long as 122 rounds took; and nothing in the loop looked at signals, so the
# task sat in TASK_UNINTERRUPTIBLE and `timeout` could not end it.
#
# WHAT THIS HARNESS PROVES, on the 2-node TCP rig, without faking anything:
#
#   K  (killability)  Both VMs are destroyed and restarted with their mounts
#      in flight, which leaves frozen ACTIVE heartbeat records on the LUN.  B
#      then mounts under `timeout -s TERM KILL_AT_S`.  Its barrier is holding
#      admission on A's frozen record (P-BARRIER-GHOST-EXTEND) when the
#      signal lands.  The mount must return within one poll of the signal
#      (MOUNT_RC=124, WALL_MS <= KILL_AT_S*1000 + KILL_SLACK_MS), log
#      P-BARRIER-CANCELLED and P-BARRIER-CLOCK result=cancelled with a wait
#      that was genuinely in progress (wait_ms >= KILL_MIN_WAIT_MS — the
#      vacuity gate: a mount that had not reached the barrier proves nothing).
#
#   C  (the bound, and the debt left behind)  A then mounts with no signal.
#      Its barrier resolves the frozen records (declared dead, fenced as the
#      sole survivor, replayed) and admits, or refuses at its bound; either
#      way its P-BARRIER-CLOCK line must show overrun_ms <= last_round_ms +
#      POLL_MS: a deadline checked between slices can run past the bound only
#      by the slice it could not preempt.  A completing mount also proves the
#      cancelled mount left the slices where a later owner finds them.
#
#   R  (retry)  B mounts again, unbounded by a signal, and must complete:
#      cancellation left nothing that poisons the next attempt.
#
# the budget rule (derived, not rounded): VM destroy+start+boot ~150 s
# (measured 152 s, s581a) + deploy ~20 s + K: KILL_AT_S + slack ~25 s + C: the
# dead window 62 s + one takeover/fence/replay round 18 s (measured s65g) +
# unwind ~10 s = ~90 s + R: ~10 s (peer live) + captures ~30 s = ~325 s.
# Caller bound 480 s (1.5x).  JOIN_BOUND 300 s bounds each unsignalled mount.
#
# Usage: tests/d0980_barrier_killable.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS,
#        KILL_AT_S (default 20), KILL_SLACK_MS (default 3000),
#        KILL_MIN_WAIT_MS (default 5000), JOIN_BOUND (default 300), VM_RESTART=1.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # the control mount
B=${MXFS_NODE_LIST##*,}          # the signalled mount
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
KILL_AT_S=${KILL_AT_S:-20}
KILL_SLACK_MS=${KILL_SLACK_MS:-3000}
KILL_MIN_WAIT_MS=${KILL_MIN_WAIT_MS:-5000}
JOIN_BOUND=${JOIN_BOUND:-300}
POLL_MS=1000
VM_RESTART=${VM_RESTART:-1}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0980_$LABEL
mkdir -p "$OUT"
fails=0
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# clockf <journal> <result> <field>: one field of the P-BARRIER-CLOCK line
# carrying that result (the first such line), empty when there is none
clockf() { grep -a "P-BARRIER-CLOCK result=$2 " "$1" | head -1 | grep -ao " $3=[0-9]*" | head -1 | cut -d= -f2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0980_barrier_killable label=$LABEL A(control)=$A B(signalled)=$B sv=$SV kill_at=${KILL_AT_S}s join_bound=${JOIN_BOUND}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)

if [ "$VM_RESTART" = 1 ]; then
    for n in $A $B; do
        timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1
        timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1
    done
    for n in $A $B; do
        w=0
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait node=$n polls=$w"
    done
    echo "STAGE vm-restart wall=$(( $(date +%s) - s0 ))s"
fi

MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_$n.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy fails=$fails"; exit 2; }

measure "$A" 60 "$OUT/hb_before.txt" '^slot +[0-9]+ magic=' "the platter dump on $A before the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
echo "STAGE hb-before: $(grep -ac 'flags=ACTIVE' "$OUT/hb_before.txt") ACTIVE record(s)"
grep -a 'flags=ACTIVE' "$OUT/hb_before.txt" | sed 's/^/    /' | cut -c1-120
# The arm's precondition, asserted before anything is judged: the platter
# must carry the shape the probe leaves — frozen ACTIVE records of REAL
# incarnations (epoch != 0; the epoch-0 slot-2 record seen on this LUN is
# not one) for B's barrier to hold on, and NO certified-but-unowned recovery
# descriptor.  Measured s66e: a lap started on a LUN left by refused mounts
# found slot 0 at stage FENCED owner=0; B claimed it in round 1 and the
# replay ended in a whole-filesystem quarantine (a finding of its own,
# ledgered), so no barrier WAIT was ever in progress and the signal landed on
# nothing.  Run this harness through the capture gate (ensure, then lap),
# which formats and mounts both nodes first; the VM restart above then
# leaves exactly the two frozen records this arm needs.
live=$(grep -a 'flags=ACTIVE' "$OUT/hb_before.txt" | grep -avc ' epoch=0 ')
guard=$(grep -ac 'flags=RECOVERY_GUARD\|stage=FENCED\|stage=FENCING\|stage=SNAPSHOTTING' "$OUT/hb_before.txt")
echo "STAGE precondition: frozen real-incarnation ACTIVE=$live recovery-descriptors=$guard"
if [ "${live:-0}" -lt 1 ] || [ "${guard:-0}" -ne 0 ]; then
    echo "  VACUOUS the platter does not carry the arm's precondition (need >=1 frozen ACTIVE record with a real epoch and no recovery descriptor) — run through the capture gate's ensure + lap"
    echo "RESULT: VACUOUS label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi

# ---- K: B mounts under a SIGTERM at KILL_AT_S.
KMARK=$(date +%s)
echo "MARK=$KMARK" > "$OUT/K_join.txt"
rsx $((KILL_AT_S + 90)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout -s TERM $KILL_AT_S mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/K_join.txt"
measure "$B" 60 "$OUT/K_journal.txt" '^JOURNAL_END$' "the kernel journal on $B since the signalled join" "journalctl -k --since @$KMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
measure "$B" 30 "$OUT/K_mount_stack.txt" '^STACK_END$' "the stack of any mount still running on $B" "for p in /proc/[0-9]*; do [ \"\$(cat \$p/comm 2>/dev/null)\" = mount ] || continue; echo \"PID=\${p#/proc/} STATE=\$(cut -d' ' -f3 \$p/stat)\"; cat \$p/stack 2>/dev/null; done; echo STACK_END"
capture_require "$OUT/K_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the signalled join of $B"
kmrc=$(field "$OUT/K_join.txt" MOUNT_RC); kwall=$(field "$OUT/K_join.txt" WALL_MS)
echo "STAGE K: B mount rc=$kmrc wall=${kwall}ms $(grep -a '^MOUNTED\|^NOT_MOUNTED' "$OUT/K_join.txt")"
grep -a 'P-BARRIER-CLOCK\|P-BARRIER-CANCELLED\|P-BARRIER-GHOST-EXTEND\|mount ABORTED' "$OUT/K_journal.txt" | sed 's/.*kernel: /    /' | cut -c1-200 | head -6
c() { grep -ac "$1" "$2"; }
# vacuity: the signal must have landed on a barrier that was WAITING
kwait=$(clockf "$OUT/K_journal.txt" cancelled wait_ms)
ckge "K: the admission wait was in progress when the signal landed (P-BARRIER-CLOCK result=cancelled wait_ms)" "${kwait:-0}" "$KILL_MIN_WAIT_MS"
ck   "K: the mount was ended by the signal (timeout rc 124)" "$kmrc" 124
ck   "K: the mount returned within one poll of the signal (WALL_MS <= kill_at + slack)" "$([ "${kwall:-0}" -le $((KILL_AT_S * 1000 + KILL_SLACK_MS)) ] && echo within || echo late:${kwall}ms)" within
ck   "K: the barrier logged the cancellation (P-BARRIER-CANCELLED)" "$(c 'P-BARRIER-CANCELLED' "$OUT/K_journal.txt")" 1
ck   "K: nothing was admitted (no 'Ending clean mount')" "$(c 'Ending clean mount' "$OUT/K_journal.txt")" 0
ck   "K: no mount task is left running on $B" "$(c '^PID=' "$OUT/K_mount_stack.txt")" 0
ck   "K: $B is not mounted" "$(c '^NOT_MOUNTED' "$OUT/K_join.txt")" 1

# ---- C: A mounts with no signal; the bound must hold and the debt B left
# must be recoverable.
CMARK=$(date +%s)
echo "MARK=$CMARK" > "$OUT/C_join.txt"
rsx $((JOIN_BOUND + 60)) "$A" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/C_join.txt"
measure "$A" 60 "$OUT/C_journal.txt" '^JOURNAL_END$' "the kernel journal on $A since its join" "journalctl -k --since @$CMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
capture_require "$OUT/C_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $A"
cmrc=$(field "$OUT/C_join.txt" MOUNT_RC); cwall=$(field "$OUT/C_join.txt" WALL_MS)
echo "STAGE C: A mount rc=$cmrc wall=${cwall}ms $(grep -a '^MOUNTED\|^NOT_MOUNTED' "$OUT/C_join.txt")"
grep -a 'P-BARRIER-CLOCK\|P-BARRIER-GHOST-EXTEND\|mount ABORTED\|P238-TAKEOVER-NOBUDGET' "$OUT/C_journal.txt" | sed 's/.*kernel: /    /' | cut -c1-200 | head -6
cres=$(grep -ao 'P-BARRIER-CLOCK result=[a-z]*' "$OUT/C_journal.txt" | head -1 | cut -d= -f2)
ck   "C: A's barrier printed its exit line (P-BARRIER-CLOCK)" "$([ -n "$cres" ] && echo present || echo absent)" present
if [ -n "$cres" ]; then
    cover=$(clockf "$OUT/C_journal.txt" "$cres" overrun_ms); clast=$(clockf "$OUT/C_journal.txt" "$cres" last_round_ms)
    cbound=$(clockf "$OUT/C_journal.txt" "$cres" bound_ms); cw=$(clockf "$OUT/C_journal.txt" "$cres" wait_ms)
    echo "    C: result=$cres wait_ms=$cw bound_ms=$cbound overrun_ms=$cover last_round_ms=$clast"
    ck "C: the wait ran past its bound by no more than the slice it could not preempt (overrun_ms <= last_round_ms + poll)" "$([ "${cover:-0}" -le $(( ${clast:-0} + POLL_MS )) ] && echo held || echo exceeded:${cover}ms)" held
fi
ck   "C: A's mount ended inside its own timeout (never rc 124)" "$([ "${cmrc:-none}" != 124 ] && [ "${cmrc:-none}" != none ] && echo ended || echo hung:rc=${cmrc:-none})" ended
ck   "C: A completed its mount over the records the cancelled mount left behind" "$(c '^MOUNTED' "$OUT/C_join.txt")" 1

# ---- R: B mounts again, unsignalled.
RMARK=$(date +%s)
echo "MARK=$RMARK" > "$OUT/R_join.txt"
rsx $((JOIN_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" >> "$OUT/R_join.txt"
measure "$B" 60 "$OUT/R_journal.txt" '^JOURNAL_END$' "the kernel journal on $B since its retry" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600; echo JOURNAL_END"
capture_require "$OUT/R_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the retry join of $B"
echo "STAGE R: B mount rc=$(field "$OUT/R_join.txt" MOUNT_RC) wall=$(field "$OUT/R_join.txt" WALL_MS)ms $(grep -a '^MOUNTED\|^NOT_MOUNTED' "$OUT/R_join.txt")"
ck   "R: B's retry completed after the cancelled attempt" "$(c '^MOUNTED' "$OUT/R_join.txt")" 1

for t in K C R; do
    ck "$t: zero shutdown / BUG / Oops" \
       "$(grep -ac 'shutting down filesystem\|BUG:\|Oops\|WARNING:' "$OUT/${t}_journal.txt")" 0
done
measure "$A" 60 "$OUT/hb_after.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after the joins" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
echo "STAGE hb-after: $(grep -ac 'flags=ACTIVE' "$OUT/hb_after.txt") ACTIVE record(s)"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
