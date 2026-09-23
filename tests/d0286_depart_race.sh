#!/bin/sh
# d0286_depart_race.sh — D-0286 review item F.1: prove the clean-leave /
# poison LINEARIZATION semantics with the deterministic injector
# mxfs.dbg_depart_race (0.29.0, dlm/v5_mount.c v5_depart_race_inject).
#
# For each injection point P in 1..5, on node N (mounted, transport-agnostic):
#   set dbg_depart_race=P, cleanly unmount N, then sweep N's dmesg from a
#   marker and the observer W's dmesg:
#   P=1 (poison lands BEFORE the ACTIVE->CLEAN_LEAVE cmpxchg): poison WINS —
#       P-DEPART-POISON-WINS=1, P-GOODBYE-SENT=0, P-POISON-AFTER-CLEAN-LEAVE=0,
#       W sees NO P-GOODBYE-RX from N and its death path engages for N
#       (heartbeat record left ACTIVE -> monitor -> fence -> replay).
#   P=2..5 (poison lands AFTER the CAS): the departure is committed and
#       irrevocable — P-DEPART-POISON-WINS=0, P-GOODBYE-SENT=1 (TCP) or the
#       slot release stands (CAW), and the contradiction detector
#       P-POISON-AFTER-CLEAN-LEAVE=1 fires exactly once; W sees P-GOODBYE-RX
#       (TCP) / a clean-depart (CAW) and NO death path for N.
# REACHABILITY (sess419): CAW clean unmount = P1, P2 only (P3/P4 are inside
# the TCP-only GOODBYE block); TCP = P1..P4; P5 is unreachable on every
# transport (Arm C deferred slot release frees the ctx before the commit).
# Unreachable points are reported SKIP with the knob disarmed.
# Every P is followed by a full prep_cluster (P=1 leaves N dirty by design;
# the rig must re-form) — the caller does that between invocations:
#   for p in 1 2 3 4 5; do ./run.sh 32 $dlm prep_cluster; \
#       tests/d0286_depart_race.sh s418 $p; done
#
# the budget rule (derived): srcgate 5s + umount <=45s + 4 sweeps ~10s + P=1's
# death-path wait <= dead_timeout_ms/1000+12 (74s at the 62s compile
# default) => ~135s.  Caller bound 160s (P=2..5 finish in ~60s).
#
# Usage: tests/d0286_depart_race.sh <label> <point 1..5> [N] [W]
set -u
LABEL=${1:?label}; PT=${2:?point}
N=${3:-test3}; W=${4:-test1}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0286race_p$PT
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/window_count_into (tests/lib/rig.sh): every count a verdict
# is taken from is acquired into its own file and validated in the parent
# shell first; a failed ssh is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
P=/sys/module/mxfs/parameters

echo "=== d0286_depart_race label=$LABEL point=$PT N=$N W=$W out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$N" "$W"; do
    nsv=$(timeout 15 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | filt | tr -dc 'A-F0-9')
    [ "$nsv" = "$TREESV" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$TREESV'"; exit 2; }
done
tcp=$(timeout 15 $SSH "$N" "cat $P/force_transport" 2>/dev/null | filt | tr -dc '0-9')
# sess419 (s419 p3 lap): reachability of the injection points on a CLEAN
# unmount, from dlm/v5_mount.c mxfs_v5_dlm_destroy:
#   3,4 sit inside the GOODBYE block (ctx->peer && depart_clean) — TCP only;
#   5 sits on the !late slot-release arm, but a clean unmount ALWAYS hands
#     the slot out deferred (Arm C `late`, P278-LATE-RELEASE) and the ctx is
#     freed before the late commit, so there is no session left to poison:
#     point 5 is unreachable on every transport.
# An unreachable point is a matrix SKIP (knob disarmed), not an FS verdict.
skip=""
[ "$PT" = 5 ] && skip="point 5 (post-slot) is on the !late arm; clean unmount always defers the slot release (Arm C) and frees the ctx first"
[ "$tcp" != 1 ] && { [ "$PT" = 3 ] || [ "$PT" = 4 ]; } && skip="point $PT is inside the TCP-only GOODBYE block; CAW sends no goodbye"
if [ -n "$skip" ]; then
    timeout 15 $SSH "$N" "echo 0 > $P/dbg_depart_race" >/dev/null 2>&1
    echo "  SKIP p$PT unreachable on this transport: $skip"
    echo "=== d0286_depart_race p$PT: fails=0 SKIP out=$OUT ==="
    exit 0
fi
MARK="D0286R-$LABEL-p$PT-$$"
for n in "$N" "$W"; do timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done

# a little dirty state so the teardown has real drains to prove
timeout 25 $SSH "$N" "mkdir -p $MNT/.race_$LABEL && dd if=/dev/urandom of=$MNT/.race_$LABEL/p$PT bs=4096 count=4 2>/dev/null; sync; echo $PT > $P/dbg_depart_race; cat $P/dbg_depart_race" 2>/dev/null | filt | tr -dc '0-9' > "$OUT/armed.txt"
ck "knob armed on $N" "$(cat "$OUT/armed.txt")" "$PT"
urc=$(timeout 60 $SSH "$N" "timeout 45 umount $MNT; echo rc=\$?" 2>/dev/null | filt | sed -n 's/^rc=//p')
echo "  INFO umount rc=$urc"
sleep 3
measure "$N" 25 "$OUT/dmesg_$N.txt" '^DMESG_END$' "the kernel log on $N from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
inj=$(grep -ac "P-DEPART-RACE-INJECT point=$PT" "$OUT/dmesg_$N.txt")
ck "injector fired at point $PT" "$inj" "1"
pw=$(grep -ac 'P-DEPART-POISON-WINS' "$OUT/dmesg_$N.txt")
gs=$(grep -ac 'P-GOODBYE-SENT' "$OUT/dmesg_$N.txt")
pa=$(grep -ac 'P-POISON-AFTER-CLEAN-LEAVE' "$OUT/dmesg_$N.txt")
sp=$(grep -ac 'P-SESSION-POISON' "$OUT/dmesg_$N.txt")
if [ "$PT" = 1 ]; then
    ck "p1: poison wins the CAS (P-DEPART-POISON-WINS)" "$pw" "1"
    ck "p1: no goodbye sent" "$gs" "0"
    ck "p1: no P-POISON-AFTER-CLEAN-LEAVE" "$pa" "0"
    ck "p1: P-SESSION-POISON logged" "$sp" "1"
    ck "p1: heartbeat record NOT cleanly released (no P-GOODBYE/clean stamp)" "$(grep -ac 'clean-release stamp\|release_slot' "$OUT/dmesg_$N.txt")" "0"
    # observer: no goodbye consumed, death path engages within the grace.
    # budget: the grace is DERIVED from the observer's dead-declaration
    # window — dead_timeout_ms (0 = compile default 31 samples x 2 s =
    # 62 s, dlm/disklock.h MXFS_DISKLOCK_DEAD_THRESHOLD) + one HB sample
    # of monitor phase + ~10 s fence/dead-confirm re-read.  sess419: a
    # fixed 45 s window produced a false FAIL on CAW (test1 needed 62 s).
    dtm=$(timeout 15 $SSH "$W" "cat $P/dead_timeout_ms" 2>/dev/null | filt | tr -dc '0-9')
    [ "${dtm:-0}" -eq 0 ] && dtm=62000
    grace=$(( dtm / 1000 + 2 + 10 ))
    echo "  INFO $W dead_timeout_ms=$dtm -> death-path grace ${grace}s"
    i=0; dp=0
    while [ $i -lt $grace ]; do
        window_count_into dp "$W" 25 "$MARK" 'lease expired/died\|recovery starting\|P-TCPDEATH-DEFERRED\|initiating recovery' "dp"
        [ "${dp:-0}" -ge 1 ] && break; sleep 3; i=$((i+3))
    done
    ck "p1: $W death/recovery path engaged for $N" "$([ "${dp:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    window_count_into wc1 "$W" 25 "$MARK" 'P-GOODBYE-RX' "p1:  W saw no P-GOODBYE-RX"
    ck "p1: $W saw no P-GOODBYE-RX" "$wc1" "0"
else
    ck "p$PT: CAS already committed (no P-DEPART-POISON-WINS)" "$pw" "0"
    ck "p$PT: contradiction detector fired once" "$pa" "1"
    ck "p$PT: state stayed CLEAN_LEAVE (no P-SESSION-POISON)" "$sp" "0"
    if [ "$tcp" = 1 ]; then
        ck "p$PT: goodbye still sent (irrevocable)" "$gs" "1"
        sleep 2
        window_count_into wc2 "$W" 25 "$MARK" 'P-GOODBYE-RX' "p PT:  W consumed the goodbye"
        ck "p$PT: $W consumed the goodbye" "$([ "$wc2" -ge 1 ] && echo 1 || echo 0)" "1"
    fi
    window_count_into wc3 "$W" 25 "$MARK" 'lease expired/died\|initiating recovery\|P-TCPDEATH-DEFERRED' "p PT:  W ran no death path for  N"
    ck "p$PT: $W ran no death path for $N" "$wc3" "0"
fi
measure "$W" 25 "$OUT/dmesg_$W.txt" '^DMESG_END$' "the kernel log on $W from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
for n in "$N" "$W"; do
    window_into "$OUT/rv_s_1.txt" "$n" 25 "$MARK"; s=$(cat "$OUT/rv_s_1.txt" | grep -aEc 'BUG:|Oops' | tr -dc '0-9')
    ck "zero splats on $n" "${s:-nossh}" "0"
done
echo "=== d0286_depart_race p$PT: fails=$fails out=$OUT ==="
[ "$fails" -eq 0 ]
