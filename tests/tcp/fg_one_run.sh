#!/bin/bash
# fg_one_run.sh — ONE reliability run of `./run.sh 2 tcp`, FOREGROUND.
# Reboots both nodes clean, runs the full 2/tcp suite once, reports 17/17 vs
# partial, and on a partial dumps both nodes' dmesg.  Designed to be invoked
# from a single foreground Bash call (set the Bash tool timeout to 600000ms) so
# the turn BLOCKS on it — NEVER background+poll (user directive, sess10/sess47).
#
#   bash tests/tcp/fg_one_run.sh <label>   # e.g. r1, r2, ...
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
LABEL="${1:-r}"
N1=192.168.120.186; N2=192.168.120.182
# PLAIN=1 → pure defaults (no modargs) = the exact criterion command.
if [ "${PLAIN:-0}" = 1 ]; then
    export MXFS_EXTRA_MODARGS=""
else
    export MXFS_EXTRA_MODARGS="${MXFS_EXTRA_MODARGS:-dir_pr_release_fast=2 dir_acq_lockwait=60}"
fi
RUN_TIMEOUT="${RUN_TIMEOUT:-565}"
NOREBOOT="${NOREBOOT:-0}"

echo "===== FG RUN $LABEL ($(date -u +%H:%M:%S)Z) modargs='$MXFS_EXTRA_MODARGS' noreboot=$NOREBOOT ====="
if [ "$NOREBOOT" != 1 ]; then
    for n in test1 test2; do virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    sleep 3
    for n in test1 test2; do virsh -c qemu:///system start "$n" >/dev/null 2>&1; done
    up=0
    for i in $(seq 1 40); do
        ok=0
        for h in "$N1" "$N2"; do
            timeout 5 sshpass -f "$P" ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 root@"$h" true 2>/dev/null && ok=$((ok+1))
        done
        [ "$ok" -eq 2 ] && { up=1; echo "  both up after $((i*5))s"; break; }
        sleep 5
    done
    [ "$up" -eq 1 ] || { echo "RESULT: RUN $LABEL BOOT-FAIL"; exit 1; }
fi

LOG="/tmp/fg_${LABEL}.log"
t0=$(date +%s)
timeout "$RUN_TIMEOUT" ./run.sh 2 tcp > "$LOG" 2>&1
rc=$?
t1=$(date +%s)
np=$(grep -c '^  PASS ' "$LOG"); nf=$(grep -c '^  FAIL ' "$LOG")
echo "  rc=$rc wall=$((t1-t0))s PASS=$np FAIL=$nf"
grep -E '=== done:' "$LOG" | sed 's/^/  /'
if grep -q '=== done: ran=17' "$LOG" && [ "$nf" -eq 0 ] && [ "$np" -eq 17 ]; then
    echo "RESULT: RUN $LABEL PASS 17/17"
    exit 0
fi
echo "RESULT: RUN $LABEL PARTIAL pass=$np fail=$nf — FAILS:"
grep '^  FAIL ' "$LOG" | sed 's/^/    /'
[ "$rc" -eq 124 ] && echo "    (timeout: suite exceeded ${RUN_TIMEOUT}s — RULE 0 slowness FAIL)"
for h in "$N1" "$N2"; do
    nm=$([ "$h" = "$N1" ] && echo node1 || echo node2)
    timeout 25 sshpass -f "$P" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 root@"$h" dmesg \
        > "/tmp/fg_${LABEL}_${nm}.dmesg" 2>/dev/null
    echo "    dmesg -> /tmp/fg_${LABEL}_${nm}.dmesg ($(wc -l < /tmp/fg_${LABEL}_${nm}.dmesg 2>/dev/null) lines)"
done
exit 2
