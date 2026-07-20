#!/bin/bash
# run_criteria_tcp.sh — run the ship criteria `./run.sh {1,2,4,8} tcp` full
# suites, each preceded by a CLEAN reboot of the participating nodes (sess45
# lesson: a wedged/orphaned leftover from a prior run cascades the next full
# run to a false 0/N).  Records per-condition PASS/FAIL tallies.
# Usage: run_criteria_tcp.sh ["1 2 4 8"]   (default all four)
set -u
CONDS="${1:-1 2 4 8}"
cd /src/mxfs
SSH=/src/mxfs/tools/mxfs_sshpass.sh
flt() { grep -vE '^Warning:|^Unauthorized|^If you'; }

for N in $CONDS; do
    echo "############## CONDITION ${N}/tcp  $(date -u +%H:%M:%S) ##############"
    # clean reboot of test1..testN
    for n in $(seq 1 "$N"); do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 7
    for n in $(seq 1 "$N"); do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 40); do
        up=0
        for n in $(seq 1 "$N"); do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done
        [ "$up" = "$N" ] && break
        sleep 3
    done
    echo "nodes_up=$up/$N after reboot $(date -u +%H:%M:%S)"
    [ "$up" = "$N" ] || { echo ">>> CONDITION ${N}/tcp ABORT: only $up/$N nodes up"; continue; }
    # full suite
    ./run.sh "$N" tcp 2>&1 | flt | grep -E "  (PASS|FAIL|PEND)  |prep OK|ABORT|=== done"
    echo "---- ${N}/tcp showstat ----"
    ./showstat.sh "$N" tcp 2>/dev/null | tail -40
    echo "############## END ${N}/tcp  $(date -u +%H:%M:%S) ##############"
done
echo "=== all criteria conditions done $(date -u +%H:%M:%S) ==="
