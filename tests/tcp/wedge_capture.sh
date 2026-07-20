#!/bin/bash
# wedge_capture.sh — capture the hard-hang ("wedge") stack that every coherent
# dir-block re-read variant triggers under 8-node dir_reuse churn (sess24 handoff:
# the wedge stack was NEVER captured; nmi_watchdog was OFF so no NMI stack printed).
#
# Strategy: nmi_watchdog is a HARD-hang detector (fires from NMI even with IRQs
# off).  Enable it + hardlockup_panic so a wedged node panics with a stack to the
# kernel ring.  Independently, poll every node for ssh-reachability; when a node
# goes dark, dump its vCPU registers host-side via the qemu monitor (works even
# when the guest CPU is in an IRQs-off spin) so we can map RIP -> symbol.
#
# Usage: tests/tcp/wedge_capture.sh   (run from /src/mxfs)
set -u
PASS=/tmp/.mxfs_pass
SSH="tools/mxfs_sshpass.sh"
CAP=/src/mxfs/tests/tcp/wedge_cap
NODES="1 2 3 4 5 6 7 8"
mkdir -p "$CAP"; rm -f "$CAP"/*.txt "$CAP"/*.log 2>/dev/null

modargs="dir_postread_reread=1 dir_postread_leaf_only=0"
echo "=== wedge_capture: modargs=[$modargs] ===" | tee "$CAP/run.log"

# Launch the dir_reuse run in the background (it does prep+mount itself).
( MXFS_EXTRA_MODARGS="$modargs" timeout 590 ./run.sh 8 tcp dir_reuse_coherency \
    > "$CAP/drc_run.log" 2>&1 ) &
RUNPID=$!
echo "run pid=$RUNPID" | tee -a "$CAP/run.log"

# Wait for all nodes mounted (prep done), then arm watchdog + snapshot module base.
armed=0
for i in $(seq 1 60); do
    grep -q "prep OK" "$CAP/drc_run.log" 2>/dev/null && { armed=1; break; }
    kill -0 $RUNPID 2>/dev/null || break
    sleep 3
done
echo "armed=$armed after prep wait" | tee -a "$CAP/run.log"
for n in $NODES; do
    timeout 10 $SSH test$n $PASS "
        echo 1 > /proc/sys/kernel/nmi_watchdog 2>/dev/null
        echo 1 > /proc/sys/kernel/hardlockup_panic 2>/dev/null
        echo 1 > /proc/sys/kernel/softlockup_panic 2>/dev/null
        echo 8 > /proc/sys/kernel/printk
        grep -E ' mxfs\$' /proc/modules" > "$CAP/modbase_test$n.txt" 2>&1 &
done
wait
echo "watchdog armed + module base snapshotted" | tee -a "$CAP/run.log"

# Poll for a dark node; on first dark node, dump registers from the qemu monitor.
captured=0
while kill -0 $RUNPID 2>/dev/null; do
    for n in $NODES; do
        if ! timeout 6 $SSH test$n $PASS "true" >/dev/null 2>&1; then
            # double-check it is really dark (one retry)
            timeout 6 $SSH test$n $PASS "true" >/dev/null 2>&1 && continue
            ts=$(date -u +%H%M%S)
            echo "=== test$n DARK at $ts — dumping vCPU regs ===" | tee -a "$CAP/run.log"
            for rep in 1 2 3 4 5; do
                {
                  echo "--- rep $rep $(date -u +%H:%M:%S) ---"
                  virsh -c qemu:///system qemu-monitor-command test$n --hmp 'info registers -a' 2>&1
                  echo "--- cpu state ---"
                  virsh -c qemu:///system qemu-monitor-command test$n --hmp 'info cpus' 2>&1
                } >> "$CAP/regs_test$n.log"
                sleep 2
            done
            # also try to NMI it into a panic stack via the monitor
            virsh -c qemu:///system inject-nmi test$n 2>&1 | tee -a "$CAP/run.log"
            sleep 4
            virsh -c qemu:///system qemu-monitor-command test$n --hmp 'info registers -a' \
                >> "$CAP/regs_test$n.log" 2>&1
            captured=1
            break
        fi
    done
    [ "$captured" = 1 ] && break
    sleep 5
done

echo "=== capture done captured=$captured ===" | tee -a "$CAP/run.log"
ls -la "$CAP"
