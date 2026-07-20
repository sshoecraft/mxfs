#!/bin/bash
# reliability_loop.sh — run the FULL 2-node tcp suite N times, clean reboot
# between each, recording 17/17 vs partial.  The tcp_dlm_scaling/dlm_fairness
# residual is intermittent (~per-run), so a single 17/17 is not proof; the
# criterion is RELIABLE 100%.  Reboot+reset between runs avoids cross-run
# contamination (a TaskStop'd or wedged prior run poisons the next).
#
# Run ON clyde:  bash tests/tcp/reliability_loop.sh [runs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
RUNS="${1:-3}"
N1=test1; N2=test2

boot_wait() {
    for n in "$N1" "$N2"; do virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    sleep 3
    for n in "$N1" "$N2"; do virsh -c qemu:///system start "$n" >/dev/null 2>&1; done
    for i in $(seq 1 40); do
        ok=0
        for h in 192.168.120.186 192.168.120.182; do
            timeout 5 sshpass -f "$P" ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 root@"$h" true 2>/dev/null && ok=$((ok+1))
        done
        [ "$ok" -eq 2 ] && return 0
        sleep 5
    done
    echo "boot_wait FAILED"; return 1
}

pass=0; total=0
for r in $(seq 1 "$RUNS"); do
    echo "===== RELIABILITY RUN $r/$RUNS ($(date -u +%H:%M:%S)Z) ====="
    boot_wait || { echo "RUN $r: boot failed"; continue; }
    LOG="/tmp/relrun_${r}.log"
    timeout 900 ./run.sh 2 tcp > "$LOG" 2>&1
    np=$(grep -c 'PASS ' "$LOG"); nf=$(grep -c 'FAIL ' "$LOG")
    total=$((total+1))
    if grep -q '=== done: ran=17' "$LOG" && [ "$nf" -eq 0 ] && [ "$np" -eq 17 ]; then
        pass=$((pass+1)); echo "RUN $r: PASS 17/17"
    else
        echo "RUN $r: PARTIAL pass=$np fail=$nf — FAILS:"; grep 'FAIL ' "$LOG" | sed 's/^/    /'
        # Capture both nodes' dmesg BEFORE the next reboot wipes it.
        for h in 192.168.120.186 192.168.120.182; do
            nm=$([ "$h" = 192.168.120.186 ] && echo node1 || echo node2)
            timeout 25 sshpass -f "$P" ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 root@"$h" \
                "dmesg" > "/tmp/relrun_${r}_${nm}.dmesg" 2>/dev/null
        done
        echo "    dmesg saved: /tmp/relrun_${r}_node{1,2}.dmesg"
    fi
done
echo "===== RELIABILITY: $pass/$total full runs were 17/17 ====="
