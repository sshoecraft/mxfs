#!/bin/bash
# sess51_drc_repro.sh — reproduce dir_reuse_coherency's intermittent failure and
# capture the FAILURE MODE (readdir count-loss = conversion-divergence/data-block
# loss, vs leaf-hash lookup_fail) + the relevant dmesg from BOTH nodes BEFORE the
# next reboot wipes it.  Runs the full suite (dir_reuse fails in-suite, not
# standalone) N times with a clean reboot between, capturing per-run dmesg.
#
# Run ON clyde:  bash tests/tcp/sess51_drc_repro.sh [runs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
P="${MXFS_PASS:-/tmp/.mxfs_pass}"
RUNS="${1:-5}"
N1=192.168.120.186; N2=192.168.120.182
SSH="timeout 15 sshpass -f $P ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4"

boot_wait() {
    for n in test1 test2; do virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    sleep 3
    for n in test1 test2; do virsh -c qemu:///system start "$n" >/dev/null 2>&1; done
    for i in $(seq 1 40); do
        ok=0
        for h in $N1 $N2; do
            $SSH root@"$h" true 2>/dev/null && ok=$((ok+1))
        done
        [ "$ok" -eq 2 ] && return 0
        sleep 5
    done
    echo "boot_wait FAILED"; return 1
}

capture() {  # $1 = run number
    local r="$1"
    for h in $N1 $N2; do
        local f="/tmp/sess51_drc_run${r}_${h}.dmesg"
        $SSH root@"$h" 'dmesg | grep -E "mxfs-drc-FAIL|mxfs-drc-RDMISS|mxfs-DRCph|P43|P34D|P133-DINO|FMTREVERT|sf_to_block|SPLIT|block0|shutting down|Corruption|double-free|BNOBT|P62-RELOAD"' > "$f" 2>/dev/null
        echo "  captured $f ($(wc -l < "$f" 2>/dev/null) lines)"
    done
}

pass=0; total=0; drc_fail=0
for r in $(seq 1 "$RUNS"); do
    echo "===== DRC-REPRO RUN $r/$RUNS ($(date -u +%H:%M:%S)Z) ====="
    boot_wait || { echo "RUN $r: boot failed"; continue; }
    LOG="/tmp/sess51_drc_run${r}.log"
    timeout 900 ./run.sh 2 tcp > "$LOG" 2>&1
    total=$((total+1))
    np=$(grep -c 'PASS ' "$LOG"); nf=$(grep -c 'FAIL ' "$LOG")
    if grep -q '=== done: ran=17' "$LOG" && [ "$nf" -eq 0 ] && [ "$np" -eq 17 ]; then
        pass=$((pass+1)); echo "RUN $r: PASS 17/17"
    else
        echo "RUN $r: PARTIAL pass=$np fail=$nf — FAILS:"; grep 'FAIL ' "$LOG" | sed 's/^/    /'
        if grep -q 'FAIL  dir_reuse_coherency' "$LOG"; then
            drc_fail=$((drc_fail+1))
            echo "  >>> dir_reuse FAILED — capturing dmesg before next reboot"
            capture "$r"
        fi
    fi
done
echo "===== DRC-REPRO: $pass/$total full 17/17; dir_reuse failed $drc_fail/$total ====="
