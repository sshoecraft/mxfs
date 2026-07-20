#!/bin/bash
# diag_cpu_pin_capture.sh — run dir_reuse_coherency+fence_during_write@N/caw
# in the background while polling every node's SSH liveness on a tight
# cadence.  The instant a node misses two consecutive polls (~unresponsive
# for ~2x POLL_INT), immediately pull live per-vCPU register state via
# `virsh qemu-monitor-command --hmp "info registers -a"` — this reads
# straight from QEMU on the HOST side and does NOT require the guest
# scheduler to cooperate, so it works even when the guest is fully
# CPU-pinned/softlocked and unreachable over SSH.  Keeps re-sampling that
# node's registers for a while (to distinguish a static RIP — genuine
# spin/deadlock — from a moving one — just slow) before giving up on it.
#
# Sess: diagnosing the fence_during_write@8/caw CPU-pin regression seen
# with caw_fair_handoff=1 (ccloop cc87fed3 sess2).  Serial console evidence
# (test4-serial.log) showed two CONSECUTIVE boots both hitting
# "watchdog: BUG: soft lockup" with bash+kworker/uNN pinned in pairs of 2
# CPUs and NO call trace printed — this script exists to catch it live and
# get a real RIP instead of guessing from source.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
cd "$REPO"

N="${1:-8}"
OUT="${2:?usage: diag_cpu_pin_capture.sh <N> <outdir> [extra_modargs]}"
EXTRA_MODARGS="${3:-caw_fair_handoff=1}"
mkdir -p "$OUT"

POLL_INT=5
FAIL_THRESH=2		# consecutive missed polls before we call it "stuck"
			# (capture then re-fires every POLL_INT while still down,
			# so a stuck node gets a fresh register sample ~5s apart)

for n in $(seq 1 "$N"); do
    ( timeout 15 "$SSH" "test$n" "$PASS" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

DRC_TT=$(( 140 * N + 300 ))
OUTER=$(( DRC_TT + 300 ))

echo "$(date -u +%H:%M:%S) launching run.sh N=$N modargs='$EXTRA_MODARGS' DRC_TT=$DRC_TT OUTER=$OUTER" | tee "$OUT/monitor.log"

( MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="$EXTRA_MODARGS" TEST_TIMEOUT="$DRC_TT" timeout "$OUTER" \
    ./run.sh "$N" caw dir_reuse_coherency fence_during_write \
    > "$OUT/run.log" 2>&1
  echo "RUN_EXIT=$?" >> "$OUT/run.log" ) &
RUNPID=$!

declare -A failcount
for n in $(seq 1 "$N"); do failcount[$n]=0; done

capture_node() {
    local n="$1" ts
    ts=$(date -u +%H%M%S)
    {
        echo "=== capture test$n @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
        echo "--- virsh domstate ---"
        virsh -c qemu:///system domstate "test$n" 2>&1
        echo "--- virsh vcpuinfo ---"
        virsh -c qemu:///system vcpuinfo "test$n" 2>&1
        echo "--- info registers -a ---"
        virsh -c qemu:///system qemu-monitor-command "test$n" --hmp "info registers -a" 2>&1
    } >> "$OUT/test${n}_regs.log"
    echo "$(date -u +%H:%M:%S) captured test$n regs -> $OUT/test${n}_regs.log" >> "$OUT/monitor.log"
}

sample_end=$(( $(date +%s) + OUTER + 60 ))
while kill -0 "$RUNPID" 2>/dev/null && [ "$(date +%s)" -lt "$sample_end" ]; do
    pollpids=()
    for n in $(seq 1 "$N"); do
        (
            if timeout 3 "$SSH" "test$n" "$PASS" "echo ALIVE" 2>/dev/null | grep -q ALIVE; then
                echo "OK" > "$OUT/.st_$n"
            else
                echo "FAIL" > "$OUT/.st_$n"
            fi
        ) &
        pollpids+=("$!")
    done
    # bash bug class (see ccmemory infra-timeout-orphans / repro_fdw_instrumented.sh
    # sess1 note): a BARE `wait` here would wait on every background job of this
    # shell, including $RUNPID (the ~29min run.sh) — not just this round's 8 poll
    # subshells.  Wait ONLY on the poll PIDs so each round stays ~3s.
    wait "${pollpids[@]}" 2>/dev/null

    for n in $(seq 1 "$N"); do
        st=$(cat "$OUT/.st_$n" 2>/dev/null)
        if [ "$st" = "OK" ]; then
            if [ "${failcount[$n]}" -ge "$FAIL_THRESH" ]; then
                echo "$(date -u +%H:%M:%S) test$n RECOVERED after ${failcount[$n]} misses" >> "$OUT/monitor.log"
            fi
            failcount[$n]=0
        else
            failcount[$n]=$(( failcount[$n] + 1 ))
            echo "$(date -u +%H:%M:%S) test$n miss #${failcount[$n]}" >> "$OUT/monitor.log"
            if [ "${failcount[$n]}" -ge "$FAIL_THRESH" ]; then
                capture_node "$n"
            fi
        fi
    done
    sleep "$POLL_INT"
done
wait "$RUNPID" 2>/dev/null

echo "=== monitor done, run.log tail: ===" | tee -a "$OUT/monitor.log"
tail -30 "$OUT/run.log" | tee -a "$OUT/monitor.log"
echo DONE > "$OUT/.done"
