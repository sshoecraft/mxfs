#!/bin/bash
# standalone_retest.sh — run each named 2/tcp test in TRUE ISOLATION to split
# REAL-bug failures from suite CONTAMINATION (sess44, ccloop 8ddb16a2).
#
# The criterion is the full `./run.sh 2 tcp` suite (ONE prep, all tests back to
# back).  A test that fails in-suite may be a real bug OR contamination from a
# prior test that degraded the cluster (esp. coord=fault tests that kill nodes).
# To tell them apart, this harness — for EACH named test — does a full virsh
# destroy/start of both nodes (pristine), clears dmesg, then runs exactly that
# one test via `./run.sh 2 tcp <test>` (which does its own fresh mkfs+mount).
# A test that PASSES here but FAILED in-suite => contamination.  A test that
# FAILS here too => real bug.  Per-run it also reports any FS shutdown /
# corruption / self-fence seen in either node's (now-fresh) dmesg.
#
# Usage:  tests/standalone_retest.sh [test ...]
#   default test list = the sess44 in-suite failures.
# Env:    MXFS_EXTRA_MODARGS passed through to run.sh (e.g. dir_force_block=0).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
SSH="$REPO/tools/mxfs_sshpass.sh"
TESTS=("$@")
[ "${#TESTS[@]}" -gt 0 ] || TESTS=(posix_multi dlm_membership rsync_paired \
    crash_consistency fence_during_write fault_netpartition soak tcp_dlm_scaling)

reboot_clean() {   # destroy+start both nodes, wait ssh, clear dmesg
    local vm n i
    for vm in test1 test2; do timeout 25 virsh -c qemu:///system destroy "$vm" >/dev/null 2>&1; done
    sleep 3
    for vm in test1 test2; do timeout 25 virsh -c qemu:///system start "$vm" >/dev/null 2>&1; done
    for n in test1 test2; do
        for i in $(seq 1 60); do
            timeout 5 "$SSH" "$n" "$PASS" 'true' >/dev/null 2>&1 && break
            sleep 5
        done
    done
    for n in test1 test2; do timeout 10 "$SSH" "$n" "$PASS" 'dmesg -C' >/dev/null 2>&1; done
}

post_dmesg() {     # report shutdown/corruption/self-fence per node
    local n hit
    for n in test1 test2; do
        hit=$(timeout 12 "$SSH" "$n" "$PASS" \
          "dmesg | grep -iE 'Shutting down filesystem|Corruption|ltbno|P131-SELF-FENCE|double-free|imap_to_bp.*-5' | tail -3" \
          2>&1 | grep -vE '^Warning:|^Unauthorized|^If you')
        [ -n "$hit" ] && { echo "    [$n KERNEL]:"; echo "$hit" | sed 's/^/      /'; }
    done
}

echo "=== standalone_retest: ${TESTS[*]} (modargs='${MXFS_EXTRA_MODARGS:-}') ==="
declare -A RESULT
for t in "${TESTS[@]}"; do
    echo "--- [$t] reboot to pristine, then run isolated ---"
    reboot_clean
    out=$(timeout 600 ./run.sh 2 tcp "$t" 2>&1)
    line=$(echo "$out" | grep -E "^  (PASS|FAIL|PEND) " | tail -1)
    verdict=$(echo "$line" | awk '{print $1}')
    RESULT[$t]="${verdict:-NORESULT}"
    echo "  $t => ${verdict:-NORESULT}  ${line#*"$verdict"}"
    [ "$verdict" = PASS ] || { echo "$out" | grep -E 'PREP FAIL|ABORT|reason=' | tail -3 | sed 's/^/    /'; post_dmesg; }
done

echo "=== SUMMARY (isolated, pristine-per-test) ==="
for t in "${TESTS[@]}"; do printf "  %-22s %s\n" "$t" "${RESULT[$t]}"; done
