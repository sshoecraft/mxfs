#!/bin/bash
# suite_loop.sh — run the FULL `./run.sh <N> <dlm>` suite K times and aggregate
# per-test PASS/FAIL across runs, to confirm REPRODUCIBLE 100% success (esp. the
# historically-flaky dir_reuse_coherency).  Production config: pass NO
# MXFS_EXTRA_MODARGS (module defaults) unless the caller exports it.
# run.sh prep asserts the build srcversion on every node, so all runs use the
# local .ko.  RULE 0: a full 2/tcp suite is ~15-25 min (17 tests; dir_reuse
# alone ~284s) => K runs ~ K*20min.
#
# Usage: tests/suite_loop.sh <N> <dlm> <iters>
set -u
cd /src/mxfs
N="${1:?usage: suite_loop.sh <N> <dlm> <iters>}"
DLM="${2:?}"; K="${3:?}"
CAPDIR=/src/mxfs/tests/_cap
SUM="$CAPDIR/suite_loop_summary.txt"
mkdir -p "$CAPDIR"
: > "$SUM"
build=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
echo "=== suite_loop ${N}/${DLM} x${K} build=$build @ $(date -u +%T) ===" | tee -a "$SUM"
allpass=0
for i in $(seq 1 "$K"); do
    echo "--- run $i/$K @ $(date -u +%T) ---" | tee -a "$SUM"
    log="$CAPDIR/suite_run_${i}.log"
    ./run.sh "$N" "$DLM" > "$log" 2>&1
    # run.sh prints "  PASS  name" / "  FAIL  name" per test and a done summary.
    npass=$(grep -cE '^  PASS ' "$log")
    nfail=$(grep -cE '^  FAIL ' "$log")
    npend=$(grep -cE '^  PEND ' "$log")
    echo "  run $i: PASS=$npass FAIL=$nfail PEND=$npend" | tee -a "$SUM"
    if [ "$nfail" -gt 0 ]; then
        grep -E '^  FAIL ' "$log" | sed 's/^/    /' | tee -a "$SUM"
    fi
    if grep -q 'ABORT: cluster prep failed' "$log"; then
        echo "    (PREP ABORTED — see $log)" | tee -a "$SUM"
    fi
    [ "$nfail" -eq 0 ] && [ "$npass" -gt 0 ] && allpass=$((allpass+1))
done
echo "=== DONE: clean-suite runs = $allpass/$K @ $(date -u +%T) ===" | tee -a "$SUM"
