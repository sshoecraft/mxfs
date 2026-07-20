#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Gate 5 — NET2 membership plane / MEPOCH (DLM_IMPL_PLAN.md §11 step 5).
#
# The §7.C single-decree epoch authority over a file-backed disklock
# image in the user harness — the seven success-criteria checks:
# bootstrap epoch-1 self-quorum (mep_bootstrap), join/leave increments
# with the clean-leave-vs-fence distinction (mep_join_leave), proposer
# crash mid-round → PREPARED adoption completing the SAME decree
# (mep_prepared_adoption), voter-minority stall = open round + zero
# commit + VISIBLE lease freeze (mep_stall), whole-cluster restart
# adopting the max valid committed record (mep_restart_all), excluded
# node with zero network self-fencing off the LUN alone
# (mep_disk_self_fence, delivery-counter-proven), exclusion without
# fence proof NACKed dead (mep_no_fence_proof), plus the observer/
# SUSPECT machine + persisted-incarnation bump (mep_membership).
# Group × 4 seeds, a N2_DEBUG pass (instrumentation can MASK timing
# bugs — sess3 lesson), and an ASan sweep of the whole suite (mepoch
# rides midcomms; a group-only sweep would miss cross-layer frees).
#
# ── RULE-0 budget (written BEFORE first run; tighten after healthy PASS) ──
#   infra    = harness clean build ×2 (normal + ASan): measured ~10 s
#   workload = mepoch group ≈ 4 s/run × 5 runs (4 seeds + debug pass)
#              + ASan build + ASan full-suite run (38 scenarios, the
#              dominant term) — native == the harness itself
#   SCEN_BUDGET_S (everything after first build) = 120
#   (calibrated 2026-07-18: actual 108 s on clyde; the success.md
#   provisional 120 pins with ~11% headroom.  RULE0_CALIBRATE=1 =>
#   measure + report without enforcing.)
#   A timeout or overrun is a FAIL (RULE 0.3), never a retry with a
#   bigger budget.
#
# Usage: gate5_mepoch.sh

set -u
cd "$(dirname "$0")"
SCEN_BUDGET_S="${SCEN_BUDGET_S:-120}"
CAL="${RULE0_CALIBRATE:-0}"
SEEDS="0xF422 0xBEEF 0x1234"

fail=0

t0=$(date +%s)
echo "== gate5: harness clean build =="
make clean >/dev/null 2>&1
if ! make 2>&1 | tail -5; then
    echo "RESULT: FAIL | test=net2_gate5 | nodes=1 | measured=- | reason=harness-build-failed"
    exit 1
fi
t_build=$(( $(date +%s) - t0 ))
echo "build_wall_s=$t_build"

run_matrix() {
    local label="$1"; shift
    local out errlog
    errlog=$(mktemp)
    out="$("$@" 2>"$errlog" | grep '^RESULT:')"
    echo "$out"
    local pass ntot
    pass=$(echo "$out" | grep -c 'RESULT: PASS')
    ntot=$(echo "$out" | grep -c 'RESULT:')
    if [ "$ntot" -eq 0 ] || [ "$pass" -ne "$ntot" ]; then
        echo "gate5: $label: $pass/$ntot passed — FAIL"
        # surface the harness diagnostics (CHECK-FAIL/ENV-FAIL go to
        # stderr) — a failure without its evidence is undebuggable
        grep -E 'CHECK-FAIL|ENV-FAIL' "$errlog" | head -20
        fail=1
    else
        echo "gate5: $label: $pass/$ntot passed"
    fi
    rm -f "$errlog"
}

t1=$(date +%s)
echo "== gate5: mepoch group, default seed =="
run_matrix "mepoch default" ./net2_harness run mepoch
for seed in $SEEDS; do
    echo "== gate5: mepoch group, seed $seed =="
    run_matrix "mepoch seed=$seed" ./net2_harness run mepoch --seed "$seed"
done
echo "== gate5: mepoch group, default seed, N2_DEBUG=1 =="
run_matrix "mepoch debug" env N2_DEBUG=1 ./net2_harness run mepoch

echo "== gate5: AddressSanitizer sweep (full suite) =="
make clean >/dev/null 2>&1
if ! make CFLAGS="-O1 -g -std=gnu11 -Wall -Wextra -Werror -fsanitize=address" >/dev/null 2>&1; then
    echo "RESULT: FAIL | test=net2_gate5 | nodes=1 | measured=- | reason=asan-build-failed"
    exit 1
fi
asan_log=$(mktemp)
run_matrix "asan full suite" ./net2_harness run all
./net2_harness run all >/dev/null 2>"$asan_log" || true
if grep -qE 'ERROR: (Address|Leak)Sanitizer' "$asan_log"; then
    echo "gate5: sanitizer errors:"
    grep -E 'ERROR: (Address|Leak)Sanitizer' "$asan_log" | head -5
    fail=1
fi
rm -f "$asan_log"

# leave a normal (non-sanitizer) binary behind
make clean >/dev/null 2>&1
make >/dev/null 2>&1

t_scen=$(( $(date +%s) - t1 ))
echo "scenario_wall_s=$t_scen budget_s=$SCEN_BUDGET_S"
if [ "$CAL" = "1" ]; then
    echo "gate5: CALIBRATION run — wall $t_scen s (pin the budget near this)"
elif [ "$t_scen" -gt "$SCEN_BUDGET_S" ]; then
    echo "gate5: RULE-0 overrun: $t_scen s > $SCEN_BUDGET_S s — FAIL"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL | test=net2_gate5 | nodes=1 | measured=wall=${t_scen}s | reason=see-above"
    exit 1
fi
echo "RESULT: PASS | test=net2_gate5 | nodes=1 | measured=wall=${t_scen}s,budget=${SCEN_BUDGET_S}s | reason=-"
